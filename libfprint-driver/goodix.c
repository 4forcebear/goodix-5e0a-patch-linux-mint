// Goodix Tls driver for libfprint

// Copyright (C) 2021 Alexander Meiler <alex.meiler@protonmail.com>
// Copyright (C) 2021 Matthieu CHARETTE <matthieu.charette@gmail.com>
// Copyright (C) 2021 Natasha England-Elbro <natasha@natashaee.me>

// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.

// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include "fpi-log.h"
#include "fpi-ssm.h"
#include "fpi-usb-transfer.h"
#define FP_COMPONENT "goodixtls"

#include <gio/gio.h>
#include <glib.h>
#include <gusb.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "drivers_api.h"
#include "goodix.h"
#include "goodix_proto.h"
#include "goodixtls.h"

typedef struct
{
  GoodixTlsServer    *tls_hop;

  GSource            *timeout;

  guint8              cmd;

  gboolean            ack;
  gboolean            reply;

  GoodixCmdCallback   callback;
  gpointer            user_data;

  guint8             *data;
  guint32             length;

  GoodixCallbackInfo *tls_ready_callback;

  /* Ticket 34 stale-activation guard: bumped on every (re)activation start
   * and every deactivate/teardown entry; TLS completion callbacks capture
   * it at TLS-init time and drop on mismatch. Zero-initialized. */
  guint         activation_gen;

  /* Ticket 40 warm-activation key: bumped in goodix_dev_init (once per
   * device open, not per claim). Zero-initialized; first open reads 1.
   * Ticket 42 couples it to the USB reset actually taken (not the open):
   * a clean reopen is the same device boot, a real reset is a new boot. */
  guint         boot_seq;

  /* Ticket 42 conditional USB reset: TRUE only when the previous session
   * on this USB device closed cleanly (set ONLY in the
   * goodix5e0a_deactivate park branch — the single point a session proves
   * clean with a live TLS context + completed deactivate). FALSE is the
   * safe direction (reset taken). Zero-initialized, so the first open
   * after a daemon restart always resets. Cleared on every failure funnel
   * (activate/TLS/chip/scan errors), on suspend entry, and on USB
   * re-enumeration; destroy-path deactivate also clears (no live context
   * to prove device health — when in doubt, reset). */
  gboolean      clean_close;

  /* Ticket 42 re-enumeration key: bus+address+port+vid+pid snapshot from
   * the last open, via fpi_device_get_usb_device. A mismatch means the
   * kernel re-enumerated the device (replug / vanish+reappear) so the
   * flag is forced dirty regardless of clean_close. Choice: bus+address
   * detects a new kernel address on the same port; port+vid+pid disam-
   * biguates port moves and foreign devices. If no USB identity can be
   * read (NULL device — never expected for our USB type), the open is
   * treated as dirty. usb_identity_valid is FALSE until the first open
   * snapshots, so daemon restarts stay dirty by construction. */
  guint8        last_usb_bus;
  guint8        last_usb_addr;
  guint8        last_usb_port;
  guint16       last_usb_vid;
  guint16       last_usb_pid;
  gboolean      usb_identity_valid;
  gint64        last_close_boot;
  gint64        last_close_mono;

  GCancellable *transfer_cancel_tkn;
  gboolean      inited;
} FpiDeviceGoodixTlsPrivate;

G_DEFINE_ABSTRACT_TYPE_WITH_PRIVATE (FpiDeviceGoodixTls, fpi_device_goodixtls,
                                     FP_TYPE_DEVICE);

gchar *
data_to_str (guint8 *data, guint32 length)
{
  if (!data || length > (G_MAXUINT32 - 1) / 2)
    return NULL;

  gchar *string = g_malloc ((length * 2) + 1);

  for (guint32 i = 0; i < length; i++)
    sprintf (string + i * 2, "%02x", data[i]);

  return string;
}

// ---- GOODIX RECEIVE SECTION START ----

static void goodix_receive_done (FpDevice *dev, guint8 *data, guint16 length, GError *error);
static void goodix_receive_success (FpDevice *dev, guint8 *data, guint16 length, gpointer user_data, GError *error);
static void goodix_receive_reset (FpDevice *dev, guint8 *data, guint16 length, gpointer user_data, GError *error);
static void goodix_receive_none_tolerant (FpDevice *dev, guint8 *data, guint16 length, gpointer user_data, GError *error);
static void goodix_receive_preset_psk_read (FpDevice *dev, guint8 *data, guint16 length, gpointer user_data, GError *error);
static void goodix_receive_ack (FpDevice *dev, guint8 *data, guint16 length, gpointer user_data, GError *error);
static void goodix_receive_firmware_version (FpDevice *dev, guint8 *data, guint16 length, gpointer user_data, GError *error);
static void goodix_receive_protocol (FpDevice *dev, guint8 *data, guint32 length);
static void goodix_receive_pack (FpDevice *dev, guint8 *data, guint32 length);
static void goodix_receive_timeout_cb (FpDevice *dev, gpointer user_data);
static void goodix_receive_data (FpDevice *dev);

static void
goodix_receive_done (FpDevice *dev, guint8 *data, guint16 length,
                     GError *error)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);
  GoodixCmdCallback callback = priv->callback;
  gpointer user_data = priv->user_data;

  if (!(priv->ack || priv->reply))
    {
      if (error)
        g_error_free (error);
      return;
    }

  priv->callback = NULL;
  priv->user_data = NULL;
  goodix_reset_state (dev);
  if (!error)
    fp_dbg ("Completed command: 0x%02x", priv->cmd);

  if (callback)
    callback (dev, data, length, user_data, error);
  else if (error)
    g_error_free (error);
}

void
goodix_receive_none (FpDevice *dev, guint8 *data, guint16 length,
                     gpointer user_data, GError *error)
{
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixNoneCallback callback = (GoodixNoneCallback) cb_info->callback;

  callback (dev, cb_info->user_data, error);
}

static void
goodix_receive_none_tolerant (FpDevice *dev, guint8 *data, guint16 length,
                              gpointer user_data, GError *error)
{
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixNoneCallback callback = (GoodixNoneCallback) cb_info->callback;

  if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
    g_clear_error (&error); /* ponytail: NOP silence = buffer already empty */

  callback (dev, cb_info->user_data, error);
}

void
goodix_receive_default (FpDevice *dev, guint8 *data, guint16 length,
                        gpointer user_data, GError *error)
{
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixDefaultCallback callback = (GoodixDefaultCallback) cb_info->callback;

  callback (dev, data, length, cb_info->user_data, error);
}

static void
goodix_receive_success (FpDevice *dev, guint8 *data, guint16 length,
                        gpointer user_data, GError *error)
{
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixSuccessCallback callback = (GoodixSuccessCallback) cb_info->callback;

  if (error)
    {
      callback (dev, FALSE, cb_info->user_data, error);
      return;
    }

  if (!data || length != sizeof (guint8) * 2)
    {
      g_set_error (&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Invalid success reply length: %d", length);
      callback (dev, FALSE, cb_info->user_data, error);
      return;
    }

  callback (dev, data[0] == 0x00 ? FALSE : TRUE, cb_info->user_data, NULL);
}

static void
goodix_receive_reset (FpDevice *dev, guint8 *data, guint16 length,
                      gpointer user_data, GError *error)
{
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixResetCallback callback = (GoodixResetCallback) cb_info->callback;

  if (error)
    {
      callback (dev, FALSE, 0, cb_info->user_data, error);
      return;
    }

  if (!data || length != sizeof (guint8) + sizeof (guint16))
    {
      g_set_error (&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Invalid reset reply length: %d", length);
      callback (dev, FALSE, 0, cb_info->user_data, error);
      return;
    }

  guint16 reset_val;
  memcpy (&reset_val, data + sizeof (guint8), sizeof (guint16));
  callback (dev, data[0] == 0x00 ? FALSE : TRUE,
            GUINT16_FROM_LE (reset_val),
            cb_info->user_data, NULL);
}

static void
goodix_receive_preset_psk_read (FpDevice *dev, guint8 *data, guint16 length,
                                gpointer user_data, GError *error)
{
  guint32 psk_len;
  GoodixPresetPsk psk_hdr;
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixPresetPskReadCallback callback =
    (GoodixPresetPskReadCallback) cb_info->callback;

  if (error)
    {
      callback (dev, FALSE, 0x00000000, NULL, 0, cb_info->user_data, error);
      return;
    }

  /* Zero-length decodes deliver NULL (see goodix_proto.h contract). */
  if (!data || length < sizeof (guint8))
    {
      g_set_error (&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Invalid preset PSK read reply length: %d", length);
      callback (dev, FALSE, 0x00000000, NULL, 0, cb_info->user_data, error);
      return;
    }

  if (data[0] != 0x00)
    {
      callback (dev, FALSE, 0x00000000, NULL, 0, cb_info->user_data, NULL);
      return;
    }

  if (length < sizeof (guint8) + sizeof (GoodixPresetPsk))
    {
      g_set_error (&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Invalid preset PSK read reply length: %d", length);
      callback (dev, FALSE, 0x00000000, NULL, 0, cb_info->user_data, error);
      return;
    }

  memcpy (&psk_hdr, data + sizeof (guint8), sizeof (GoodixPresetPsk));
  psk_len = GUINT32_FROM_LE (psk_hdr.length);

  if (length < psk_len + sizeof (guint8) + sizeof (GoodixPresetPsk))
    {
      g_set_error (&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Invalid preset PSK read reply length: %d", length);
      callback (dev, FALSE, 0x00000000, NULL, 0, cb_info->user_data, error);
      return;
    }

  callback (dev, TRUE,
            GUINT32_FROM_LE (psk_hdr.flags),
            data + sizeof (guint8) + sizeof (GoodixPresetPsk), psk_len,
            cb_info->user_data, NULL);
}

static void
goodix_receive_firmware_version (FpDevice *dev, guint8 *data,
                                 guint16 length, gpointer user_data,
                                 GError *error)
{
  g_autofree gchar *payload = g_malloc (length + sizeof (gchar));
  g_autofree GoodixCallbackInfo *cb_info = user_data;
  GoodixFirmwareVersionCallback callback =
    (GoodixFirmwareVersionCallback) cb_info->callback;

  if (error)
    {
      callback (dev, NULL, cb_info->user_data, error);
      return;
    }

  /* Zero-length decodes deliver NULL; a NULL payload with nonzero length
   * is a broken reply, while NULL/0 is an empty (unterminated) version. */
  if (!data && length > 0)
    {
      callback (dev, NULL, cb_info->user_data,
                g_error_new (G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                             "Invalid firmware version reply length: %d", length));
      return;
    }
  if (length > 0)
    memcpy (payload, data, length);

  // Some device send the firmware without the null terminator
  payload[length] = 0x00;

  callback (dev, payload, cb_info->user_data, NULL);
}

/* ponytail: safety-critical cmds must never act on a bad-checksum frame;
 * image/stream traffic keeps ticket-52 log-only tolerance. */
static gboolean
goodix_cmd_is_safety_critical (guint8 cmd)
{
  switch (cmd)
    {
    case GOODIX_CMD_UPLOAD_CONFIG_MCU:
    case GOODIX_CMD_ENABLE_CHIP:
    case GOODIX_CMD_RESET:
    case GOODIX_CMD_REQUEST_TLS_CONNECTION:
    case GOODIX_CMD_PRESET_PSK_WRITE:
    case GOODIX_CMD_PRESET_PSK_READ:
      return TRUE;
    default:
      return FALSE;
    }
}

static void
goodix_receive_ack (FpDevice *dev, guint8 *data, guint16 length,
                    gpointer user_data, GError *error)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);
  GoodixAck *ack = (GoodixAck *) data;
  guint8 cmd;

  /* Zero-length decodes deliver NULL; never deref before this gate. */
  if (!data || length != sizeof (GoodixAck))
    {
      fp_warn ("Invalid ACK length: %d", length);
      return;
    }

  if (!ack->always_true)
    {
      // Warn about error.
      fp_warn ("Invalid ACK flags: 0x%02x", data[sizeof (guint8)]);
      return;
    }

  cmd = ack->cmd;

  if (ack->has_no_config)
    fp_warn ("MCU has no config");

  if (priv->cmd != cmd)
    {
      fp_warn ("Invalid ACK command: 0x%02x", cmd);
      return;
    }

  if (!priv->ack)
    {
      fp_warn ("Didn't expect an ACK for command: 0x%02x", priv->cmd);
      return;
    }

  if (!priv->reply)
    {
      G_DEBUG_HERE ();
      goodix_receive_done (dev, NULL, 0, NULL);
      return;
    }

  priv->ack = FALSE;
}

static void
goodix_receive_protocol (FpDevice *dev, guint8 *data, guint32 length)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);
  guint8 cmd;
  g_autofree guint8 *payload = NULL;
  guint16 payload_len;
  gboolean valid_checksum, valid_null_checksum;

  if (!goodix_decode_protocol (data, length, &cmd, &payload, &payload_len,
                               &valid_checksum, &valid_null_checksum))
    {
      fp_err ("Incomplete, size: %d", length);
      // Protocol is not full, we still need data.
      // TODO implement protocol assembling.
      return;
    }

  /* Ticket 52: Goodix firmware emits null-checksum (0x88) and MCU quirks;
   * strict drops cause timeouts. Maintain log-only tolerance while delivering,
   * except safety-critical cmds which are dropped below. */
  if (!valid_checksum && !valid_null_checksum)
    fp_dbg ("Protocol checksum mismatch for cmd 0x%02x; tolerated per ticket 52", cmd);

  if (!valid_checksum && !valid_null_checksum
      && goodix_cmd_is_safety_critical (cmd))
    {
      fp_warn ("Dropping bad-checksum safety-critical cmd 0x%02x", cmd);
      /* Fail fast when the dropped frame answers the pending command;
       * otherwise the waiter stays armed until the 1s timeout. A corrupt
       * frame for any other cmd is stray traffic: leave the waiter armed. */
      if ((priv->ack || priv->reply) && priv->cmd == cmd)
        {
          GError *checksum_error =
            g_error_new (G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                         "Bad checksum on safety-critical cmd 0x%02x", cmd);
          goodix_receive_done (dev, NULL, 0, checksum_error);
        }
      return;
    }

  if (cmd == GOODIX_CMD_ACK)
    {
      fp_dbg ("got ack");
      goodix_receive_ack (dev, payload, payload_len, NULL, NULL);
      return;
    }

  /* Stray-frame tolerance (intentional no-fail): a mismatched or
   * unsolicited frame must not kill the pending command's waiter — one
   * spurious frame would otherwise abort a legitimate wait. The timeout
   * remains the backstop for a reply that never arrives. */
  if (priv->cmd != cmd)
    {
      fp_warn ("Invalid protocol command: 0x%02x", cmd);
      return;
    }

  if (!priv->reply)
    {
      fp_warn ("Didn't expect a reply for command: 0x%02x", priv->cmd);
      return;
    }

  if (priv->ack)
    fp_warn ("Didn't got ACK for command: 0x%02x", priv->cmd);

  goodix_receive_done (dev, payload, payload_len, NULL);
}

static void
goodix_receive_pack (FpDevice *dev, guint8 *data, guint32 length)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  if (data && length > 0)
    {
      /* Cap accumulator to prevent unbounded allocation on corrupt streams */
      if (priv->length + length > GOODIX_EP_IN_MAX_BUF_SIZE * 2)
        {
          fp_warn ("Receive buffer exceeded frame cap; resetting accumulator");
          g_clear_pointer (&priv->data, g_free);
          priv->length = 0;
        }

      priv->data = g_realloc (priv->data, priv->length + length);
      memcpy (priv->data + priv->length, data, length);
      priv->length += length;
    }

  /* Iterative drain: decode + dispatch frames until the accumulator holds
   * an incomplete frame or is empty. (A recursive self-call here reached
   * ~32k stack depth on corrupt tiny-header streams: min consumed 4B
   * against a 128KiB accumulator cap.) */
  while (priv->data && priv->length > 0)
    {
      guint8 flags;
      guint8 *payload = NULL;
      guint16 payload_len;
      gboolean valid_checksum;
      guint32 consumed;
      gboolean drop;
      guint8 drop_cmd = 0;

      if (!goodix_decode_pack (priv->data, priv->length, &flags, &payload,
                               &payload_len, &valid_checksum))
        {
          /* Framing gate: the pack checksum covers the header only, so a
           * corrupt length byte would otherwise stall the pending command
           * here until timeout while the accumulator fills with bytes that
           * form no legit frame. A claim above GOODIX_PACK_MAX_PAYLOAD is
           * impossible (image frames are ~10.6KiB, TLS flights a few KiB),
           * so drop the accumulator and fail the waiter fast. Anything at
           * or below the cap keeps ticket-52 tolerance: wait for more data
           * and let the inner checksum gate judge the payload. */
          if (priv->length >= sizeof (GoodixPack) + sizeof (guint8))
            {
              guint16 claimed_le;
              guint16 claimed;
              memcpy (&claimed_le, priv->data + sizeof (guint8),
                      sizeof (claimed_le));
              claimed = GUINT16_FROM_LE (claimed_le);
              if (claimed > GOODIX_PACK_MAX_PAYLOAD)
                {
                  fp_warn ("Impossible pack payload length %u; dropping %u buffered bytes",
                           claimed, priv->length);
                  if (priv->ack || priv->reply)
                    goodix_receive_done (dev, NULL, 0,
                                         g_error_new (G_IO_ERROR,
                                                      G_IO_ERROR_INVALID_DATA,
                                                      "Impossible pack payload length: %u",
                                                      claimed));
                  g_clear_pointer (&priv->data, g_free);
                  priv->length = 0;
                  break;
                }
            }
          // Packet is not full, we still need data.
          fp_dbg ("not full packet");
          return;
        }

      /* Decode guarantees consumed <= priv->length, so this corrupt length
       * can no longer drive the memmove below or dispatch past the buffer. */
      consumed = (guint32) payload_len + sizeof (GoodixPack) + sizeof (guint8);

      /* Ticket 52: maintain log-only tolerance for pack checksums against hardware
       * quirks; safety-critical control frames are dropped (consumed, not dispatched). */
      if (!valid_checksum)
        fp_dbg ("Pack checksum mismatch for flags 0x%02x; tolerated per ticket 52", flags);

      /* ponytail: outer-frame gate (GoodixProtocol.cmd is payload[0]); the inner
       * checksum gate lives in goodix_receive_protocol. */
      drop = !valid_checksum && flags == GOODIX_FLAGS_MSG_PROTOCOL
        && payload_len >= 1 && payload != NULL
        && goodix_cmd_is_safety_critical (payload[0]);
      if (drop)
        drop_cmd = payload[0];

      if (drop)
        {
          fp_warn ("Dropping bad-checksum safety-critical pack cmd 0x%02x", drop_cmd);
          /* Fail fast when the dropped frame answers the pending command
           * (same goodix_receive_done idiom as the timeout path); stray
           * corrupt frames are only consumed. */
          if ((priv->ack || priv->reply) && priv->cmd == drop_cmd)
            goodix_receive_done (dev, NULL, 0,
                                 g_error_new (G_IO_ERROR,
                                              G_IO_ERROR_INVALID_DATA,
                                              "Bad pack checksum on safety-critical cmd 0x%02x",
                                              drop_cmd));
        }
      else
        {
          switch (flags)
            {
            case GOODIX_FLAGS_MSG_PROTOCOL:
              fp_dbg ("Got protocol msg");
              goodix_receive_protocol (dev, payload, payload_len);
              break;

            case GOODIX_FLAGS_TLS:
            case GOODIX_FLAGS_TLS_DATA:
              fp_dbg ("Got TLS msg (0x%02x, %u bytes)", flags, payload_len);
              if (priv->cmd == GOODIX_CMD_MCU_GET_IMAGE ||
                  priv->cmd == GOODIX_CMD_REQUEST_TLS_CONNECTION ||
                  (priv->reply && priv->callback != NULL && priv->cmd == 0))
                goodix_receive_done (dev, payload, payload_len, NULL);
              else
                fp_dbg ("Discarding stale TLS msg (0x%02x, len %u) while waiting for cmd 0x%02x",
                        flags, payload_len, priv->cmd);
              break;

            default:
              fp_warn ("Unknown flags: 0x%02x", flags);
              break;
            }
        }

      g_free (payload);

      /* Dispatch may have completed the waiter (goodix_receive_done clears
       * the accumulator via goodix_reset_state); re-check before advancing. */
      if (!priv->data || priv->length <= consumed)
        {
          g_clear_pointer (&priv->data, g_free);
          priv->length = 0;
          break;
        }
      /* Advance past the frame, then skip send-path zero padding (every
       * pack is padded to a 0x40 multiple). Padding must never be parsed
       * as the next header: flags 0x00/len 0 would dispatch a bogus empty
       * frame and desync the stream. A real header never opens with 0x00
       * (0xa0/0xb0/0xb2), so leading zeros are padding by construction. */
      {
        guint32 skip = consumed;
        while (skip < priv->length && priv->data[skip] == 0x00)
          skip++;
        if (skip >= priv->length)
          {
            g_clear_pointer (&priv->data, g_free);
            priv->length = 0;
            break;
          }
        if (skip != consumed)
          fp_dbg ("Skipped %u zero-padding bytes between packs", skip - consumed);
        memmove (priv->data, priv->data + skip, priv->length - skip);
        priv->length -= skip;
      }
    }
}

static void
goodix_receive_data_cb (FpiUsbTransfer *transfer, FpDevice *dev,
                        gpointer user_data, GError *error)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  if (g_cancellable_is_cancelled (priv->transfer_cancel_tkn) ||
      g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED) || !priv->inited)
    {
      fp_dbg ("transfer cancelled, aborting read loop...");
      if (error)
        g_error_free (error);
      return;
    }

  if (error)
    {
      fp_warn ("Receive data error: %s", error->message);
      g_error_free (error);

      // Retry receiving data and return.
      if (priv->inited)
        goodix_receive_data (dev);
      return;
    }

  goodix_receive_pack (dev, transfer->buffer, transfer->actual_length);

  goodix_receive_data (dev);
}

static void
goodix_receive_timeout_cb (FpDevice *dev, gpointer user_data)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);
  GError *error = NULL;

  priv->timeout = NULL;

  g_set_error (&error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
               "Command timed out: 0x%02x", priv->cmd);
  goodix_receive_done (dev, NULL, 0, error);
}

void
goodix_start_read_loop (FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  if (priv->inited)
    return;

  if (g_cancellable_is_cancelled (priv->transfer_cancel_tkn))
    g_cancellable_reset (priv->transfer_cancel_tkn);

  priv->inited = TRUE;
  g_clear_pointer (&priv->data, g_free);
  priv->length = 0;

  goodix_receive_data (dev);
}

void
goodix_stop_read_loop (FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  fp_dbg ("Stopping read loop");
  if (priv->transfer_cancel_tkn)
    g_cancellable_cancel (priv->transfer_cancel_tkn);

  priv->inited = FALSE;
  g_clear_pointer (&priv->data, g_free);
  priv->length = 0;
}

static void
goodix_receive_data (FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsClass *class = FPI_DEVICE_GOODIXTLS_GET_CLASS (self);
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  transfer->short_is_error = FALSE;

  fpi_usb_transfer_fill_bulk (transfer, class->ep_in,
                              GOODIX_EP_IN_MAX_BUF_SIZE);

  fpi_usb_transfer_submit (transfer, 0, priv->transfer_cancel_tkn,
                           goodix_receive_data_cb, NULL);
}

// ---- GOODIX RECEIVE SECTION END ----

// -----------------------------------------------------------------------------

// ---- GOODIX SEND SECTION START ----

gboolean
goodix_send_data (FpDevice *dev, guint8 *data, guint32 length,
                  GDestroyNotify free_func, GError **error)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsClass *class = FPI_DEVICE_GOODIXTLS_GET_CLASS (self);

  for (guint32 i = 0; i < length; i += GOODIX_EP_OUT_MAX_BUF_SIZE)
    {
      FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
      guint32 chunk_len = MIN ((guint32) GOODIX_EP_OUT_MAX_BUF_SIZE, length - i);
      transfer->short_is_error = TRUE;

      fpi_usb_transfer_fill_bulk_full (transfer, class->ep_out, data + i,
                                       chunk_len, NULL);

      if (!fpi_usb_transfer_submit_sync (transfer, GOODIX_TIMEOUT,
                                         error))
        {
          if (free_func)
            free_func (data);
          fpi_usb_transfer_unref (transfer);
          return FALSE;
        }
      fpi_usb_transfer_unref (transfer);
    }

  if (free_func)
    free_func (data);
  return TRUE;
}

gboolean
goodix_send_pack (FpDevice *dev, guint8 flags, guint8 *payload,
                  guint16 length, GDestroyNotify free_func,
                  GError **error)
{
  guint8 *data;
  guint32 data_len;

  goodix_encode_pack (flags, payload, length, TRUE, &data, &data_len);
  if (free_func)
    free_func (payload);

  /* ponytail: fail loudly on encode failure instead of sending an empty pack. */
  if (data == NULL)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Failed to encode pack (flags 0x%02x)", flags);
      return FALSE;
    }

  return goodix_send_data (dev, data, data_len, g_free, error);
}

void
goodix_send_protocol (
  FpDevice *dev, guint8 cmd, const guint8 *payload, guint16 length,
  GDestroyNotify free_func, gboolean calc_checksum, guint timeout_ms,
  gboolean reply, GoodixCmdCallback callback, gpointer user_data)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);
  GError *error = NULL;
  guint8 *data;
  guint32 data_len;

  if (priv->ack || priv->reply || priv->timeout)
    {
      // A command is already running.
      fp_warn ("A command is already running: 0x%02x", priv->cmd);
      if (free_func)
        free_func ((void *) payload);
      // ponytail: fail loudly so the waiting SSM aborts instead of hanging
      guint8 busy_cmd = priv->cmd;
      GError *collision_error =
        g_error_new (G_IO_ERROR, G_IO_ERROR_BUSY,
                     "A command is already running: 0x%02x", busy_cmd);
      goodix_receive_done (dev, NULL, 0, collision_error);
      /* The incoming request's waiter must also fail loudly — otherwise its
       * SSM stalls forever with no completion. Separate error object: the
       * one above is owned by the old waiter's completion path. */
      if (callback)
        {
          GError *incoming_error =
            g_error_new (G_IO_ERROR, G_IO_ERROR_BUSY,
                         "A command is already running: 0x%02x", busy_cmd);
          callback (dev, NULL, 0, user_data, incoming_error);
        }
      return;
    }

  fp_dbg ("Running command: 0x%02x", cmd);

  if (timeout_ms)
    priv->timeout = fpi_device_add_timeout (
      dev, timeout_ms, goodix_receive_timeout_cb, NULL, NULL);
  priv->cmd = cmd;
  priv->ack = TRUE;
  priv->reply = reply;
  priv->callback = callback;
  priv->user_data = user_data;

  goodix_encode_protocol (cmd, payload, length, calc_checksum, FALSE,
                          &data, &data_len);
  if (free_func)
    free_func ((void *) payload);

  /* ponytail: encode overflow yields NULL/0; fail loudly, don't send empty pack. */
  if (data == NULL)
    {
      GError *encode_error =
        g_error_new (G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                     "Failed to encode protocol command: 0x%02x", cmd);
      goodix_receive_done (dev, NULL, 0, encode_error);
      return;
    }

  if (!goodix_send_pack (dev, GOODIX_FLAGS_MSG_PROTOCOL, data, data_len,
                         g_free, &error))
    {
      goodix_receive_done (dev, NULL, 0, error);
      return;
    }
}
void
goodix_send_nop (FpDevice *dev, GoodixNoneCallback callback,
                 gpointer user_data)
{
  GoodixNop payload = {.unknown = 0x00000000};
  GoodixCallbackInfo *cb_info;

  /* ponytail: flush, not a handshake — silence is success (see tolerant
     receiver); a real ACK is still validated when one arrives. */
  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_NOP, (guint8 *) &payload,
                            sizeof (payload), NULL, FALSE, GOODIX_NOP_TIMEOUT, FALSE,
                            goodix_receive_none_tolerant, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_NOP, (guint8 *) &payload, sizeof (payload),
                        NULL, FALSE, GOODIX_NOP_TIMEOUT, FALSE, NULL, NULL);
}



void
goodix_send_mcu_get_image (FpDevice *dev, GoodixImageCallback callback,
                           gpointer user_data)
{
  GoodixCallbackInfo *cb_info;
  GoodixDefault payload_default = {.unused_flags = 0x01};
  guint8 *payload = (guint8 *) &payload_default;
  guint16 len = sizeof (payload_default);

  if (g_strcmp0 (fp_device_get_driver (dev), "goodixtls5e0a") == 0)
    {
      payload = g_object_get_data (G_OBJECT (dev), "goodix5e0a-capture-payload");
      if (!payload)
        {
          if (callback)
            callback (dev, NULL, 0, user_data,
                      fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                "Missing Goodix sensor calibration"));
          return;
        }
      len = 10;
    }

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_MCU_GET_IMAGE, payload,
                            len, NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                            goodix_receive_default, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_MCU_GET_IMAGE, payload,
                        len, NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                        NULL, NULL);
}

void
goodix_send_mcu_switch_to_fdt_down (FpDevice *dev, const guint8 *mode, guint16 length,
                                    GDestroyNotify free_func,
                                    GoodixDefaultCallback callback,
                                    gpointer user_data)
{
  GoodixCallbackInfo *cb_info = NULL;
  GoodixDefaultCallback cb = NULL;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);
      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;
      cb = goodix_receive_default;
    }

  if (mode && length > 0 && mode[0] == 0x01)
    {
      guint8 * payload = malloc (sizeof (guint8) * (length + 1));
      memcpy (payload + 1, mode, length);
      payload[0] = 0xc;
      if (free_func)
        free_func ((void *) mode);
      goodix_send_protocol (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_DOWN, payload, length + 1,
                            free, TRUE, 0, TRUE, cb, cb_info);
    }
  else
    {
      goodix_send_protocol (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_DOWN, mode, length,
                            free_func, TRUE, 0, TRUE, cb, cb_info);
    }
}

void
goodix_send_mcu_switch_to_fdt_up (FpDevice *dev, const guint8 *mode, guint16 length,
                                  GDestroyNotify free_func,
                                  GoodixDefaultCallback callback,
                                  gpointer user_data)
{
  GoodixCallbackInfo *cb_info = NULL;
  GoodixDefaultCallback cb = NULL;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);
      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;
      cb = goodix_receive_default;
    }

  if (mode && length > 0 && mode[0] == 0x01)
    {
      guint8 * payload = malloc (sizeof (guint8) * (length + 1));
      memcpy (payload + 1, mode, length);
      payload[0] = 0xe;
      if (free_func)
        free_func ((void *) mode);
      goodix_send_protocol (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_UP, payload, length + 1,
                            free, TRUE, 0, TRUE, cb, cb_info);
    }
  else
    {
      goodix_send_protocol (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_UP, mode, length,
                            free_func, TRUE, 0, TRUE, cb, cb_info);
    }
}

void
goodix_send_mcu_switch_to_fdt_mode (FpDevice *dev, const guint8 *mode,
                                    guint16 length, GDestroyNotify free_func,
                                    GoodixNoneCallback callback,
                                    gpointer user_data)
{
  GoodixCallbackInfo *cb_info = NULL;
  GoodixCmdCallback cb = NULL;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;
      cb = goodix_receive_none;
    }

  goodix_send_protocol (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_MODE, mode, length,
                        free_func, TRUE, GOODIX_TIMEOUT, FALSE, cb,
                        cb_info);

}

void
goodix_send_nav_0 (FpDevice *dev, GoodixDefaultCallback callback,
                   gpointer user_data)
{
  GoodixDefault payload = {.unused_flags = 0x01};
  GoodixCallbackInfo *cb_info;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_NAV_0, (guint8 *) &payload,
                            sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                            goodix_receive_default, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_NAV_0, (guint8 *) &payload,
                        sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE, NULL,
                        NULL);
}

void
goodix_send_mcu_switch_to_idle_mode (FpDevice *dev, guint8 sleep_time,
                                     GoodixNoneCallback callback,
                                     gpointer user_data)
{
  GoodixMcuSwitchToIdleMode payload = {.sleep_time = sleep_time};
  GoodixCallbackInfo *cb_info;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_MCU_SWITCH_TO_IDLE_MODE,
                            (guint8 *) &payload, sizeof (payload), NULL, TRUE,
                            GOODIX_TIMEOUT, FALSE, goodix_receive_none, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_MCU_SWITCH_TO_IDLE_MODE,
                        (guint8 *) &payload, sizeof (payload), NULL, TRUE,
                        GOODIX_TIMEOUT, FALSE, NULL, NULL);
}

void
goodix_send_write_sensor_register (FpDevice *dev, guint16 address,
                                   guint16 value,
                                   GoodixNoneCallback callback,
                                   gpointer user_data)
{
  // Only support one address and one value

  GoodixWriteSensorRegister payload = {.multiples = FALSE,
                                       .address = GUINT16_TO_LE (address),
                                       .value = GUINT16_TO_LE (value)};
  GoodixCallbackInfo *cb_info;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_WRITE_SENSOR_REGISTER,
                            (guint8 *) &payload, sizeof (payload), NULL, TRUE,
                            GOODIX_TIMEOUT, FALSE, goodix_receive_none, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_WRITE_SENSOR_REGISTER,
                        (guint8 *) &payload, sizeof (payload), NULL, TRUE,
                        GOODIX_TIMEOUT, FALSE, NULL, NULL);
}

void
goodix_send_read_sensor_register (FpDevice *dev, guint16 address,
                                  guint8 length,
                                  GoodixDefaultCallback callback,
                                  gpointer user_data)
{
  // Only support one address

  GoodixReadSensorRegister payload = {
    .multiples = FALSE, .address = GUINT16_TO_LE (address), .length = length
  };
  GoodixCallbackInfo *cb_info;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_READ_SENSOR_REGISTER,
                            (guint8 *) &payload, sizeof (payload), NULL, TRUE,
                            GOODIX_TIMEOUT, TRUE, goodix_receive_default, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_READ_SENSOR_REGISTER, (guint8 *) &payload,
                        sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE, NULL,
                        NULL);
}

void
goodix_send_upload_config_mcu (FpDevice *dev, guint8 *config,
                               guint16 length, GDestroyNotify free_func,
                               GoodixSuccessCallback callback,
                               gpointer user_data)
{
  GoodixCallbackInfo *cb_info;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_UPLOAD_CONFIG_MCU, config, length,
                            free_func, TRUE, GOODIX_TIMEOUT, TRUE,
                            goodix_receive_success, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_UPLOAD_CONFIG_MCU, config, length,
                        free_func, TRUE, GOODIX_TIMEOUT, TRUE, NULL, NULL);
}

void
goodix_send_set_powerdown_scan_frequency (FpDevice             *dev,
                                          guint16               powerdown_scan_frequency,
                                          GoodixSuccessCallback callback,
                                          gpointer              user_data)
{
  GoodixSetPowerdownScanFrequency payload = {
    .powerdown_scan_frequency = GUINT16_TO_LE (powerdown_scan_frequency)
  };
  GoodixCallbackInfo *cb_info;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_SET_POWERDOWN_SCAN_FREQUENCY,
                            (guint8 *) &payload, sizeof (payload), NULL, TRUE,
                            GOODIX_TIMEOUT, TRUE, goodix_receive_success, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_SET_POWERDOWN_SCAN_FREQUENCY,
                        (guint8 *) &payload, sizeof (payload), NULL, TRUE,
                        GOODIX_TIMEOUT, TRUE, NULL, NULL);
}

void
goodix_send_enable_chip (FpDevice *dev, gboolean enable,
                         GoodixNoneCallback callback, gpointer user_data)
{
  GoodixEnableChip payload = {.enable = enable ? TRUE : FALSE};
  GoodixCallbackInfo *cb_info;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_ENABLE_CHIP, (guint8 *) &payload,
                            sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, FALSE,
                            goodix_receive_none, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_ENABLE_CHIP, (guint8 *) &payload,
                        sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, FALSE, NULL,
                        NULL);
}

void
goodix_send_reset (FpDevice *dev, gboolean reset_sensor, guint8 sleep_time,
                   GoodixResetCallback callback, gpointer user_data)
{
  // Only support reset sensor

  GoodixReset payload = {.soft_reset_mcu = FALSE,
                         .reset_sensor = reset_sensor ? TRUE : FALSE,
                         .sleep_time = sleep_time};
  GoodixCallbackInfo *cb_info;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_RESET, (guint8 *) &payload,
                            sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                            goodix_receive_reset, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_RESET, (guint8 *) &payload,
                        sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE, NULL,
                        NULL);
}

void
goodix_send_query_firmware_version (FpDevice                     *dev,
                                    GoodixFirmwareVersionCallback callback,
                                    gpointer                      user_data)
{
  GoodixNone payload = {};
  GoodixCallbackInfo *cb_info;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_FIRMWARE_VERSION, (guint8 *) &payload,
                            sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                            goodix_receive_firmware_version, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_FIRMWARE_VERSION, (guint8 *) &payload,
                        sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE, NULL,
                        NULL);
}

void
goodix_send_query_mcu_state (FpDevice *dev, GoodixNoneCallback callback,
                             gpointer user_data)
{
  GoodixQueryMcuState payload = {.unused_flags = 0x55};
  GoodixCallbackInfo *cb_info;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_QUERY_MCU_STATE, (guint8 *) &payload,
                            sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, FALSE,
                            goodix_receive_none, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_QUERY_MCU_STATE, (guint8 *) &payload,
                        sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, FALSE, NULL,
                        NULL);
}

void
goodix_send_request_tls_connection (FpDevice             *dev,
                                    GoodixDefaultCallback callback,
                                    gpointer              user_data)
{
  /* Ticket 48 note: Windows wbdi.dll may send 2 bytes here, but the MCU
   * rejects non-zero-length payloads on this device — reverted to match
   * the working 0-byte behavior. */
  GoodixNone payload = {};
  GoodixCallbackInfo *cb_info;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_REQUEST_TLS_CONNECTION,
                            (guint8 *) &payload, sizeof (payload), NULL, TRUE, 0,
                            TRUE, goodix_receive_default, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_REQUEST_TLS_CONNECTION,
                        (guint8 *) &payload, sizeof (payload), NULL, TRUE,
                        GOODIX_TIMEOUT, TRUE, NULL, NULL);
}

void
goodix_send_tls_successfully_established (FpDevice          *dev,
                                          GoodixNoneCallback callback,
                                          gpointer           user_data)
{
  GoodixNone payload = {};
  GoodixCallbackInfo *cb_info;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;
      /* Ticket 86: The Goodix MCU acknowledges CMD 0xd4 in ~16ms with standard
       * GOODIX_CMD_ACK (0xb0) and sends no subsequent data packet (matching
       * Python tls_successfully_established). With reply=FALSE, goodix_receive_ack
       * completes the command immediately on ACK receipt, eliminating an artificial
       * 2000ms timeout wait. */

      goodix_send_protocol (dev, GOODIX_CMD_TLS_SUCCESSFULLY_ESTABLISHED,
                            (guint8 *) &payload, sizeof (payload), NULL, TRUE,
                            GOODIX_TIMEOUT, FALSE, goodix_receive_none, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_TLS_SUCCESSFULLY_ESTABLISHED,
                        (guint8 *) &payload, sizeof (payload), NULL, TRUE,
                        GOODIX_TIMEOUT, FALSE, NULL, NULL);
}

void
goodix_send_read_otp (FpDevice *dev, GoodixDefaultCallback callback,
                      gpointer user_data)
{
  GoodixNone payload = {};
  GoodixCallbackInfo *cb_info;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_READ_OTP, (guint8 *) &payload,
                            sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                            goodix_receive_default, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_READ_OTP, (guint8 *) &payload,
                        sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                        NULL, NULL);
}

void
goodix_send_preset_psk_read (FpDevice *dev, guint32 flags, guint16 length,
                             GoodixPresetPskReadCallback callback,
                             gpointer user_data)
{
  GoodixPresetPsk payload = {.flags = GUINT32_TO_LE (flags),
                             .length = GUINT32_TO_LE (length)};
  GoodixCallbackInfo *cb_info;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_PRESET_PSK_READ, (guint8 *) &payload,
                            sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                            goodix_receive_preset_psk_read, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_PRESET_PSK_READ, (guint8 *) &payload,
                        sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE, NULL,
                        NULL);
}

void
goodix_send_preset_psk_read_5e0a (FpDevice                   *dev,
                                  guint32                     flags,
                                  guint32                     length,
                                  guint32                     offset,
                                  GoodixPresetPskReadCallback callback,
                                  gpointer                    user_data)
{
  /* Ticket 48: 5e0a / Geneva CMD 0xe4 wire framing reversed from wbdi.dll
   * PresetPskReadG (0x1800978c8): 16 bytes consisting of
   * length (4B LE) + offset (4B LE) + flags (4B LE) + reserved (4B LE). */
  struct __attribute__((__packed__)) {
    guint32 length;
    guint32 offset;
    guint32 flags;
    guint32 reserved;
  } payload = {
    .length = GUINT32_TO_LE (length),
    .offset = GUINT32_TO_LE (offset),
    .flags = GUINT32_TO_LE (flags),
    .reserved = 0,
  };
  GoodixCallbackInfo *cb_info;

  if (callback)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);

      cb_info->callback = G_CALLBACK (callback);
      cb_info->user_data = user_data;

      goodix_send_protocol (dev, GOODIX_CMD_PRESET_PSK_READ, (guint8 *) &payload,
                            sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE,
                            goodix_receive_preset_psk_read, cb_info);
      return;
    }

  goodix_send_protocol (dev, GOODIX_CMD_PRESET_PSK_READ, (guint8 *) &payload,
                        sizeof (payload), NULL, TRUE, GOODIX_TIMEOUT, TRUE, NULL,
                        NULL);
}

// ---- GOODIX SEND SECTION END ----

// -----------------------------------------------------------------------------

// ---- DEV SECTION START ----

gboolean
goodix_dev_init (FpDevice *dev, GError **error)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsClass *class = FPI_DEVICE_GOODIXTLS_GET_CLASS (self);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  priv->timeout = NULL;
  priv->ack = FALSE;
  priv->reply = FALSE;
  priv->callback = NULL;
  priv->user_data = NULL;
  priv->data = NULL;
  priv->length = 0;
  priv->transfer_cancel_tkn = g_cancellable_new ();

  /* Ticket 42 conditional USB reset: skip the cold-state repair only when
   * the previous session on THIS USB device closed cleanly. The reset
   * wipes the device-side TLS key/config before activate runs, and
   * boot_seq follows the reset (not the open): a clean reopen is the same
   * device boot by construction (freezing the counter across a real reset
   * would fake warmth; bumping it across a skipped reset would fake
   * coldness and kill tickets 38/40 exactly as observed). Re-enumeration
   * (bus/address/port/vid/pid mismatch) forces dirty+reset regardless of
   * the flag; a NULL USB handle (never expected) is also dirty. */
  {
    GUsbDevice *usb = fpi_device_get_usb_device (dev);
    gboolean reenumerated = FALSE;
    gboolean take_reset;
    if (usb != NULL)
      {
        guint8 bus = g_usb_device_get_bus (usb);
        guint8 addr = g_usb_device_get_address (usb);
        guint8 port = g_usb_device_get_port_number (usb);
        guint16 vid = g_usb_device_get_vid (usb);
        guint16 pid = g_usb_device_get_pid (usb);
        if (priv->usb_identity_valid
            && (bus != priv->last_usb_bus || addr != priv->last_usb_addr
                || port != priv->last_usb_port || vid != priv->last_usb_vid
                || pid != priv->last_usb_pid))
          {
            reenumerated = TRUE;
            priv->clean_close = FALSE;
          }
        priv->last_usb_bus = bus;
        priv->last_usb_addr = addr;
        priv->last_usb_port = port;
        priv->last_usb_vid = vid;
        priv->last_usb_pid = pid;
        priv->usb_identity_valid = TRUE;
      }
    else
      {
        reenumerated = TRUE;
        priv->clean_close = FALSE;
      }
    if (priv->last_close_boot > 0)
      {
        gint64 sleep_time = goodix_sleep_us (priv->last_close_boot, priv->last_close_mono);
        if (sleep_time > 500000)
          {
            reenumerated = TRUE;
            priv->clean_close = FALSE;
          }
      }
    take_reset = !priv->clean_close;
    if (take_reset)
      {
        /* Ticket 40 (as amended by 42): counter follows the reset. */
        priv->boot_seq++;
        if (reenumerated)
          g_message ("5e0a USB reset taken (re-enumerated device, boot_seq=%u)",
                     priv->boot_seq);
        else
          g_message ("5e0a USB reset taken (dirty close, boot_seq=%u)",
                     priv->boot_seq);
        if (usb != NULL)
          g_usb_device_reset (usb, NULL);
      }
    else
      {
        g_message ("5e0a USB reset skipped (clean close, boot_seq=%u)",
                   priv->boot_seq);
      }
  }

  {
    gboolean ok = g_usb_device_claim_interface (fpi_device_get_usb_device (dev),
                                                class->interface, 0, error);
    if (!ok)
      priv->clean_close = FALSE;
    return ok;
  }
}
void
goodix_reset_state (FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);
  GoodixCmdCallback callback = priv->callback;
  gpointer user_data = priv->user_data;

  if (priv->timeout)
    g_clear_pointer (&priv->timeout, g_source_destroy);
  priv->ack = FALSE;
  priv->reply = FALSE;
  priv->cmd = 0;
  priv->callback = NULL;
  priv->user_data = NULL;
  g_clear_pointer (&priv->data, g_free);
  priv->length = 0;

  /* Never strand an armed waiter: suspend/deactivate/teardown call this
   * directly, bypassing goodix_receive_done. Snapshot + clear above (the
   * completion may re-arm a new command), then fail the waiter with
   * CANCELLED — the same goodix_receive_done completion idiom the timeout
   * path uses. Ownership invariant: the completion owns user_data (the
   * receive_* wrappers free a heap GoodixCallbackInfo; raw waiters such as
   * the goodix_read_tls SSM pointer are borrowed), so it is NOT freed here.
   * No recursion via goodix_receive_done: it clears callback before calling
   * here, so this is a no-op on that path. */
  if (callback)
    {
      GError *cancel_error =
        g_error_new (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                     "Command cancelled by state reset");
      callback (dev, NULL, 0, user_data, cancel_error);
    }
}

/* Ticket 34 stale-activation guard (single shared counter; live paths untouched). */
guint
goodix_activation_gen_get (FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  return priv->activation_gen;
}

guint
goodix_activation_gen_bump (FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  return ++priv->activation_gen;
}

/* Ticket 40 warm-activation key (single shared counter; live paths untouched).
 * Ticket 42 amends the bump site: goodix_dev_init bumps ONLY when the USB
 * reset is actually taken (see above). */
guint
goodix_boot_seq_get (FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  return priv->boot_seq;
}

/* Ticket 42 clean-vs-dirty session lifetime (single shared flag; live
 * paths untouched). Set ONLY in the goodix5e0a_deactivate park branch;
 * cleared on every failure funnel, on suspend entry, on destroy-path
 * deactivate, and on re-enumeration/claim failure in goodix_dev_init. */
void
goodix_session_mark_clean (FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  priv->clean_close = TRUE;
}

void
goodix_session_mark_dirty (FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  priv->clean_close = FALSE;
}

gboolean
goodix_session_is_clean (FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  return priv->clean_close;
}

gboolean
goodix_dev_deinit (FpDevice *dev, GError **error)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsClass *class = FPI_DEVICE_GOODIXTLS_GET_CLASS (self);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);
  gboolean clean_close = priv->clean_close;
  gboolean released;

  /* Ticket 42: clean close skips bump+shutdown (deactivate done). */
  if (!clean_close)
    goodix_activation_gen_bump (dev);

  priv->inited = FALSE;
  if (priv->timeout)
    {
      g_source_destroy (priv->timeout);
      priv->timeout = NULL;
    }
  g_free (priv->data);
  priv->data = NULL;
  if (priv->transfer_cancel_tkn)
    g_cancellable_cancel (priv->transfer_cancel_tkn);
  g_clear_object (&priv->transfer_cancel_tkn);
  if (!clean_close)
    goodix_shutdown_tls (dev, error);

  goodix_reset_state (dev);

  released = g_usb_device_release_interface (fpi_device_get_usb_device (dev),
                                              class->interface, 0, error);
  if (!released)
    {
      /* A failed release is a dirty close even if deactivate parked TLS.
       * Do not carry that context or its generation into the next open. */
      priv->clean_close = FALSE;
      if (clean_close)
        {
          goodix_activation_gen_bump (dev);
          goodix_shutdown_tls (dev, NULL);
        }
    }
  priv->last_close_boot = goodix_get_boottime_us ();
  priv->last_close_mono = g_get_monotonic_time ();
  return released;
}

// ---- DEV SECTION END ----

// -----------------------------------------------------------------------------

// ---- TLS SECTION START ----

/* TLS relay debug + coalesced-read helpers (ported from /tmp/libfprint
 * goodixtls@83e5522 read_all_tls_records + tls_hex_dump, adapted to the
 * single parked-TLS model here).
 *
 * The OpenSSL server side coalesces its flight (ServerHello..HelloDone,
 * CCS+Finished) into back-to-back TLS records on the socketpair. A single
 * read() on client_fd returns a short count as "success" and truncates the
 * flight, which desyncs the relay. Read whole records (5B header
 * type+ver+len, then body) until poll() reports no more data pending.
 * Bounded by buf_size; fp_dbg-gated and truncated so the hot path stays
 * a single line per flight (ticket 24/56). */
static void
goodix_tls_hex_dump (const char *label, const guint8 *data, int len)
{
  GString *s = g_string_sized_new (len * 3 + 64);
  g_string_append_printf (s, "5e0a TLS-RELAY %s (%d bytes):", label, len);
  int show = len > 128 ? 128 : len;
  for (int i = 0; i < show; i++)
    {
      if (i % 16 == 0)
        g_string_append_printf (s, "\n  %04x: ", i);
      g_string_append_printf (s, "%02x ", data[i]);
    }
  if (len > 128)
    g_string_append_printf (s, "\n  ... (%d more bytes)", len - 128);
  fp_dbg ("%s", s->str);
  g_string_free (s, TRUE);
}

static int
goodix_tls_read_all_records (int fd, guint8 *buf, int buf_size)
{
  int total = 0;
  struct pollfd pfd = { .fd = fd, .events = POLLIN };

  for (;;)
    {
      int hdr_got = 0;
      while (hdr_got < 5)
        {
          if (total + 5 - hdr_got > buf_size)
            {
              fp_dbg ("5e0a TLS-RELAY: buffer full at %d bytes", total);
              return total;
            }
          int n = read (fd, buf + total + hdr_got, 5 - hdr_got);
          if (n < 0 && errno == EINTR)
            continue;
          if (n <= 0)
            {
              fp_dbg ("5e0a TLS-RELAY: read header failed (got %d, errno %d)", n, errno);
              return (n <= 0 && total == 0) ? n : total;
            }
          hdr_got += n;
        }

      int rec_len = (buf[total + 3] << 8) | buf[total + 4];
      fp_dbg ("5e0a TLS-RELAY: record type=0x%02x ver=0x%02x%02x len=%d",
              buf[total], buf[total + 1], buf[total + 2], rec_len);

      total += 5;

      int body_got = 0;
      while (body_got < rec_len)
        {
          if (total + rec_len - body_got > buf_size)
            {
              fp_dbg ("5e0a TLS-RELAY: buffer full at %d bytes", total);
              return total;
            }
          int n = read (fd, buf + total + body_got, rec_len - body_got);
          if (n < 0 && errno == EINTR)
            continue;
          if (n <= 0)
            {
              fp_dbg ("5e0a TLS-RELAY: read body failed (got %d, errno %d)", n, errno);
              return total + body_got;
            }
          body_got += n;
        }
      total += rec_len;

      int ready = poll (&pfd, 1, 50);
      if (ready <= 0 || !(pfd.revents & POLLIN))
        break;
    }

  return total;
}

void
goodix_read_tls (FpDevice *dev, GoodixTlsCallback callback,
                 gpointer user_data)
{

  fp_dbg ("goodix_read_tls()");
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);
  if (priv->timeout)
    {
      g_source_destroy (priv->timeout);
      priv->timeout = NULL;
    }
  priv->timeout = fpi_device_add_timeout (
    dev, GOODIX_TIMEOUT, goodix_receive_timeout_cb, NULL, NULL);
  priv->callback = callback;
  priv->user_data = user_data;
  priv->reply = TRUE;
  priv->cmd = 0;
}

enum tls_states {
  TLS_SERVER_INIT,
  TLS_SERVER_HANDSHAKE_INIT,
  TLS_NUM_STATES,
};


static void
on_goodix_tls_read_handshake (FpDevice *dev, guint8 *data,
                              guint16 length, gpointer user_data,
                              GError *error)
{
  FpiSsm *ssm = user_data;

  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  FpiDeviceGoodixTls *self =
    FPI_DEVICE_GOODIXTLS (fpi_ssm_get_data (user_data));
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  int sent = goodix_tls_client_write (priv->tls_hop, data, length);

  if (sent < 0)
    {
      fpi_ssm_mark_failed (ssm, g_error_new (g_io_error_quark (), sent,
                                             "failed to sent data to "
                                             "tls server"));
      return;
    }
  fpi_ssm_next_state (ssm);
}

enum goodix_tls_handshake_stages {
  TLS_HANDSHAKE_STAGE_HELLO_S,
  TLS_HANDSHAKE_STAGE_KH_EXCHANGE,
  TLS_HANDSHAKE_STAGE_CHANGE_CIPHER_C,
  TLS_HANDSHAKE_STAGE_HANDSHAKE_C,
  TLS_HANDSHAKE_STAGE_CHANGE_CIPHER_S,

  TLS_HANDSHAKE_STAGE_NUM,
};

static void
on_tls_successfully_established (FpDevice *dev, gpointer user_data,
                                 GError *error)
{
  fp_dbg ("HANDSHAKE DONE");
  FpiDeviceGoodixTls * self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate * priv =
    fpi_device_goodixtls_get_instance_private (self);
  if (!priv->tls_ready_callback)
    {
      /* Torn down mid-flight (shutdown releases without invoking): nobody
       * waits, so drop. The error, if any, has no owner left — free it. */
      fp_dbg ("HANDSHAKE DONE with no waiter, dropping");
      if (error)
        g_error_free (error);
      return;
    }
  /* Ticket 86: 0xd4 completes on genuine MCU ACK without timing out. Propagate
   * any unexpected transfer error to the activation callback. */
  if (error)
    {
      fp_err ("failed to send TLS established: %s", error->message);
      ((GoodixNoneCallback) priv->tls_ready_callback->callback)(
        dev, priv->tls_ready_callback->user_data, error);
      g_clear_pointer (&priv->tls_ready_callback, g_free);
      return;
    }
  ((GoodixNoneCallback) priv->tls_ready_callback->callback)(
    dev, priv->tls_ready_callback->user_data, NULL);
  g_clear_pointer (&priv->tls_ready_callback, g_free);
}
static void
tls_handshake_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  if (error)
    {
      fp_err ("failed to do tls handshake: %s (code: %d)", error->message,
              error->code);
      FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
      FpiDeviceGoodixTlsPrivate *priv =
        fpi_device_goodixtls_get_instance_private (self);
      if (priv->tls_ready_callback)
        {
          ((GoodixNoneCallback) priv->tls_ready_callback->callback)(
            dev, priv->tls_ready_callback->user_data, error);
          g_clear_pointer (&priv->tls_ready_callback, g_free);
        }
      else
        g_error_free (error);
      return;
    }
  goodix_send_tls_successfully_established (
    dev, on_tls_successfully_established, NULL);
}

static void
tls_handshake_run (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  if (!priv->tls_hop)
    {
      fpi_ssm_mark_failed (ssm, g_error_new (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                             "TLS session context missing"));
      return;
    }

  int stage = fpi_ssm_get_cur_state (ssm);

  if (stage == TLS_HANDSHAKE_STAGE_HELLO_S)
    {
      guint8 buff[4096];
      int size = goodix_tls_read_all_records (priv->tls_hop->client_fd,
                                              buff, sizeof (buff));
      if (size <= 0)
        {
          fpi_ssm_mark_failed (ssm, g_error_new (g_io_error_quark (), size,
                                                 "failed to read tls server "
                                                 "hello"));
          return;
        }
      goodix_tls_hex_dump ("ServerHello flight (server->device)", buff, size);
      GError *err = NULL;
      if (!goodix_send_pack (dev, GOODIX_FLAGS_TLS, buff, size, NULL, &err))
        {
          fpi_ssm_mark_failed (ssm, err);
          return;
        }
      fpi_ssm_next_state (ssm);
    }
  else if (stage < TLS_HANDSHAKE_STAGE_CHANGE_CIPHER_S)
    {
      // Still proxying from hardware
      fpi_ssm_set_data (ssm, dev, NULL);
      goodix_read_tls (dev, on_goodix_tls_read_handshake, ssm);
    }
  else if (stage == TLS_HANDSHAKE_STAGE_CHANGE_CIPHER_S)
    {
      fp_dbg ("Reading to proxy back");
      guint8 buff[4096];
      int size = goodix_tls_read_all_records (priv->tls_hop->client_fd,
                                              buff, sizeof (buff));
      if (size <= 0)
        {
          fpi_ssm_mark_failed (ssm, g_error_new (g_io_error_quark (), size,
                                                 "failed to read server "
                                                 "handshake"));

          return;
        }
      goodix_tls_hex_dump ("ServerCCS+Finished (server->device)", buff, size);
      GError *err = NULL;
      if (!goodix_send_pack (dev, GOODIX_FLAGS_TLS, buff, size, NULL, &err))
        {
          fpi_ssm_mark_failed (ssm, err);
          return;
        }
      fpi_ssm_next_state (ssm);
    }
}

static void
do_tls_handshake (FpDevice *dev)
{
  fpi_ssm_start (fpi_ssm_new (dev, tls_handshake_run, TLS_HANDSHAKE_STAGE_NUM),
                 tls_handshake_done);
}

static void
on_goodix_request_tls_connection (FpDevice *dev, guint8 *data,
                                  guint16 length, gpointer user_data,
                                  GError *error)
{
  if (error)
    {
      fp_err ("failed to get tls handshake: %s", error->message);
      /* Ticket 48: propagate the error to tls_ready_callback so the
       * activation path (on_tls_activation_complete) receives it and can
       * report activation failure or trigger the warm-fallback retry.
       * The old code called goodix_send_tls_successfully_established
       * which swallowed the error and fired the callback as if TLS had
       * succeeded — causing scan commands on a dead channel. */
      FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
      FpiDeviceGoodixTlsPrivate *priv =
        fpi_device_goodixtls_get_instance_private (self);
      if (priv->tls_ready_callback)
        {
          ((GoodixNoneCallback) priv->tls_ready_callback->callback)(
            dev, priv->tls_ready_callback->user_data, error);
          g_clear_pointer (&priv->tls_ready_callback, g_free);
        }
      else
        g_error_free (error);
      return;
    }
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (user_data);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  goodix_tls_client_write (priv->tls_hop, data, length);

  do_tls_handshake (dev);
}

void
goodix_tls_init (FpDevice *dev, GoodixNoneCallback callback, gpointer user_data)
{
  fp_dbg ("Starting up goodix tls server");
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);
  g_assert (priv->tls_hop == NULL);
  priv->tls_hop = g_new0 (GoodixTlsServer, 1);

  if (!priv->tls_ready_callback)
    priv->tls_ready_callback = g_new0 (GoodixCallbackInfo, 1);
  priv->tls_ready_callback->callback = G_CALLBACK (callback);
  priv->tls_ready_callback->user_data = user_data;
  GoodixTlsServer *s = priv->tls_hop;
  s->user_data = self;
  GError *err = NULL;
  if (!goodix_tls_server_init (priv->tls_hop, &err))
    {
      fp_err ("failed to init tls server, error: %s, code: %d", err->message,
              err->code);
      /* The activation waiter must fail loudly instead of hanging: forward
       * the error into the stored callback, then release the half-built
       * server so a later claim can start clean (entry asserts NULL). */
      g_free (priv->tls_hop);
      priv->tls_hop = NULL;
      if (priv->tls_ready_callback)
        {
          ((GoodixNoneCallback) priv->tls_ready_callback->callback)(
            dev, priv->tls_ready_callback->user_data, err);
          g_clear_pointer (&priv->tls_ready_callback, g_free);
        }
      else if (err)
        {
          g_error_free (err);
        }
      return;
    }

  goodix_send_request_tls_connection (dev,
                                      on_goodix_request_tls_connection, dev);
}

gboolean
goodix_shutdown_tls (FpDevice *dev, GError **error)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  if (priv->tls_hop)
    {
      gboolean rs = goodix_tls_server_deinit (priv->tls_hop, error);
      g_free (priv->tls_hop);
      priv->tls_hop = NULL;
      /* A teardown racing a live handshake strands the ready callback: no
       * waiter needs completion here (deactivate/suspend already completed
       * the claim), so release it without invoking. Never invoke: the
       * orphaned handshake SSM can no longer complete, and completing
       * activation post-teardown would double-complete the claim. */
      g_clear_pointer (&priv->tls_ready_callback, g_free);
      return rs;
    }
  g_clear_pointer (&priv->tls_ready_callback, g_free);
  return TRUE;
}

gboolean
goodix_tls_is_alive (FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  return priv->tls_hop != NULL;
}
static void
goodix_tls_ready_image_handler (FpDevice *dev, guint8 *data,
                                guint16 length, gpointer user_data,
                                GError *error)
{
  GoodixCallbackInfo *cb_info = user_data;
  GoodixImageCallback callback = (GoodixImageCallback) cb_info->callback;

  if (error)
    {
      callback (dev, NULL, 0, cb_info->user_data, error);
      g_free (cb_info);
      return;
    }
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  FpiDeviceGoodixTlsPrivate *priv =
    fpi_device_goodixtls_get_instance_private (self);

  guint8 *tls_data = data;
  guint16 tls_len = length;

  if (data && length > 9 && data[0] == 0x00 && data[1] == 0x20)
    {
      tls_data = data + 9;
      tls_len = length - 9;
    }
  else if (data && length > 5 && data[0] != 0x17)
    {
      for (guint16 i = 0; i + 5 < length; i++)
        {
          if (data[i] == 0x17 && data[i + 1] == 0x03 && data[i + 2] == 0x03)
            {
              tls_data = data + i;
              tls_len = length - i;
              break;
            }
        }
    }

  goodix_tls_client_write (priv->tls_hop, tls_data, tls_len);

  guint32 size = 65535;
  g_autofree guint8 *buff = g_malloc (size);
  GError *err = NULL;
  int read_size = goodix_tls_server_read (priv->tls_hop, buff, size, &err);

  if (read_size <= 0)
    {
      callback (dev, NULL, 0, cb_info->user_data, err);
      g_free (cb_info);
      return;
    }

  callback (dev, buff, read_size, cb_info->user_data, NULL);
  g_free (cb_info);
}

void
goodix_tls_read_image (FpDevice *dev, GoodixImageCallback callback,
                       gpointer user_data)
{
  g_assert (callback);
  GoodixCallbackInfo *cb_info = g_new0 (GoodixCallbackInfo, 1);

  cb_info->callback = G_CALLBACK (callback);
  cb_info->user_data = user_data;

  goodix_send_mcu_get_image (dev, goodix_tls_ready_image_handler, cb_info);
}

// ---- TLS SECTION END ----

static void
fpi_device_goodixtls_init (FpiDeviceGoodixTls *self)
{
}

static void
fpi_device_goodixtls_class_init (FpiDeviceGoodixTlsClass *class)
{
}
