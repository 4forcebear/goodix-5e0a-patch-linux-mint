// Goodix TLS driver for libfprint - 27c6:5e0a (Realme Book / ChicagoH)
// Reverse engineered for NixOS - Windows-faithful steady-state port (Ticket 10)

// Copyright (C) 2026 The libfprint Goodix 5e0a contributors

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

#include "drivers/goodixtls/goodix5xx.h"
#include "fp-device.h"
#include "fp-image-device.h"
#include "fp-image.h"
#include "fpi-image-device.h"
#include "fpi-image.h"
#include "fpi-ssm.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

#define FP_COMPONENT "goodixtls5e0a"

#include <glib.h>
#include <string.h>

#include "drivers_api.h"
#include "goodix.h"
#include "goodix_proto.h"
#include "goodix5e0a.h"
#include "goodix5e0a-image.h"
#include "goodix_milan.h"


guint32 goodix5e0a_last_declen = 0;

static void goodix5e0a_scan_start (FpDevice *);

static void
goodix5e0a_activate_complete (FpDevice *dev, GError *error)
{
  if (error)
    {
      fpi_device_action_error (dev, error);
      return;
    }
  goodix5e0a_scan_start (dev);
}

#define fpi_image_device_activate_complete(idev, err) \
  goodix5e0a_activate_complete (FP_DEVICE (idev), (err))

#define fpi_image_device_deactivate_complete(idev, err) \
  do { if (err) fpi_device_action_error (FP_DEVICE (idev), (err)); } while (0)

#define fpi_image_device_session_error(idev, err) \
  fpi_device_action_error (FP_DEVICE (idev), (err))

#define fpi_image_device_report_finger_status(idev, present) \
  fpi_device_report_finger_status_changes (FP_DEVICE (idev), \
                                           (present) ? FP_FINGER_STATUS_PRESENT : 0, \
                                           (present) ? 0 : FP_FINGER_STATUS_PRESENT)

struct _FpiDeviceGoodixTls5e0a
{
  FpiDeviceGoodixTls5xx parent;

  gboolean              session_started;
  FpiSsm               *scan_ssm;
  guint                 scan_gen;
  guint                 scan_timeout_gen;
  GSource              *down_timeout;
  /* Consecutive zero-length FDT_DOWN replies (bounded by
   * GOODIX_5E0A_DOWN_EMPTY_POLL_MAX); reset by any valid reply. */
  guint                 down_empty_polls;

  /* Ticket 38 parked TLS session */
  gboolean              tls_parked;
  gint64                tls_parked_at;
  guint                 tls_parked_gen;
  gint64                tls_parked_boot;

  /* Ticket 40 warm activation fast path */
  gboolean              warm_ok;
  gint64                last_clean_mono;
  guint                 warm_boot_seq;
  const char           *warm_down_reason;
  gboolean              warm_attempted;
  gboolean              warm_retried;
  gint64                last_clean_boot;

  /* Best-of-N per-touch state */
  guint               frame_count;
  guint               best_frame_no;
  guint               best_quality;
  guint               best_overlap;
  guint               best_range;

  /* Ticket 47: verify retry guard against rapid retry burn on continuous touch */
  gboolean            retry_guard;
  gint64              retry_guard_mono;

  /* Ticket 73 + 77: Milan enrollment, verify and identify state */
  gboolean            is_verify;
  gboolean            is_identify;
  guint               enroll_stage;
  void               *milan_enrol_ctx;
  guint8             *tmpl_blob;
  gsize               tmpl_len;
  guint8              best_pixels[GOODIX_5E0A_FRAME_SIZE];
  guint               best_active;
  guint8              latest_norm_pixels[GOODIX_5E0A_FRAME_SIZE];
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodixTls5e0a, fpi_device_goodixtls5e0a, FPI,
                      DEVICE_GOODIXTLS5E0A, FpiDeviceGoodixTls5xx);

G_DEFINE_TYPE (FpiDeviceGoodixTls5e0a, fpi_device_goodixtls5e0a,
               FPI_TYPE_DEVICE_GOODIXTLS5XX);

static void goodix5e0a_reset_touch_frames (FpiDeviceGoodixTls5e0a *self);

// ---- ACTIVATE SECTION START ----

/* Ticket 38 / 85: Parked-TLS session TTL (300s) and probe timeout (500ms) */
#define GOODIX_5E0A_TLS_PARK_TTL_US (G_USEC_PER_SEC * 300)
#define GOODIX_5E0A_TLS_PARK_HEALTH_TIMEOUT_MS 500

/* Ticket 40: Warm activation TTL (60s) */
#define GOODIX_5E0A_WARM_TTL_US (G_USEC_PER_SEC * 60)

enum activate_states {
  ACTIVATE_READ_AND_NOP,
  ACTIVATE_RESET,
  ACTIVATE_READ_CHIP_ID,
  ACTIVATE_READ_OTP,
  ACTIVATE_CHECK_FW_VER,
  ACTIVATE_UPLOAD_CONFIG,
  ACTIVATE_CHECK_PSK,
  ACTIVATE_NUM_STATES,
};

/* Ticket 48: PresetPskIsVaildG reads MCU slot 0xbb020001 to prime crypto. */
static void activate_complete (FpiSsm *ssm, FpDevice *dev, GError *error);

/* Ticket 48: PSK hash read callback primes the MCU crypto subsystem. */
static void
on_psk_hash_read (FpDevice *dev, gboolean success, guint32 flags,
                  guint8 *psk, guint16 length, gpointer user_data,
                  GError *error)
{
  FpiSsm *ssm = user_data;

  if (error)
    {
      fp_warn ("PSK hash read (0x%x) failed: %s — continuing to TLS",
               flags, error->message);
      g_error_free (error);
    }
  else
    {
      fp_dbg ("PSK hash read (0x%x): success=%d, len=%d",
              flags, success, length);
    }
  fpi_ssm_next_state (ssm);
}

static void
activate_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  /* Ticket 40: READ_AND_NOP starts read loop; skips middle states on warm path. */
  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ACTIVATE_READ_AND_NOP:
      goodix_start_read_loop (dev);
      goodix_send_nop (dev, goodixtls5xx_check_none, ssm);
      break;

    case ACTIVATE_RESET:
      /* Ticket 45: 5e0a relies on USB reset rather than MCU command 0xa2. */
      fpi_ssm_jump_to_state (ssm, ACTIVATE_CHECK_FW_VER);
      break;

    case ACTIVATE_READ_CHIP_ID:
      if (self->warm_attempted)
        {
          fpi_ssm_jump_to_state (ssm, ACTIVATE_CHECK_FW_VER);
          return;
        }
      goodix_send_read_sensor_register (dev, 0x0000, 4, goodixtls5xx_check_none_cmd, ssm);
      break;

    case ACTIVATE_READ_OTP:
      if (self->warm_attempted)
        {
          fpi_ssm_jump_to_state (ssm, ACTIVATE_CHECK_FW_VER);
          return;
        }
      goodix_send_read_otp (dev, goodixtls5xx_check_none_cmd, ssm);
      break;

    case ACTIVATE_CHECK_FW_VER:
      goodix_send_query_firmware_version (dev, goodixtls5xx_check_firmware_version, ssm);
      break;

    case ACTIVATE_UPLOAD_CONFIG:
      /* Ticket 48: Config upload occurs after TLS completion in on_tls_activation_complete. */
      if (self->warm_attempted)
        {
          fpi_ssm_jump_to_state (ssm, ACTIVATE_NUM_STATES);
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    case ACTIVATE_CHECK_PSK:
      if (self->warm_attempted)
        {
          fpi_ssm_jump_to_state (ssm, ACTIVATE_NUM_STATES);
          return;
        }
      fp_dbg ("Cold path — reading PSK slot 0x%08x to latch MCU crypto state...", GOODIX_5E0A_PSK_FLAGS);
      goodix_send_preset_psk_read_5e0a (dev, GOODIX_5E0A_PSK_FLAGS, 32, 0,
                                        on_psk_hash_read, ssm);
      break;
    }
}

static void
on_chip_enabled (FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  if (user_data && GPOINTER_TO_UINT (user_data) != goodix_activation_gen_get (dev))
    {
      fp_dbg ("dropping stale on_chip_enabled completion");
      if (error)
        g_error_free (error);
      return;
    }

  if (error)
    {
      /* Ticket 40: a dead enable poisons recency — the next claim ladder-checks. */
      self->warm_ok = FALSE;
      self->warm_down_reason = "failed-last";
      self->warm_attempted = FALSE;
      goodix_session_mark_dirty (dev);
      fp_err ("failed to enable chip: %s (code: %d)", error->message, error->code);
      fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), error);
      return;
    }
  /* Ticket 40: the last host→device proof — stamp warmth for the next claim. */
  self->warm_ok = TRUE;
  self->last_clean_mono = g_get_monotonic_time ();
  self->last_clean_boot = goodix_get_boottime_us ();
  self->warm_boot_seq = goodix_boot_seq_get (dev);
  self->warm_attempted = FALSE;
  fp_dbg ("Chip enabled! Activation complete.");
  fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), NULL);
}

/* Ticket 40 warm predicate: host-observed recency on the same device boot.
 * img_open (goodix_dev_init) brackets the whole open session, not each
 * claim, so boot_seq survives back-to-back verifies and only turns on
 * reopen/re-enumeration. TTL expiry is applied lazily by the caller. */
static gboolean
goodix5e0a_warm_fresh (FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  gint64 now_boot = goodix_get_boottime_us ();

  if (self->last_clean_boot > 0)
    {
      gint64 sleep_time = goodix_sleep_us (self->last_clean_boot, self->last_clean_mono);
      if (sleep_time > 500000)
        {
          self->warm_ok = FALSE;
          self->warm_down_reason = "suspended";
          return FALSE;
        }
      if ((now_boot - self->last_clean_boot) >= GOODIX_5E0A_WARM_TTL_US)
        return FALSE;
    }

  return self->warm_ok
         && self->warm_boot_seq == goodix_boot_seq_get (dev)
         && (g_get_monotonic_time () - self->last_clean_mono) < GOODIX_5E0A_WARM_TTL_US;
}

static void
goodix5e0a_log_warm_taken (FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  g_message ("5e0a warm activation: reusing MCU config (age=%.1fs, boot_seq=%u)",
             (g_get_monotonic_time () - self->last_clean_mono) / (gdouble) G_USEC_PER_SEC,
             self->warm_boot_seq);
}

/* Ticket 40 warm bring-up: the SAME SSM/engine/callbacks as the full ladder
 * — activate_run_state skips RESET/CHIP_ID/OTP/CONFIG while warm_attempted
 * is set, so this is READ_AND_NOP + FW check + TLS by construction. There
 * is never a third half-bring-up path, and the handshake is never skipped:
 * SSL_accept failure stays loud via the funnels below. */
static void
goodix5e0a_start_warm_activation (FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  self->session_started = FALSE;
  self->scan_ssm = NULL;
  self->down_timeout = NULL;
  self->warm_attempted = TRUE;

  g_message ("5e0a warm path: skipping RESET + config upload, entry=CHECK_FW_VER");
  fpi_ssm_start (fpi_ssm_new (dev, activate_run_state, ACTIVATE_NUM_STATES),
                 activate_complete);
}

/* Ticket 38: the bring-up ladder */
static void
goodix5e0a_start_full_activation (FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  self->session_started = FALSE;
  self->scan_ssm = NULL;
  self->down_timeout = NULL;
  /* Ticket 40: the full ladder never skips — a stale warm flag from an
   * orphaned attempt must not leak into this run. */
  self->warm_attempted = FALSE;

  fpi_ssm_start (fpi_ssm_new (dev, activate_run_state, ACTIVATE_NUM_STATES),
                 activate_complete);
}

/* Ticket 38 parked-session health probe reply */
static void
on_parked_health_reply (FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  guint gen = GPOINTER_TO_UINT (user_data);

  if (gen != goodix_activation_gen_get (dev))
    {
      fp_dbg ("dropping stale parked-TLS health reply");
      if (error)
        g_error_free (error);
      return;
    }

  if (error)
    {
      const char *reason = "tls-error";
      gboolean transport_miss = FALSE;
      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
        {
          reason = "timeout";
          transport_miss = TRUE;
        }
      g_error_free (error);
      goodix_shutdown_tls (dev, NULL);
      goodix_reset_state (dev);
      if (transport_miss)
        {
          /* Ticket 40: the device went silent — the MCU may have rebooted,
           * so config recency is void. Falls through to today's full
           * ladder, unchanged. */
          self->warm_ok = FALSE;
          self->warm_down_reason = "transport-miss";
        }
      /* Ticket 40: crypto-grade miss — retry via warm activation if fresh */
      else if (goodix5e0a_warm_fresh (dev))
        {
          goodix5e0a_log_warm_taken (dev);
          goodix5e0a_start_warm_activation (dev);
          return;
        }
      g_message ("5e0a parked TLS session unhealthy (%s), full re-handshake", reason);
      goodix5e0a_start_full_activation (dev);
      return;
    }

  g_message ("5e0a TLS session reused (parked %.1fs, gen=%u)",
             (g_get_monotonic_time () - self->tls_parked_at) / (gdouble) G_USEC_PER_SEC,
             gen);
  fp_dbg ("parked TLS session healthy, confirming chip enable");
  goodix_send_enable_chip (dev, TRUE, on_chip_enabled, NULL);
}

/* Ticket 48: config upload callback used after TLS succeeds (cold path).
 * On success, proceed to chip enable; on failure, report activation error. */
static void
on_post_tls_config_uploaded (FpDevice *dev, gboolean success,
                             gpointer user_data, GError *error)
{
  if (user_data && GPOINTER_TO_UINT (user_data) != goodix_activation_gen_get (dev))
    {
      fp_dbg ("dropping stale on_post_tls_config_uploaded completion");
      if (error)
        g_error_free (error);
      return;
    }

  if (error)
    {
      fp_err ("failed to upload config after TLS: %s", error->message);
      fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), error);
      return;
    }
  if (!success)
    {
      fp_err ("MCU rejected config upload after TLS");
      fpi_image_device_activate_complete (
        FP_IMAGE_DEVICE (dev),
        g_error_new (FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                     "failed to upload mcu config after TLS"));
      return;
    }
  fp_dbg ("Config uploaded after TLS, enabling chip...");
  goodix_send_enable_chip (dev, TRUE, on_chip_enabled,
                           GUINT_TO_POINTER (goodix_activation_gen_get (dev)));
}

static void
on_tls_activation_complete (FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  /* Ticket 34 stale-activation guard: a deactivate/teardown that landed
   * while the TLS handshake was in flight bumped the generation, so a
   * mismatch means this completion is orphaned — drop it without touching
   * hardware or completing activation. Live sessions always match. */
  if (GPOINTER_TO_UINT (user_data) != goodix_activation_gen_get (dev))
    {
      fp_dbg ("dropping stale TLS activation completion");
      if (error)
        g_error_free (error);
      return;
    }

  if (error)
    {
      goodix_session_mark_dirty (dev);
      /* Ticket 40 warm fallback: retry full ladder once on failed warm handshake */
      if (self->warm_attempted && !self->warm_retried)
        {
          self->warm_ok = FALSE;
          self->warm_down_reason = "failed-last";
          self->warm_attempted = FALSE;
          self->warm_retried = TRUE;
          g_message ("5e0a warm attempt failed (%s), retrying full ladder", error->message);
          g_error_free (error);
          goodix_shutdown_tls (dev, NULL);
          goodix_reset_state (dev);
          goodix5e0a_start_full_activation (dev);
          return;
        }
      self->warm_ok = FALSE;
      self->warm_down_reason = "failed-last";
      self->warm_attempted = FALSE;
      fp_err ("failed during TLS activation: %s (code: %d)", error->message, error->code);
      fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), error);
      return;
    }

  fp_dbg ("TLS connection ready!");

  /* Ticket 48: upload config AFTER TLS, matching Windows order.
   * Warm reuse already has config loaded — skip straight to chip enable. */
  if (self->warm_attempted)
    {
      fp_dbg ("Warm path — config already loaded, enabling chip...");
      goodix_send_enable_chip (dev, TRUE, on_chip_enabled,
                               GUINT_TO_POINTER (goodix_activation_gen_get (dev)));
    }
  else
    {
      fp_dbg ("Cold path — uploading config after TLS...");
      goodix_send_upload_config_mcu (dev, (guint8 *) goodix_5e0a_config,
                                     sizeof (goodix_5e0a_config), NULL,
                                     on_post_tls_config_uploaded,
                                     GUINT_TO_POINTER (goodix_activation_gen_get (dev)));
    }
}

static void
activate_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  G_DEBUG_HERE ();
  if (!error)
    {
      /* Ticket 34: capture the activation generation for the staleness guard. */
      goodix_tls_init (dev, on_tls_activation_complete,
                       GUINT_TO_POINTER (goodix_activation_gen_get (dev)));
    }
  else
    {
      goodix_session_mark_dirty (dev);
      /* Ticket 40 warm fallback: retry full ladder once on failed warm ladder */
      if (self->warm_attempted && !self->warm_retried)
        {
          self->warm_ok = FALSE;
          self->warm_down_reason = "failed-last";
          self->warm_attempted = FALSE;
          self->warm_retried = TRUE;
          g_message ("5e0a warm attempt failed (%s), retrying full ladder", error->message);
          g_error_free (error);
          goodix5e0a_start_full_activation (dev);
          return;
        }
      self->warm_ok = FALSE;
      self->warm_down_reason = "failed-last";
      self->warm_attempted = FALSE;
      fp_err ("failed during activation: %s (code: %d)", error->message, error->code);
      fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), error);
    }
}

static void
dev_activate (FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE (img_dev);
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  /* Ticket 34: invalidate any in-flight activation from a previous session.
   * Ticket 38: capture the pre-bump generation first — a parked session is
   * pinned to exactly that generation at park time, so equality proves no
   * deactivate/teardown raced between park and this claim. */
  guint pre_gen = goodix_activation_gen_get (dev);
  guint new_gen = goodix_activation_gen_bump (dev);
  gint64 now_boot = goodix_get_boottime_us ();
  gboolean park_suspended = FALSE;

  /* Ticket 39: a stale burst winner must never survive across claims. */
  goodix5e0a_reset_touch_frames (self);

  /* Ticket 40: each claim gets exactly one silent warm-to-full retry. */
  self->warm_retried = FALSE;

  if (self->tls_parked && self->tls_parked_boot > 0)
    {
      gint64 sleep_time = goodix_sleep_us (self->tls_parked_boot, self->tls_parked_at);
      if (sleep_time > 500000 || (now_boot - self->tls_parked_boot) >= GOODIX_5E0A_TLS_PARK_TTL_US)
        park_suspended = TRUE;
    }

  if (self->tls_parked && self->tls_parked_gen == pre_gen
      && goodix_tls_is_alive (dev)
      && !park_suspended
      && (now_boot - self->tls_parked_boot) < GOODIX_5E0A_TLS_PARK_TTL_US
      && (g_get_monotonic_time () - self->tls_parked_at) < GOODIX_5E0A_TLS_PARK_TTL_US)
    {
      GoodixCallbackInfo *cb_info;
      GoodixQueryMcuState payload;

      /* Ticket 38 reuse attempt: claim the park now so the probe's fallback
       * below can never loop back into this branch. */
      self->tls_parked = FALSE;
      self->scan_ssm = NULL;
      self->down_timeout = NULL;
      fp_dbg ("5e0a parked TLS session candidate fresh, health-checking (gen=%u)", new_gen);
      goodix_start_read_loop (dev);
      /* Ticket 38: Fast QUERY_MCU_STATE health probe */
      cb_info = g_new0 (GoodixCallbackInfo, 1);
      cb_info->callback = G_CALLBACK (on_parked_health_reply);
      cb_info->user_data = GUINT_TO_POINTER (new_gen);
      payload.unused_flags = 0x55;
      goodix_send_protocol (dev, GOODIX_CMD_QUERY_MCU_STATE,
                            (guint8 *) &payload, sizeof (payload),
                            NULL, TRUE,
                            GOODIX_5E0A_TLS_PARK_HEALTH_TIMEOUT_MS,
                            FALSE, goodix_receive_none, cb_info);
      return;
    }

  if (self->tls_parked)
    {
      /* Ticket 38 fallback: void parked session and run full ladder */
      const char *reason;
      if (self->tls_parked_gen != pre_gen)
        reason = "gen-mismatch";
      else if (!goodix_tls_is_alive (dev))
        reason = "tls-error";
      else
        reason = "expired";
      self->tls_parked = FALSE;
      if (park_suspended)
        {
          self->warm_ok = FALSE;
          self->warm_down_reason = "suspended";
        }
      g_message ("5e0a parked TLS session unhealthy (%s), full re-handshake", reason);
      goodix_shutdown_tls (dev, NULL);
    }

  if (goodix_tls_is_alive (dev))
    {
      /* Ticket 75: alive but unparked — the previous claim completed without
       * parking (FpDevice holds the device open, so no deactivate runs
       * between claims) or an error path left its context behind. Every
       * ladder below ends in goodix_tls_init, which asserts tls_hop == NULL,
       * so shut the orphan down now; warmth still earns the warm ladder. */
      fp_dbg ("5e0a closing orphaned TLS session before new activation");
      goodix_shutdown_tls (dev, NULL);
    }

  /* Ticket 40 warm fast path (branch 2 of 3 — the 38 parked-session check
   * above dominates and runs first because its gate is cheaper; the full
   * ladder below is the default). Cold session but warm device: READ_AND_NOP
   * + FW check + TLS, via the shared SSM with warm_attempted set. */
  if (goodix5e0a_warm_fresh (dev))
    {
      goodix5e0a_log_warm_taken (dev);
      goodix5e0a_start_warm_activation (dev);
      return;
    }

  /* Branch 3: today's full ladder unchanged. Name why warmth didn't apply
   * (TTL expiry invalidates lazily here; a reopened device reads as a cold
   * start — the pre-reopen recency is meaningless on the new boot). */
  {
    const char *reason;
    if (self->warm_ok && self->warm_boot_seq == goodix_boot_seq_get (dev))
      {
        reason = "ttl-expired";
        self->warm_ok = FALSE;
        self->warm_down_reason = "ttl-expired";
      }
    else if (self->warm_ok)
      {
        reason = "cold-start";
        self->warm_ok = FALSE;
        self->warm_down_reason = "cold-start";
      }
    else
      {
        reason = self->warm_down_reason ? self->warm_down_reason : "cold-start";
      }
    self->warm_attempted = FALSE;
    g_message ("5e0a warm expired: reason=%s", reason);
    goodix5e0a_start_full_activation (dev);
  }
}

// ---- ACTIVATE SECTION END ----

// -----------------------------------------------------------------------------

// ---- SCAN SECTION START (Windows-faithful steady-state port) ----

enum goodix5e0a_scan_states {
  SCAN_5E0A_SESSION_AE,
  SCAN_5E0A_SESSION_D6,
  SCAN_5E0A_FDT_DOWN,
  SCAN_5E0A_GET_IMAGE,
  SCAN_5E0A_FDT_UP_1,
  SCAN_5E0A_UP_AE,
  SCAN_5E0A_FDT_UP_2,
  SCAN_5E0A_NUM_STATES,
};

static void
send_cmd_noreply (FpDevice *dev, guint8 cmd, const guint8 *payload, guint16 len,
                  GoodixNoneCallback cb, gpointer user_data)
{
  GoodixCallbackInfo *cb_info = NULL;
  GoodixCmdCallback callback = NULL;

  if (cb)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);
      cb_info->callback = G_CALLBACK (cb);
      cb_info->user_data = user_data;
      callback = goodix_receive_none;
    }

  goodix_send_protocol (dev, cmd, payload, len, NULL, TRUE, GOODIX_TIMEOUT,
                        FALSE, callback, cb_info);
}

static void
send_cmd_reply (FpDevice *dev, guint8 cmd, const guint8 *payload, guint16 len,
                guint timeout_ms, GoodixDefaultCallback cb, gpointer user_data)
{
  GoodixCallbackInfo *cb_info = NULL;
  GoodixCmdCallback callback = NULL;

  if (cb)
    {
      cb_info = g_new0 (GoodixCallbackInfo, 1);
      cb_info->callback = G_CALLBACK (cb);
      cb_info->user_data = user_data;
      callback = goodix_receive_default;
    }

  goodix_send_protocol (dev, cmd, payload, len, NULL, TRUE, timeout_ms,
                        TRUE, callback, cb_info);
}

static gboolean
drop_stale_ssm (FpiDeviceGoodixTls5e0a *self, gpointer ssm, GError *err)
{
  if (self->scan_ssm != (FpiSsm *) ssm)
    {
      if (err)
        g_error_free (err);
      return TRUE;
    }
  return FALSE;
}

static void
goodix5e0a_step_cb (FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  FpiSsm *ssm = user_data;

  if (drop_stale_ssm (self, ssm, error))
    return;

  if (error)
    {
      /* Teardown CANCELLED (goodix_reset_state failing the armed priv
       * waiter synchronously inside deactivate/suspend) must fail fast:
       * swallowing it and calling next_state would resurrect the scan
       * mid-teardown and re-arm priv via send_cmd after the teardown
       * clear. Only non-CANCELLED transients stay tolerant. */
      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      fp_dbg ("5e0a step cb tolerant error: %s", error->message);
      g_error_free (error);
    }
  fpi_ssm_next_state (ssm);
}

static void
goodix5e0a_on_d6_reply (FpDevice *dev, guint8 *data, guint16 len,
                        gpointer ssm, GError *err)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  if (drop_stale_ssm (self, ssm, err))
    return;

  if (err)
    {
      fp_warn ("5e0a session d6 reply error: %s", err->message);
      g_error_free (err);
    }
  else
    {
      fp_dbg ("5e0a session d6 replied successfully (len=%u)", len);
    }
  self->session_started = TRUE;
  if (self->retry_guard)
    fpi_ssm_jump_to_state (ssm, SCAN_5E0A_FDT_UP_1);
  else
    fpi_ssm_next_state (ssm);
}

static void goodix5e0a_on_fdt_down_reply (FpDevice *dev,
                                          guint8   *data,
                                          guint16   len,
                                          gpointer  ssm,
                                          GError   *err);

static void
goodix5e0a_on_down_poll_timeout (FpDevice *dev, gpointer user_data)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  self->down_timeout = NULL;

  FpiSsm *ssm = user_data;
  if (self->scan_ssm != ssm)
    return;
  if (self->scan_timeout_gen != self->scan_gen)
    return;

  send_cmd_reply (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_DOWN,
                  goodix_5e0a_down_s12, sizeof (goodix_5e0a_down_s12),
                  0, goodix5e0a_on_fdt_down_reply, self->scan_ssm);
}

static void
goodix5e0a_on_fdt_down_reply (FpDevice *dev, guint8 *data, guint16 len,
                              gpointer ssm, GError *err)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  if (drop_stale_ssm (self, ssm, err))
    return;

  if (err)
    {
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  if (!data || len == 0)
    {
      /* Transient empties are retried (same 50ms pace + scan_timeout_gen
       * idiom as the no-touch path below), but a device answering empty
       * forever is dead: bound the loop and fail the SSM with a clear
       * error instead of polling until the client gives up. */
      if (++self->down_empty_polls >= GOODIX_5E0A_DOWN_EMPTY_POLL_MAX)
        {
          self->down_empty_polls = 0;
          g_clear_pointer (&self->down_timeout, g_source_destroy);
          fpi_ssm_mark_failed (ssm,
                               g_error_new (G_IO_ERROR,
                                            G_IO_ERROR_INVALID_DATA,
                                            "5e0a FDT DOWN: %u consecutive empty replies, aborting wait for finger",
                                            GOODIX_5E0A_DOWN_EMPTY_POLL_MAX));
          return;
        }
      g_clear_pointer (&self->down_timeout, g_source_destroy);
      self->scan_timeout_gen = self->scan_gen;
      self->down_timeout = fpi_device_add_timeout (dev, 50, goodix5e0a_on_down_poll_timeout,
                                                   ssm, NULL);
      return;
    }
  self->down_empty_polls = 0;

  guint8 status = data[0];

  GString *hex_str = g_string_new ("");
  for (guint16 i = 0; i < len; i++)
    g_string_append_printf (hex_str, "%02x ", data[i]);
  g_message ("5e0a D32 reply: status=0x%02x len=%u bytes=[%s]", status, len, hex_str->str);
  g_string_free (hex_str, TRUE);

  guint32 channel_energy = 0;
  if (len >= 4)
    for (guint16 i = 4; i + 1 < len; i += 2)
      channel_energy += (guint32) data[i] | ((guint32) data[i + 1] << 8);

  /* Gating rule: touch = channel-byte energy (data[2] != 0xff and channel_energy > 0), never byte0 */
  gboolean touch = (len >= 4 && data[2] != 0xff && channel_energy > 0);

  if (touch)
    {
      if (self->down_timeout)
        {
          g_source_destroy (self->down_timeout);
          self->down_timeout = NULL;
        }
      g_message ("5e0a D32 touch confirmed: mask=0x%02x energy=%u",
                 (data && len >= 3) ? data[2] : 0, channel_energy);
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), TRUE);
      fpi_ssm_next_state (ssm);
      return;
    }

  /* No touch (empty air or poor contact): pace re-sampling silently after 50ms */
  if (self->down_timeout)
    {
      g_source_destroy (self->down_timeout);
      self->down_timeout = NULL;
    }
  self->scan_timeout_gen = self->scan_gen;
  self->down_timeout = fpi_device_add_timeout (dev, 50, goodix5e0a_on_down_poll_timeout,
                                               ssm, NULL);
}

static FpImage * process_raw_frame (GoodixTls5xxPix * pix);

static guint32
goodix5e0a_decode_frame (GoodixTls5xxPix *out_row_major, const guint8 *data, guint16 len)
{
  guint32 pixel_idx = 0;

  if (!out_row_major || !data)
    return 0;

  /* A canonical ChicagoH frame is 80 blocks of 132 bytes followed by a
   * four-byte footer. Each block carries 96 packed pixel bytes and 36 zero
   * padding bytes. The 80 active blocks are the natural rows of a 64x80
   * raster; decoding directly from wire blocks avoids an intermediate 7.6KB buffer. */
  for (guint32 block = 0; block < GOODIX_5E0A_FRAME_BLOCKS; block++)
    {
      guint32 src = block * GOODIX_5E0A_BLOCK_BYTES;
      if (src + GOODIX_5E0A_BLOCK_ACTIVE_BYTES > len)
        break;

      const guint8 *blk = data + src;
      for (guint32 i = 0; i < GOODIX_5E0A_BLOCK_ACTIVE_BYTES && pixel_idx + 4 <= GOODIX_5E0A_FRAME_SIZE; i += 6)
        {
          const guint8 *c = blk + i;
          out_row_major[pixel_idx++] = ((c[0] & 0x0f) << 8) | c[1];
          out_row_major[pixel_idx++] = (c[3] << 4) | (c[0] >> 4);
          out_row_major[pixel_idx++] = ((c[5] & 0x0f) << 8) | c[2];
          out_row_major[pixel_idx++] = (c[4] << 4) | (c[5] >> 4);
        }
    }

  return pixel_idx;
}

/* Ticket 39: drop any half-collected burst and zero the per-touch counters.
 * Called at touch start, claim entry, and every teardown path so a stale winner never leaks. */
static void
goodix5e0a_reset_touch_frames (FpiDeviceGoodixTls5e0a *self)
{
  self->frame_count = 0;
  self->best_frame_no = 0;
  self->best_quality = 0;
  self->best_overlap = 0;
  self->best_range = 0;
  self->best_active = 0;
  memset (self->best_pixels, 0, sizeof (self->best_pixels));
  memset (self->latest_norm_pixels, 0, sizeof (self->latest_norm_pixels));
}

static void goodix5e0a_deactivate (FpImageDevice *);

static void
goodix5e0a_retry_enroll (FpDevice *dev, FpDeviceRetry retry)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  fpi_device_enroll_progress (dev, self->enroll_stage, NULL, fpi_device_retry_new (retry));
}

static void
goodix5e0a_set_print_template (FpPrint *print, const guint8 *blob, gsize len)
{
  GVariant *bytes = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, blob, len, 1);
  GVariant *data = g_variant_new ("(s@ay)", GOODIX_5E0A_PRINT_FORMAT, bytes);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  g_object_set (print, "fpi-data", data, NULL);
}

static gconstpointer
goodix5e0a_get_print_template (FpPrint *print, GVariant **out_var, gsize *out_len)
{
  if (out_len)
    *out_len = 0;
  g_return_val_if_fail (out_var != NULL, NULL);
  *out_var = NULL;

  if (!print)
    return NULL;

  GVariant *v = NULL;
  g_object_get (print, "fpi-data", &v, NULL);
  if (!v)
    return NULL;
  if (!g_variant_is_of_type (v, G_VARIANT_TYPE ("(say)")))
    {
      g_variant_unref (v);
      return NULL;
    }
  const gchar *format = NULL;
  GVariant *bytes = NULL;
  g_variant_get (v, "(&s@ay)", &format, &bytes);
  gboolean compatible = g_str_equal (format, GOODIX_5E0A_PRINT_FORMAT);
  g_variant_unref (v);
  if (!compatible)
    {
      g_variant_unref (bytes);
      return NULL;
    }
  gsize len = 0;
  gconstpointer d = g_variant_get_fixed_array (bytes, &len, 1);
  if (!d || len == 0)
    {
      g_variant_unref (bytes);
      return NULL;
    }
  *out_var = bytes;
  if (out_len)
    *out_len = len;
  return d;
}

static void
goodix5e0a_deliver_frame (FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  FpiDeviceAction action = fpi_device_get_current_action (dev);

  if (action == FPI_DEVICE_ACTION_VERIFY || self->is_verify)
    {
      if (self->tmpl_blob == NULL || self->tmpl_len == 0)
        {
          fp_err ("5e0a verify: no stored template available");
          fpi_device_verify_complete (dev, fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
        }
      else if (self->best_active < 64)
        {
          fp_dbg ("5e0a no usable frame, reporting no-match");
          fpi_device_verify_report (dev, FPI_MATCH_FAIL, NULL, NULL);
          fpi_device_verify_complete (dev, NULL);
        }
      else
        {
          int match_pts = 0;
          int is_match = goodix_milan_verify_image (self->best_pixels,
                                                   GOODIX_5E0A_WIDTH,
                                                   GOODIX_5E0A_HEIGHT,
                                                   self->tmpl_blob,
                                                   self->tmpl_len,
                                                   &match_pts);
          fp_dbg ("5e0a Milan verify: match=%d pts=%d", is_match, match_pts);
          if (is_match)
            fpi_device_verify_report (dev, FPI_MATCH_SUCCESS, NULL, NULL);
          else
            fpi_device_verify_report (dev, FPI_MATCH_FAIL, NULL, NULL);
          fpi_device_verify_complete (dev, NULL);
        }
      /* Note: Do not deactivate here. In verify mode, the scan SSM completes
       * cleanly via fpi_ssm_mark_completed in on_read_img, and fprintd will
       * close/park the device via dev_close. */
    }
  else if (action == FPI_DEVICE_ACTION_IDENTIFY || self->is_identify)
    {
      /* Ticket 77: gallery (1:N) identify. Same single-touch burst flow as
       * verify; CANCELLED never re-issues (report+complete only). NULL print
       * is accepted upstream (synaptics/elanmoc NO_MATCH precedent). */
      if (self->best_active < 64)
        {
          fp_dbg ("5e0a no usable frame, reporting identify no-match");
          fpi_device_identify_report (dev, NULL, NULL, NULL);
          fpi_device_identify_complete (dev, NULL);
        }
      else
        {
          GPtrArray *prints = NULL;
          fpi_device_get_identify_data (dev, &prints);
          if (!prints || prints->len == 0)
            {
              fp_dbg ("5e0a identify: empty gallery, reporting no-match");
              fpi_device_identify_report (dev, NULL, NULL, NULL);
              fpi_device_identify_complete (dev, NULL);
            }
          else
            {
              guint n = prints->len;
              g_autoptr(GPtrArray) held = g_ptr_array_new_with_free_func ((GDestroyNotify) g_variant_unref);
              g_autofree const uint8_t **blobs = g_new0 (const uint8_t *, n);
              g_autofree size_t *lens = g_new0 (size_t, n);
              g_autofree FpPrint **owners = g_new0 (FpPrint *, n);
              guint m = 0;
              for (guint i = 0; i < n; i++)
                {
                  FpPrint *p = g_ptr_array_index (prints, i);
                  GVariant *v = NULL;
                  gsize dl = 0;
                  gconstpointer d = goodix5e0a_get_print_template (p, &v, &dl);
                  if (!d)
                    continue;
                  g_ptr_array_add (held, v);
                  blobs[m] = d;
                  lens[m] = dl;
                  owners[m] = p;
                  m++;
                }
              int match_idx = -1, match_pts = 0, is_match = 0;
              if (m > 0)
                is_match = goodix_milan_identify_image (self->best_pixels,
                                                        GOODIX_5E0A_WIDTH,
                                                        GOODIX_5E0A_HEIGHT,
                                                        blobs, lens, m,
                                                        &match_idx, &match_pts);
              fp_dbg ("5e0a Milan identify: match=%d idx=%d pts=%d (gallery=%u usable=%u)",
                      is_match, match_idx, match_pts, n, m);
              if (is_match && match_idx >= 0 && (guint) match_idx < m)
                fpi_device_identify_report (dev, owners[match_idx], NULL, NULL);
              else
                fpi_device_identify_report (dev, NULL, NULL, NULL);
              fpi_device_identify_complete (dev, NULL);
            }
        }
      /* Same no-deactivate rule as verify: scan SSM completes in
       * on_read_img; fprintd closes/parks via dev_close. */
    }
  else if (action == FPI_DEVICE_ACTION_ENROLL)
    {
      if (!self->milan_enrol_ctx)
        {
          fp_err ("5e0a enroll: missing Milan context");
          fpi_device_enroll_complete (dev, NULL, fpi_device_error_new (FP_DEVICE_ERROR_GENERAL));
          return;
        }

      int enrolled_count = 0;
      int progress_pct = 0;
      int add_res = goodix_milan_enroll_add_image (self->milan_enrol_ctx,
                                                   self->best_pixels,
                                                   GOODIX_5E0A_WIDTH,
                                                   GOODIX_5E0A_HEIGHT,
                                                   &enrolled_count,
                                                   &progress_pct);
      fp_dbg ("5e0a Milan enrollAddImage: res=%d enrolled=%d progress=%d%% (stage %u/%d)",
              add_res, enrolled_count, progress_pct,
              self->enroll_stage + 1, FP_DEVICE_GET_CLASS (dev)->nr_enroll_stages);

      if (add_res != 0)
        {
          fp_dbg ("5e0a enrollment touch rejected by Milan engine (res=%d)", add_res);
          goodix5e0a_reset_touch_frames (self);
          fpi_device_enroll_progress (dev, self->enroll_stage, NULL,
                                      fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
          return;
        }

      self->enroll_stage++;
      fpi_device_enroll_progress (dev, self->enroll_stage, NULL, NULL);

      if (self->enroll_stage >= FP_DEVICE_GET_CLASS (dev)->nr_enroll_stages)
        {
          uint8_t *packed_blob = NULL;
          size_t packed_len = 0;
          int commit_res = goodix_milan_enroll_commit (self->milan_enrol_ctx,
                                                       &packed_blob,
                                                       &packed_len);
          if (commit_res == 0 && packed_blob && packed_len > 0)
            {
              FpPrint *print = NULL;
              fpi_device_get_enroll_data (dev, &print);
              goodix5e0a_set_print_template (print, packed_blob, packed_len);
              free (packed_blob);
              fp_dbg ("5e0a Milan enrollment committed successfully! (template size: %zu bytes)",
                      packed_len);
              fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
            }
          else
            {
              free (packed_blob);
              fp_err ("5e0a Milan enroll commit failed: err=%d", commit_res);
              fpi_device_enroll_complete (dev, NULL,
                                          fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                                    "Milan templatePack failed"));
            }

          g_clear_pointer (&self->milan_enrol_ctx, goodix_milan_enroll_finish);
        }
    }

}

#define fpi_image_device_retry_scan(idev, retry) \
  goodix5e0a_retry_enroll (FP_DEVICE (idev), (retry))

#define fpi_image_device_image_captured(idev) \
  goodix5e0a_deliver_frame (FP_DEVICE (idev))

/* Hand the burst winner to the deliver tail (logs the single
 * best-frame journal line). Callers guarantee at least one banked frame. */
static void
goodix5e0a_claim_best_frame (FpiDeviceGoodixTls5e0a *self)
{
  g_message ("5e0a best frame %u/%u: quality=%u overlap=%u range=%u score-proxy=%u (submitting)",
             self->best_frame_no, (guint) GOODIX_5E0A_FRAMES_PER_TOUCH,
             self->best_quality, self->best_overlap, self->best_range,
             (self->best_quality << 8) | self->best_overlap);
}

/* Best-of-N judging for one burst frame directly on 64x80 normalized pixels.
 * Ranks by Milan native quality first, tie-breaking on dynamic contrast range
 * and active touch area. Re-issues GET_IMAGE on the same SSM while fewer than
 * GOODIX_5E0A_FRAMES_PER_TOUCH frames are banked. */
static gboolean
goodix5e0a_keep_best_frame (FpDevice *dev, gpointer ssm,
                            guint16 declen, guint active, guint range);

static void
goodix5e0a_dump_debug_frame (const GoodixTls5xxPix *raw, const guint8 *norm)
{
  const char *dir = g_getenv ("GOODIX_5E0A_DUMP_DIR");
  static guint seq = 0;

  if (!dir || !*dir || g_mkdir_with_parents (dir, 0755) != 0)
    return;
  seq++;
  for (int pass = 0; pass < 2; pass++)
    {
      const void *buf = pass ? (const void *) norm : (const void *) raw;
      if (!buf) continue;
      char path[512];
      g_snprintf (path, sizeof (path), "%s/frame_%04u_%s.pgm", dir, seq, pass ? "norm" : "raw");
      FILE *f = fopen (path, "w");
      if (!f) continue;
      fprintf (f, "P2\n%d %d\n%u\n", GOODIX_5E0A_WIDTH, GOODIX_5E0A_HEIGHT, pass ? 255 : 4095);
      for (guint i = 0; i < GOODIX_5E0A_FRAME_SIZE; i++)
        fprintf (f, "%u%c", pass ? ((const guint8 *) buf)[i] : ((const guint16 *) buf)[i],
                 (i % 16 == 15) ? '\n' : ' ');
      fprintf (f, "\n");
      fclose (f);
    }
}

static void
goodix5e0a_on_read_img (FpDevice *dev, guint8 *data, guint16 len,
                        gpointer ssm, GError *err)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  if (self->scan_ssm != ssm)
    {
      fp_dbg ("5e0a stale on_read_img callback dropped (ssm mismatch)");
      if (err)
        g_error_free (err);
      return;
    }

  FpiDeviceAction action = fpi_device_get_current_action (dev);
  g_autofree GoodixTls5xxPix *raw_frame = NULL;

  /* Ticket 39: a mid-burst read error (finger lifted between frames) falls
   * back to the best frame collected so far. With zero frames the failure
   * is reported exactly as today. */
  if (err)
    {
      if (g_error_matches (err, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          /* CANCELLED must never fall back or re-issue; fail SSM immediately. */
          fpi_ssm_mark_failed (ssm, err);
          return;
        }
      if (self->best_frame_no > 0)
        {
          g_error_free (err);
          goto choose_best;
        }
      fpi_ssm_mark_failed (ssm, err);
      return;
    }

  /* Ticket 39: a short mid-burst read (lift between frames) submits the
   * best frame so far instead of decoding a runt. */
  if (self->best_frame_no > 0
      && (data == NULL || len < GOODIX_5E0A_FRAME_WIRE_BYTES))
    {
      g_message ("5e0a frame %u/%u: short declen=%u, submitting best-so-far %u/%u",
                 self->frame_count + 1, (guint) GOODIX_5E0A_FRAMES_PER_TOUCH,
                 len, self->best_frame_no,
                 (guint) GOODIX_5E0A_FRAMES_PER_TOUCH);
      goto choose_best;
    }

  goodix5e0a_last_declen = len;
  g_message ("5e0a scan_on_read_img: declen=%u", len);

  if (data && len >= 16)
    fp_dbg ("5e0a raw first 16 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);

  raw_frame = g_new0 (GoodixTls5xxPix, GOODIX_5E0A_FRAME_SIZE);
  guint32 decoded_pixels = goodix5e0a_decode_frame (raw_frame, data, len);
  goodix5e0a_normalize_raw_frame (raw_frame, self->latest_norm_pixels, NULL, NULL);

  guint total_nonzero = 0;
  guint16 raw_min = 65535, raw_max = 0;
  /* Ticket 39: contact-pixel (v > 30, the same definition process_raw_frame
   * uses) active/range for the per-frame journal line. */
  guint frame_active = 0;
  guint16 frame_min = 65535, frame_max = 0;
  for (guint32 i = 0; i < GOODIX_5E0A_FRAME_SIZE; i++)
    {
      guint16 px = raw_frame[i];
      if (px > 0)
        {
          total_nonzero++;
          if (px < raw_min) raw_min = px;
          if (px > raw_max) raw_max = px;
        }
      if (px > 30)
        {
          frame_active++;
          if (px < frame_min) frame_min = px;
          if (px > frame_max) frame_max = px;
        }
    }
  guint frame_range = (frame_min != 65535 && frame_max > frame_min)
                      ? (guint) (frame_max - frame_min) : 0;
  fp_dbg ("5e0a wire layout: decoded_px=%u blocks=%u active_bytes=%u footer_bytes=%u",
          decoded_pixels, MIN ((guint32) len / GOODIX_5E0A_BLOCK_BYTES, (guint32) GOODIX_5E0A_FRAME_BLOCKS),
          GOODIX_5E0A_BLOCK_ACTIVE_BYTES, len >= GOODIX_5E0A_FRAME_WIRE_BYTES ? 4 : 0);
  g_message ("5e0a row-major frame: active_px=%u nonzero=%u min=%u max=%u geometry=%dx%d (WxH)",
             decoded_pixels, total_nonzero, raw_min == 65535 ? 0 : raw_min, raw_max,
             GOODIX_5E0A_WIDTH, GOODIX_5E0A_HEIGHT);
  goodix5e0a_dump_debug_frame (raw_frame, self->latest_norm_pixels);

  /* Best-of-N frame banking: all touches (including enrollment) bank
   * GOODIX_5E0A_FRAMES_PER_TOUCH frames and select the winner; the
   * SSM does not advance between frames and only the winner reaches the
   * deliver tail below. Evaluates 64x80 normalized pixels directly without
   * intermediate FpImage allocations. */
  if (goodix5e0a_keep_best_frame (dev, ssm, len, frame_active, frame_range))
    return;

choose_best:
  if (action == FPI_DEVICE_ACTION_ENROLL)
    {
      if (self->best_active < 64 || self->best_frame_no == 0)
        {
          g_message ("5e0a enrollment touch rejected: active=%u (press firmer)",
                     self->best_active);
          goodix5e0a_reset_touch_frames (self);
          goodix5e0a_retry_enroll (dev, FP_DEVICE_RETRY_TOO_SHORT);
          fpi_ssm_next_state (ssm);
          return;
        }
      g_message ("5e0a enrollment quality check: active=%u range=%u quality=%u overlap=%u",
                 self->best_active, self->best_range, self->best_quality, self->best_overlap);
      goodix5e0a_claim_best_frame (self);
    }
  else
    {
      if (self->best_frame_no > 0)
        goodix5e0a_claim_best_frame (self);
      else
        {
          fp_dbg ("5e0a no usable frame captured");
          goto deliver;
        }
    }

  /* image_captured first: it consumes best_pixels and bumps enroll_stage,
   * so the SSM check below sees the post-increment stage (12th completes). */
deliver:
  fpi_image_device_image_captured (dev);

  if (self->scan_ssm != ssm)
    return;

  if (action != FPI_DEVICE_ACTION_ENROLL || self->enroll_stage >= FP_DEVICE_GET_CLASS (dev)->nr_enroll_stages)
    {
      self->scan_ssm = NULL;
      self->retry_guard = TRUE;
      self->retry_guard_mono = g_get_monotonic_time ();
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
      fpi_ssm_mark_completed (ssm);
    }
  else
    {
      goodix5e0a_reset_touch_frames (self); /* ticket 101: fresh burst per enroll touch */
      fpi_ssm_next_state (ssm);
    }
}

/* Ticket 39 + 76: best-of-N judging for one burst frame. Evaluates the candidate directly from
 * the 64x80 normalized raster using Milan frame quality scoring with contrast
 * dynamic range and active touch area tiebreakers, eliminating intermediate
 * FpImage allocations. Re-issues GET_IMAGE on the same SSM while fewer than
 * GOODIX_5E0A_FRAMES_PER_TOUCH frames are banked. */
static gboolean
goodix5e0a_keep_best_frame (FpDevice *dev, gpointer ssm,
                            guint16 declen, guint active, guint range)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  guint quality = 0, overlap = 0;
  guint quality_proxy = goodix_milan_frame_quality (self->latest_norm_pixels,
                                                    GOODIX_5E0A_WIDTH,
                                                    GOODIX_5E0A_HEIGHT,
                                                    &quality, &overlap);

  self->frame_count++;
  g_message ("5e0a frame %u/%u: declen=%u active=%u range=%u quality=%u overlap=%u score-proxy=%u",
             self->frame_count, (guint) GOODIX_5E0A_FRAMES_PER_TOUCH,
             declen, active, range, quality, overlap, quality_proxy);

  guint best_proxy = (self->best_quality << 8) | self->best_overlap;
  gboolean better = FALSE;

  if (self->best_frame_no == 0)
    better = TRUE;
  else if (quality_proxy > best_proxy)
    better = TRUE;
  else if (quality_proxy == best_proxy)
    {
      if (range > self->best_range)
        better = TRUE;
      else if (range == self->best_range && active > self->best_active)
        better = TRUE;
    }

  if (better)
    {
      self->best_frame_no = self->frame_count;
      self->best_quality = quality;
      self->best_overlap = overlap;
      self->best_range = range;
      self->best_active = active;
      memcpy (self->best_pixels, self->latest_norm_pixels, GOODIX_5E0A_FRAME_SIZE);
    }

  /* Ticket 84: Optimistic Verify Fast-Path (Sub-50ms Post-Touch Unlock Latency).
   * During non-enroll actions (verify or identify), if frame 1 has strong contact
   * (active >= 1500 and range >= 500) and matches immediately, deliver it at once
   * instead of waiting for the remaining 3 burst frames. */
  FpiDeviceAction action = fpi_device_get_current_action (dev);
  if ((action == FPI_DEVICE_ACTION_VERIFY || self->is_verify ||
       action == FPI_DEVICE_ACTION_IDENTIFY || self->is_identify) &&
      self->frame_count == 1 && active >= 1500 && range >= 500)
    {
      if (self->is_verify || action == FPI_DEVICE_ACTION_VERIFY)
        {
          if (self->tmpl_blob != NULL && self->tmpl_len > 0)
            {
              int match_pts = 0;
              goodix_milan_verify_image (self->best_pixels,
                                         GOODIX_5E0A_WIDTH,
                                         GOODIX_5E0A_HEIGHT,
                                         self->tmpl_blob,
                                         self->tmpl_len,
                                         &match_pts);
              if (match_pts > 0)
                {
                  g_message ("5e0a optimistic fast-path match on frame 1: pts=%d, skipping remaining burst",
                             match_pts);
                  return FALSE;
                }
            }
        }
      else if (self->is_identify || action == FPI_DEVICE_ACTION_IDENTIFY)
        {
          GPtrArray *prints = NULL;
          fpi_device_get_identify_data (dev, &prints);
          if (prints && prints->len > 0)
            {
              guint n = prints->len;
              g_autoptr(GPtrArray) held = g_ptr_array_new_with_free_func ((GDestroyNotify) g_variant_unref);
              g_autofree const uint8_t **blobs = g_new0 (const uint8_t *, n);
              g_autofree size_t *lens = g_new0 (size_t, n);
              guint m = 0;
              for (guint i = 0; i < n; i++)
                {
                  FpPrint *p = g_ptr_array_index (prints, i);
                  GVariant *v = NULL;
                  gsize dl = 0;
                  gconstpointer d = goodix5e0a_get_print_template (p, &v, &dl);
                  if (!d)
                    continue;
                  g_ptr_array_add (held, v);
                  blobs[m] = d;
                  lens[m] = dl;
                  m++;
                }
              if (m > 0)
                {
                  int matched_idx = -1, match_pts = 0;
                  goodix_milan_identify_image (self->best_pixels,
                                               GOODIX_5E0A_WIDTH,
                                               GOODIX_5E0A_HEIGHT,
                                               blobs, lens, m,
                                               &matched_idx, &match_pts);
                  if (matched_idx >= 0 && match_pts > 0)
                    {
                      g_message ("5e0a optimistic fast-path identify match on frame 1: idx=%d pts=%d, skipping remaining burst",
                                 matched_idx, match_pts);
                      return FALSE;
                    }
                }
            }
        }
    }

  if (self->frame_count < GOODIX_5E0A_FRAMES_PER_TOUCH)
    {
      goodix_tls_read_image (dev, goodix5e0a_on_read_img, ssm);
      return TRUE;
    }
  return FALSE;
}

static void
goodix5e0a_on_fdt_up_reply (FpDevice *dev, guint8 *data, guint16 len,
                            gpointer ssm, GError *err)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  if (drop_stale_ssm (self, ssm, err))
    return;

  if (err)
    {
      if (g_error_matches (err, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          /* Deactivate tore the scan down; never re-issue on an orphaned SSM. */
          fpi_ssm_mark_failed (ssm, err);
          return;
        }
      fp_dbg ("5e0a D34 reply (tolerant): %s", err->message);
      if (self->retry_guard && self->scan_ssm == ssm)
        {
          /* Hardware-proven 2026-09-09: a 0x34 timeout means the finger is
           * STILL down (no release event in 2000ms) — not a release.
           * Treating it as release re-armed FDT_DOWN onto the held finger
           * and burned the retry. Keep the guard and re-issue FDT_UP; the
           * retry claim parks here until a genuine release reply arrives. */
          if (g_get_monotonic_time () - self->retry_guard_mono > 30 * G_USEC_PER_SEC)
            {
              /* Stop-loss: every live client (PAM ~20s, D-Bus ~25s) times
               * out first, so reaching here means the client is gone but
               * never cancelled. Fail loudly instead of re-issuing forever;
               * err passes to mark_failed (no free). */
              self->retry_guard = FALSE;
              fp_dbg ("5e0a retry guard: orphaned hold past 30s, failing claim");
              fpi_ssm_mark_failed (ssm, err);
              return;
            }
          g_error_free (err);
          fp_dbg ("5e0a retry guard: finger still present, re-issuing FDT UP");
          send_cmd_reply (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_UP,
                          goodix_5e0a_up_u01, sizeof (goodix_5e0a_up_u01),
                          GOODIX_5E0A_FDT_UP_GUARD_TIMEOUT_MS, goodix5e0a_on_fdt_up_reply, ssm);
          return;
        }
      g_error_free (err);
    }
  else
    {
      g_message ("5e0a D34 finger release reply: len=%u", len);
    }

  if (self->retry_guard)
    {
      self->retry_guard = FALSE;
      fp_dbg ("5e0a retry guard: release ok, arming FDT DOWN");
      fpi_ssm_jump_to_state (ssm, SCAN_5E0A_FDT_DOWN);
      return;
    }

  /* Verify AND identify are single-touch: one burst, then report+complete.
   * Only enrollment loops for the next touch. */
  if (!self->is_verify && !self->is_identify && self->enroll_stage < FP_DEVICE_GET_CLASS (dev)->nr_enroll_stages)
    {
      fp_dbg ("5e0a enrollment stage %u waiting for next touch, arming FDT DOWN", self->enroll_stage);
      fpi_ssm_jump_to_state (ssm, SCAN_5E0A_FDT_DOWN);
      return;
    }

  /* Clear scan SSM before notifying libfprint */
  self->scan_ssm = NULL;
  fpi_ssm_next_state (ssm);
  fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);
}

static void
goodix5e0a_scan_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case SCAN_5E0A_SESSION_AE:
      send_cmd_noreply (dev, GOODIX_CMD_QUERY_MCU_STATE,
                        goodix_5e0a_query_ae, sizeof (goodix_5e0a_query_ae),
                        goodix5e0a_step_cb, ssm);
      break;

    case SCAN_5E0A_SESSION_D6:
      if (self->session_started)
        {
          if (self->retry_guard)
            fpi_ssm_jump_to_state (ssm, SCAN_5E0A_FDT_UP_1);
          else
            fpi_ssm_jump_to_state (ssm, SCAN_5E0A_FDT_DOWN);
          return;
        }
      send_cmd_reply (dev, GOODIX_CMD_SESSION_D6,
                      goodix_5e0a_session_d6, sizeof (goodix_5e0a_session_d6),
                      GOODIX_TIMEOUT, goodix5e0a_on_d6_reply, ssm);
      break;

    case SCAN_5E0A_FDT_DOWN:
      self->down_empty_polls = 0;
      send_cmd_reply (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_DOWN,
                      goodix_5e0a_down_s12, sizeof (goodix_5e0a_down_s12),
                      0, goodix5e0a_on_fdt_down_reply, ssm);
      break;

    case SCAN_5E0A_GET_IMAGE:
      goodix_tls_read_image (dev, goodix5e0a_on_read_img, ssm);
      break;

    case SCAN_5E0A_FDT_UP_1:
      send_cmd_noreply (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_UP,
                        goodix_5e0a_up_u01, sizeof (goodix_5e0a_up_u01),
                        goodix5e0a_step_cb, ssm);
      break;

    case SCAN_5E0A_UP_AE:
      send_cmd_noreply (dev, GOODIX_CMD_QUERY_MCU_STATE,
                        goodix_5e0a_query_ae, sizeof (goodix_5e0a_query_ae),
                        goodix5e0a_step_cb, ssm);
      break;

    case SCAN_5E0A_FDT_UP_2:
      send_cmd_reply (dev, GOODIX_CMD_MCU_SWITCH_TO_FDT_UP,
                      goodix_5e0a_up_u01, sizeof (goodix_5e0a_up_u01),
                      self->retry_guard ? GOODIX_5E0A_FDT_UP_GUARD_TIMEOUT_MS : GOODIX_5E0A_FDT_UP_TIMEOUT_MS, goodix5e0a_on_fdt_up_reply, ssm);
      break;
    }
}

static void
goodix5e0a_scan_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  self->scan_gen++;
  self->scan_ssm = NULL;
  /* Ticket 39: never carry a burst winner past SSM completion. */
  goodix5e0a_reset_touch_frames (self);
  self->down_empty_polls = 0;
  if (self->down_timeout)
    {
      g_source_destroy (self->down_timeout);
      self->down_timeout = NULL;
    }

  if (error)
    {
      /* Ticket 42: scan error voids reset-skipping. */
      goodix_session_mark_dirty (dev);
      self->warm_ok = FALSE;
      self->retry_guard = FALSE;
      fp_err ("5e0a failed to scan: %s (code: %d)", error->message, error->code);
      fpi_image_device_session_error (FP_IMAGE_DEVICE (dev), error);
      return;
    }
  fp_dbg ("5e0a finished scan stage");
}

static void
goodix5e0a_scan_start (FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  if (self->scan_ssm != NULL)
    {
      fp_dbg ("5e0a scan SSM already active, ignoring start request");
      return;
    }

  /* Ticket 47: Expire retry guard if older than 2000ms */
  if (self->retry_guard)
    {
      gint64 delta_us = g_get_monotonic_time () - self->retry_guard_mono;
      if (delta_us > 2 * G_USEC_PER_SEC)
        {
          fp_dbg ("5e0a retry guard expired (delta=%ld ms), clearing", (long) (delta_us / 1000));
          self->retry_guard = FALSE;
        }
      else
        {
          fp_dbg ("5e0a retry guard active (delta=%ld ms): awaiting finger release", (long) (delta_us / 1000));
        }
    }

  /* Ticket 39: each touch starts with an empty burst. */
  goodix5e0a_reset_touch_frames (self);
  self->down_empty_polls = 0;

  self->scan_gen++;
  self->scan_ssm = fpi_ssm_new (dev, goodix5e0a_scan_run_state, SCAN_5E0A_NUM_STATES);
  fpi_ssm_start (self->scan_ssm, goodix5e0a_scan_complete);
}

static void
goodix5e0a_deactivate (FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE (img_dev);
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  /* Ticket 39: never carry a burst winner past deactivation. */
  goodix5e0a_reset_touch_frames (self);

  /* Ticket 34: orphan any in-flight TLS activation; its completion will drop. */
  goodix_activation_gen_bump (dev);

  self->session_started = FALSE;
  self->scan_gen++;
  self->down_empty_polls = 0;
  if (self->down_timeout)
    {
      g_source_destroy (self->down_timeout);
      self->down_timeout = NULL;
    }

  /* Ticket 46: a deactivate arriving with a scan SSM in-flight (notably
   * FDT_DOWN wait) leaves the MCU in FDT mode with dangling ACKs that
   * poison the next parked reuse (Invalid ACK 0xae, timeout 0x96/0x32).
   * Pin park eligibility to idle deactivation; a non-idle teardown falls
   * through to the destroy branch for a clean bring-up. Capture and free
   * BEFORE goodix_reset_state: the reset fails the armed priv waiter with
   * CANCELLED synchronously, and a still-current waiter would complete
   * (clearing scan_ssm, re-arming priv, reporting session_error). Freed
   * first, the SSM is abandoned with no completion and its waiter drops
   * as stale inside the reset — park sees the true state, single report. */
  gboolean scan_was_active = (self->scan_ssm != NULL);
  if (self->scan_ssm != NULL)
    {
      fpi_ssm_free (self->scan_ssm);
      self->scan_ssm = NULL;
    }

  goodix_reset_state (dev);

  /* Ticket 38 park branch: the negotiated TLS session (and chip-enabled
   * state) survives across claims while its context is alive — stop the
   * read loop only, stamp the park, and let the next activate health-check
   * it. Destroy branch is full shutdown; only a successful chip enable may
   * park, because failure funnels can leave a host TLS context allocated.
   * Ticket 46 narrows the gate to idle deactivation (scan_ssm == NULL). */
  if (scan_was_active && goodix_tls_is_alive (dev) && self->warm_ok)
    fp_dbg ("5e0a park invalidated: scan SSM in-flight at deactivate, clean bring-up");
  if (goodix_tls_is_alive (dev) && self->warm_ok && !scan_was_active)
    {
      goodix_stop_read_loop (dev);
      self->tls_parked = TRUE;
      self->tls_parked_at = g_get_monotonic_time ();
      self->tls_parked_boot = goodix_get_boottime_us ();
      self->tls_parked_gen = goodix_activation_gen_get (dev);
      goodix_session_mark_clean (dev);
      fp_dbg ("5e0a parking live TLS session (gen=%u)", self->tls_parked_gen);
      fpi_image_device_deactivate_complete (img_dev, NULL);
      return;
    }

  self->tls_parked = FALSE;
  self->retry_guard = FALSE;
  self->retry_guard_mono = 0;
  goodix_session_mark_dirty (dev);
  GError *tls_err = NULL;
  goodix_shutdown_tls (dev, &tls_err);
  goodix_stop_read_loop (dev);
  fpi_image_device_deactivate_complete (img_dev, tls_err);
}

// ---- SCAN SECTION END ----

static void
fpi_device_goodixtls5e0a_init (FpiDeviceGoodixTls5e0a *self)
{
  self->session_started = FALSE;
  self->scan_ssm = NULL;
  self->scan_gen = 0;
  self->down_timeout = NULL;
  self->down_empty_polls = 0;
  self->tls_parked = FALSE;
  self->tls_parked_at = 0;
  self->tls_parked_gen = 0;
  self->tls_parked_boot = 0;
  self->warm_ok = FALSE;
  self->last_clean_mono = 0;
  self->last_clean_boot = 0;
  self->warm_boot_seq = 0;
  self->warm_down_reason = "cold-start";
  self->warm_attempted = FALSE;
  self->warm_retried = FALSE;
  self->frame_count = 0;
  self->best_frame_no = 0;
  self->best_quality = 0;
  self->best_overlap = 0;
  self->best_range = 0;
  self->best_active = 0;
  self->retry_guard = FALSE;
  self->retry_guard_mono = 0;
  self->is_verify = FALSE;
  self->is_identify = FALSE;
  self->enroll_stage = 0;
  self->milan_enrol_ctx = NULL;
  self->tmpl_blob = NULL;
  self->tmpl_len = 0;
}

static double
goodix5e0a_axis_correlation (const GoodixTls5xxPix *pix,
                             int                    width,
                             int                    height,
                             int                    dx,
                             int                    dy)
{
  double sum_a = 0.0, sum_b = 0.0;
  guint count = 0;

  int start_y = MAX (0, -dy);
  int start_x = MAX (0, -dx);

  for (int y = start_y; y + dy < height && y < height; y++)
    for (int x = start_x; x + dx < width && x < width; x++)
      {
        sum_a += pix[y * width + x];
        sum_b += pix[(y + dy) * width + x + dx];
        count++;
      }

  if (count == 0)
    return 0.0;

  double mean_a = sum_a / count;
  double mean_b = sum_b / count;
  double covariance = 0.0, variance_a = 0.0, variance_b = 0.0;

  for (int y = start_y; y + dy < height && y < height; y++)
    for (int x = start_x; x + dx < width && x < width; x++)
      {
        double a = pix[y * width + x] - mean_a;
        double b = pix[(y + dy) * width + x + dx] - mean_b;
        covariance += a * b;
        variance_a += a * a;
        variance_b += b * b;
      }

  double denominator = sqrt (variance_a * variance_b);
  return denominator > 1e-6 ? covariance / denominator : 0.0;
}

static FpImage *
process_raw_frame (GoodixTls5xxPix * pix)
{
  const int W = GOODIX_5E0A_WIDTH;
  const int H = GOODIX_5E0A_HEIGHT;
  const int dst_w = GOODIX_5E0A_SCALED_WIDTH;
  const int dst_h = GOODIX_5E0A_SCALED_HEIGHT;

  guint16 min_v = 65535, max_v = 0;
  guint active = 0;

  for (int r = 0; r < H; ++r)
    {
      for (int c = 0; c < W; ++c)
        {
          guint16 v = pix[r * W + c];
          if (v > 30)
            {
              active++;
              if (v < min_v)
                min_v = v;
              if (v > max_v)
                max_v = v;
            }
        }
    }

  if (min_v == 65535)
    min_v = 0;
  guint16 range = (max_v > min_v) ? (max_v - min_v) : 1;

  double horizontal_corr = goodix5e0a_axis_correlation (pix, W, H, 1, 0);
  double vertical_corr = goodix5e0a_axis_correlation (pix, W, H, 0, 1);
  double horizontal_lag4_corr = goodix5e0a_axis_correlation (pix, W, H, 4, 0);

  GString *active_cols = g_string_new ("");
  for (int c = 0; c < W; ++c)
    {
      guint32 c_sum = 0;
      for (int r = 0; r < H; ++r)
        c_sum += pix[r * W + c];
      if (c_sum > 0)
        g_string_append_printf (active_cols, "%d ", c);
    }
  if (active_cols->len > 0)
    g_message ("5e0a active cols: %s", active_cols->str);
  else
    g_message ("5e0a active cols: NONE (all 0)");
  g_string_free (active_cols, TRUE);

  /* Guaranteed journald output without needing debug flags */
  g_message ("5e0a frame stats: active=%u, min_v=%u, max_v=%u, range=%u, declen=%u, h_corr=%.3f, v_corr=%.3f, h_lag4_corr=%.3f (native %dx%d WxH)",
             active, min_v, max_v, range, goodix5e0a_last_declen,
             horizontal_corr, vertical_corr, horizontal_lag4_corr, W, H);

  if (active < 64 || range < 8)
    return NULL;

  float residual_min = 0.0f, residual_max = 0.0f;
  g_autofree guint8 *normalized = g_new (guint8, GOODIX_5E0A_FRAME_SIZE);
  if (!goodix5e0a_normalize_raw_frame (pix, normalized, &residual_min, &residual_max))
    return NULL;

  float residual_range = residual_max - residual_min;
  g_message ("5e0a local contrast: min=%.2f max=%.2f range=%.2f bandpass=%dx%d-%dx%d target_rms=%.1f",
             residual_min, residual_max, residual_range,
             2 * GOODIX_5E0A_BANDPASS_SMOOTH_RADIUS + 1, 2 * GOODIX_5E0A_BANDPASS_SMOOTH_RADIUS + 1,
             2 * GOODIX_5E0A_BANDPASS_BACKGROUND_RADIUS + 1, 2 * GOODIX_5E0A_BANDPASS_BACKGROUND_RADIUS + 1,
             GOODIX_5E0A_BANDPASS_TARGET_RMS);

  /* Create the scaled 128x160 image directly via bilinear upscaling.
   * Use FPI_IMAGE_COLORS_INVERTED for capacitive ridges (high ADC = black).
   * Omit FPI_IMAGE_PARTIAL so the interpreter retains edge points. */
  FpImage *img = fp_image_new (dst_w, dst_h);
  img->flags = FPI_IMAGE_COLORS_INVERTED;
  img->ppmm = GOODIX_5E0A_PPMM;

  for (int y = 0; y < dst_h; y++)
    {
      float src_y = (y + 0.5f) * 0.5f - 0.5f;
      if (src_y < 0.0f)
        src_y = 0.0f;
      int y0 = (int) src_y;
      int y1 = (y0 + 1 < H) ? y0 + 1 : y0;
      float y_frac = src_y - (float) y0;

      for (int x = 0; x < dst_w; x++)
        {
          float src_x = (x + 0.5f) * 0.5f - 0.5f;
          if (src_x < 0.0f)
            src_x = 0.0f;
          int x0 = (int) src_x;
          int x1 = (x0 + 1 < W) ? x0 + 1 : x0;
          float x_frac = src_x - (float) x0;

          float top = (float) normalized[y0 * W + x0] * (1.0f - x_frac) + (float) normalized[y0 * W + x1] * x_frac;
          float bot = (float) normalized[y1 * W + x0] * (1.0f - x_frac) + (float) normalized[y1 * W + x1] * x_frac;
          float val = top * (1.0f - y_frac) + bot * y_frac;
          int norm = (int) roundf (val);
          img->data[y * dst_w + x] = (guint8) CLAMP (norm, 0, 255);
        }
    }

  g_message ("5e0a scaled image: %dx%d (WxH) flags=0x%02x active=%u range=%u ppmm=%.3f",
             img->width, img->height, img->flags, active, range, img->ppmm);
  return img;
}

void
goodix5e0a_suspend (FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  FpiDeviceAction action = fpi_device_get_current_action (dev);

  fp_dbg ("5e0a suspend requested during action: %d", action);

  /* Ticket 34 staleness guard: orphan any in-flight TLS handshake/activation */
  goodix_activation_gen_bump (dev);

  /* Ticket 38: sleep safety is non-negotiable — never carry a parked
   * session across suspend; the unconditional shutdown below stands. */
  self->tls_parked = FALSE;
  goodix_session_mark_dirty (dev);
  /* Ticket 40: sleep safety extends to warmth — suspend always resets warm
   * state, unconditionally and non-negotiably. */
  self->warm_ok = FALSE;
  self->warm_down_reason = "suspended";
  self->warm_attempted = FALSE;
  /* Ticket 39: never carry a burst winner across suspend. */
  goodix5e0a_reset_touch_frames (self);
  self->retry_guard = FALSE;
  self->retry_guard_mono = 0;
  self->session_started = FALSE;
  self->is_verify = self->is_identify = FALSE;
  g_clear_pointer (&self->tmpl_blob, g_free);
  self->tmpl_len = 0;
  g_clear_pointer (&self->milan_enrol_ctx, goodix_milan_enroll_finish);
  self->scan_gen++;
  self->down_empty_polls = 0;
  g_clear_pointer (&self->down_timeout, g_source_destroy);

  /* Abandon the scan SSM BEFORE failing the armed priv waiter (same
   * ordering as deactivate): the reset below delivers CANCELLED
   * synchronously, and a still-current SSM would complete with
   * session_error alongside suspend_complete. Freed first, the waiter
   * drops as stale and the teardown reports exactly once. */
  if (self->scan_ssm != NULL)
    {
      fpi_ssm_free (self->scan_ssm);
      self->scan_ssm = NULL;
    }

  /* Reset in-flight protocol commands and timeout */
  goodix_reset_state (dev);

  /* Terminate background read loop and cancel transfers */
  goodix_stop_read_loop (dev);

  /* Tear down TLS context */
  goodix_shutdown_tls (dev, NULL);

  /* Complete suspend with NOT_SUPPORTED to trigger clean core deactivation
   * of the interactive task, releasing PAM claims before sleep. */
  fpi_device_suspend_complete (dev, fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
}

void
goodix5e0a_resume (FpDevice *dev)
{
  fp_dbg ("5e0a resume requested");

  /* Device state was cleaned up during suspend; complete resume immediately.
   * Subsequent user claims will trigger clean open/activate and hardware re-priming. */
  fpi_device_resume_complete (dev, NULL);
}

static guint8 goodix_5e0a_psk_override[32];

static void
goodix_5e0a_load_psk_override (FpDevice *dev)
{
  FpiDeviceGoodixTls5xxClass *xx_cls = FPI_DEVICE_GOODIXTLS5XX_GET_CLASS (dev);
  const char *path = "/etc/libfprint/goodix-5e0a.psk";
  g_autofree gchar *content = NULL;
  gsize length = 0;
  GError *error = NULL;

  if (!g_file_get_contents (path, &content, &length, &error))
    {
      if (!g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
        fp_warn ("5e0a: Failed to read %s: %s", path, error->message);
      g_clear_error (&error);
      return;
    }

  gchar *str = g_strstrip (content);
  if (strlen (str) != 64)
    {
      fp_warn ("5e0a: %s must contain exactly 64 hex characters (found %zu)", path, strlen (str));
      return;
    }

  for (size_t i = 0; i < 32; i++)
    {
      char hex_byte[3] = { str[i * 2], str[i * 2 + 1], '\0' };
      char *endptr = NULL;
      goodix_5e0a_psk_override[i] = (guint8) strtoul (hex_byte, &endptr, 16);
      if (endptr && *endptr != '\0')
        {
          fp_warn ("5e0a: %s contains non-hex byte at index %zu", path, i);
          return;
        }
    }

  xx_cls->psk = goodix_5e0a_psk_override;
  xx_cls->psk_len = sizeof (goodix_5e0a_psk_override);
  fp_info ("5e0a: Loaded sensor key from %s", path);
}

static void
dev_open (FpDevice *dev)
{
  GError *error = NULL;

  goodix_5e0a_load_psk_override (dev);

  if (!goodix_dev_init (dev, &error))
    {
      fpi_device_open_complete (dev, error);
      return;
    }

  if (!goodix_milan_init (NULL))
    fp_warn ("Goodix Milan engine init returned FALSE; will retry on demand");

  fpi_device_open_complete (dev, NULL);
}

static void
dev_close (FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  GError *error = NULL;

  self->is_verify = FALSE;
  self->is_identify = FALSE;
  g_clear_pointer (&self->milan_enrol_ctx, goodix_milan_enroll_finish);
  g_clear_pointer (&self->tmpl_blob, g_free);
  self->tmpl_len = 0;

  /* Ticket 87: FpDevice close has no automatic image-device deactivate.
   * Park only an already-idle, healthy session before transport deinit;
   * never free an active scan first and accidentally make it parkable.
   * This branch cannot report a deactivate error: it takes the idle park. */
  if (self->scan_ssm == NULL && self->warm_ok && goodix_tls_is_alive (dev))
    goodix5e0a_deactivate ((FpImageDevice *) dev);

  if (self->scan_ssm != NULL)
    {
      fpi_ssm_free (self->scan_ssm);
      self->scan_ssm = NULL;
    }

  if (!goodix_dev_deinit (dev, &error))
    {
      fpi_device_close_complete (dev, error);
      return;
    }

  fpi_device_close_complete (dev, NULL);
}

static void
dev_enroll (FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  self->is_verify = FALSE;
  self->is_identify = FALSE;
  self->enroll_stage = 0;
  g_clear_pointer (&self->milan_enrol_ctx, goodix_milan_enroll_finish);

  self->milan_enrol_ctx = goodix_milan_enroll_start (NULL);
  if (!self->milan_enrol_ctx)
    {
      fpi_device_enroll_complete (dev, NULL,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                            "Failed to start Milan enrollment context"));
      return;
    }

  dev_activate ((FpImageDevice *) dev);
}

static void
dev_verify (FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  FpPrint *print = NULL;

  self->is_verify = TRUE;
  self->is_identify = FALSE;
  g_clear_pointer (&self->tmpl_blob, g_free);
  self->tmpl_len = 0;

  fpi_device_get_verify_data (dev, &print);
  g_autoptr(GVariant) fp_data = NULL;
  gsize data_len = 0;
  gconstpointer data = goodix5e0a_get_print_template (print, &fp_data, &data_len);
  if (!data)
    {
      fpi_device_verify_complete (dev,
                                  fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                            "Fingerprint data is incompatible or invalid; enroll again"));
      return;
    }

  self->tmpl_blob = g_memdup2 (data, data_len);
  self->tmpl_len = data_len;

  dev_activate ((FpImageDevice *) dev);
}

static void
dev_identify (FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  /* Ticket 77: gallery claim. The gallery itself lives in libfprint core
   * for the action duration; fetch it at deliver time, so nothing is
   * cached here. Drop any stale single-template blob (unused on this
   * path) and clear the verify flag so the deliver branch is unambiguous. */
  self->is_verify = FALSE;
  self->is_identify = TRUE;
  g_clear_pointer (&self->tmpl_blob, g_free);
  self->tmpl_len = 0;

  dev_activate ((FpImageDevice *) dev);
}

static void
dev_cancel (FpDevice *dev)
{
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  fp_dbg ("5e0a dev_cancel requested");
  self->is_verify = FALSE;
  self->is_identify = FALSE;
  g_clear_pointer (&self->tmpl_blob, g_free);
  self->tmpl_len = 0;
  g_clear_pointer (&self->milan_enrol_ctx, goodix_milan_enroll_finish);

  goodix5e0a_deactivate ((FpImageDevice *) dev);
  fpi_device_action_error (dev, g_error_new (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Operation cancelled"));
}

static void
fpi_device_goodixtls5e0a_class_init (FpiDeviceGoodixTls5e0aClass * class)
{
  FpiDeviceGoodixTlsClass * gx_class = FPI_DEVICE_GOODIXTLS_CLASS (class);
  FpDeviceClass * dev_class = FP_DEVICE_CLASS (class);
  FpiDeviceGoodixTls5xxClass * xx_cls = FPI_DEVICE_GOODIXTLS5XX_CLASS (class);

  xx_cls->process_raw_frame = process_raw_frame;
  xx_cls->scan_height = GOODIX_5E0A_HEIGHT;
  xx_cls->scan_width = GOODIX_5E0A_WIDTH;
  xx_cls->psk = goodix_5e0a_psk;
  xx_cls->psk_flags = GOODIX_5E0A_PSK_FLAGS;
  xx_cls->psk_len = sizeof (goodix_5e0a_psk);
  xx_cls->firmware_version = GOODIX_5E0A_FIRMWARE_VERSION;
  xx_cls->reset_number = GOODIX_5E0A_RESET_NUMBER;
  xx_cls->has_calibration = FALSE;

  gx_class->interface = GOODIX_5E0A_INTERFACE;
  gx_class->ep_in = GOODIX_5E0A_EP_IN;
  gx_class->ep_out = GOODIX_5E0A_EP_OUT;

  dev_class->id = "goodixtls5e0a";
  dev_class->full_name = "Goodix TLS Fingerprint Sensor 5e0a";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = goodix_5e0a_id_table;
  dev_class->nr_enroll_stages = 12;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  /* Disable thermal watchdog */
  dev_class->temp_hot_seconds = -1;
  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify;
  dev_class->identify = dev_identify;
  dev_class->cancel = dev_cancel;
  dev_class->suspend = goodix5e0a_suspend;
  dev_class->resume = goodix5e0a_resume;

  fpi_device_class_auto_initialize_features (dev_class);
}
