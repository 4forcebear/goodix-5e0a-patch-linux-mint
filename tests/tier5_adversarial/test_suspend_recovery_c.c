/* Offline lifecycle coverage. Compile the current driver, not a copied model.
 * Transport and core completion hooks are replaced; libfprint's SSM and the
 * Goodix base generation/clean-state helpers remain real. No USB calls occur.
 * The driver TU is selected at build time: dev builds default to the repo
 * layout, the Nix lane overrides GOODIX_5E0A_C_INCLUDE to the patched
 * libfprint tree copy (kept identical by the patch-sync test).
 */
#ifndef GOODIX_5E0A_C_INCLUDE
#define GOODIX_5E0A_C_INCLUDE "../../libfprint-driver/goodix5e0a.c"
#endif
#define goodix_tls_is_alive mock_tls_is_alive
#define goodix_tls_init mock_tls_init
#define goodix_shutdown_tls mock_shutdown_tls
#define goodix_start_read_loop mock_start_read_loop
#define goodix_stop_read_loop mock_stop_read_loop
#define goodix_send_nop mock_send_nop
#define goodix_send_query_firmware_version mock_send_query_firmware_version
#define goodix_send_preset_psk_read_5e0a mock_send_preset_psk_read_5e0a
#define goodix_send_upload_config_mcu mock_send_upload_config_mcu
#define goodix_send_enable_chip mock_send_enable_chip
#define goodix_send_protocol mock_send_protocol
#define fpi_device_suspend_complete mock_suspend_complete
#define fpi_device_resume_complete mock_resume_complete
#define fpi_device_action_error mock_action_error
/* This driver derives from FpDevice, despite its legacy image-device casts. */
#include "fp-image-device.h"
#undef FP_IMAGE_DEVICE
#define FP_IMAGE_DEVICE(dev) ((FpImageDevice *) (dev))
#include GOODIX_5E0A_C_INCLUDE

static gboolean tls_alive, reading;
static guint tls_inits, shutdowns, probes, configs, enables, suspends, resumes, errors;
static guint scan_commands;
static GoodixCallbackInfo *scan_command;
static GoodixNoneCallback tls_cb, enable_cb;
static gpointer tls_data, enable_data;
static GoodixCallbackInfo *probe;

/* These mocks retain completions so tests can deliver an orphan after teardown. */
gboolean mock_tls_is_alive (FpDevice *dev) { return tls_alive; }
void mock_tls_init (FpDevice *dev, GoodixNoneCallback cb, gpointer data)
{
  g_assert_false (tls_alive);
  tls_alive = TRUE;
  tls_inits++;
  tls_cb = cb;
  tls_data = data;
}
gboolean mock_shutdown_tls (FpDevice *dev, GError **error)
{
  shutdowns++;
  tls_alive = FALSE;
  return TRUE;
}
void mock_start_read_loop (FpDevice *dev) { reading = TRUE; }
void mock_stop_read_loop (FpDevice *dev) { reading = FALSE; }
void mock_send_nop (FpDevice *dev, GoodixNoneCallback cb, gpointer data)
{ cb (dev, data, NULL); }
void mock_send_query_firmware_version (FpDevice *dev, GoodixFirmwareVersionCallback cb, gpointer data)
{ cb (dev, GOODIX_5E0A_FIRMWARE_VERSION, data, NULL); }
void mock_send_preset_psk_read_5e0a (FpDevice *dev, guint32 flags, guint32 len,
                                    guint32 offset, GoodixPresetPskReadCallback cb, gpointer data)
{ cb (dev, TRUE, flags, NULL, 0, data, NULL); }
void mock_send_upload_config_mcu (FpDevice *dev, guint8 *config, guint16 len,
                                  GDestroyNotify free_func, GoodixSuccessCallback cb, gpointer data)
{
  configs++;
  cb (dev, TRUE, data, NULL);
}
void mock_send_enable_chip (FpDevice *dev, gboolean enabled, GoodixNoneCallback cb, gpointer data)
{
  enables++;
  enable_cb = cb;
  enable_data = data;
}
void mock_send_protocol (FpDevice *dev, guint8 cmd, const guint8 *payload, guint16 len,
                         GDestroyNotify free_func, gboolean checksum, guint timeout,
                         gboolean reply, GoodixCmdCallback cb, gpointer data)
{
  g_assert_cmpuint (cmd, ==, GOODIX_CMD_QUERY_MCU_STATE);
  if (FPI_DEVICE_GOODIXTLS5E0A (dev)->scan_ssm)
    {
      g_assert_null (scan_command);
      scan_command = data;
      scan_commands++;
    }
  else
    {
      g_assert_null (probe);
      probe = data;
      probes++;
    }
}
void mock_suspend_complete (FpDevice *dev, GError *error)
{
  g_assert_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
  g_error_free (error);
  suspends++;
}
void mock_resume_complete (FpDevice *dev, GError *error)
{ g_assert_no_error (error); resumes++; }
void mock_action_error (FpDevice *dev, GError *error)
{ g_assert_error (error, G_IO_ERROR, G_IO_ERROR_CANCELLED); g_error_free (error); errors++; }

static FpDevice *new_device (void)
{
  tls_alive = reading = FALSE;
  tls_inits = shutdowns = probes = configs = enables = suspends = resumes = errors = 0;
  scan_commands = 0;
  g_clear_pointer (&probe, g_free);
  g_clear_pointer (&scan_command, g_free);
  FpDeviceClass *klass = g_type_class_ref (fpi_device_goodixtls5e0a_get_type ());
  klass->type = FP_DEVICE_TYPE_VIRTUAL;
  FpDevice *dev = g_object_new (fpi_device_goodixtls5e0a_get_type (), NULL);
  g_type_class_unref (klass);
  return dev;
}

static void test_park_suspend_resume (void)
{
  g_autoptr(FpDevice) dev = new_device ();
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  tls_alive = TRUE;
  reading = TRUE;
  self->warm_ok = TRUE;
  goodix5e0a_deactivate ((FpImageDevice *) dev);
  g_assert_true (self->tls_parked);
  g_assert_true (tls_alive);
  g_assert_false (reading);
  g_assert_true (goodix_session_is_clean (dev));
  guint parked_gen = goodix_activation_gen_get (dev);

  goodix5e0a_suspend (dev);
  g_assert_false (self->tls_parked);
  g_assert_false (self->warm_ok);
  g_assert_false (tls_alive);
  g_assert_false (reading);
  g_assert_false (goodix_session_is_clean (dev));
  g_assert_cmpuint (goodix_activation_gen_get (dev), >, parked_gen);
  g_assert_cmpuint (suspends, ==, 1);
  goodix5e0a_resume (dev);
  g_assert_cmpuint (resumes, ==, 1);
  g_assert_false (tls_alive);

  dev_activate ((FpImageDevice *) dev);
  g_assert_cmpuint (tls_inits, ==, 1);
  g_assert_cmpuint (probes, ==, 0);
  g_assert_false (self->warm_attempted);
  g_assert_true (reading);
  tls_cb (dev, tls_data, NULL);
  g_assert_cmpuint (configs, ==, 1);
  g_assert_cmpuint (enables, ==, 1);
  enable_cb (dev, enable_data, NULL);
  g_assert_nonnull (self->scan_ssm);
  g_assert_cmpuint (scan_commands, ==, 1);
  goodix5e0a_suspend (dev);
  g_clear_pointer (&scan_command, g_free);
}

static void test_late_tls_after_cancel (void)
{
  g_autoptr(FpDevice) dev = new_device ();
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  dev_activate ((FpImageDevice *) dev);
  GoodixNoneCallback old_cb = tls_cb;
  gpointer old_data = tls_data;
  dev_cancel (dev);
  g_assert_cmpuint (errors, ==, 1);
  g_assert_false (tls_alive);
  goodix5e0a_suspend (dev);
  goodix5e0a_resume (dev);
  dev_activate ((FpImageDevice *) dev);
  g_assert_cmpuint (tls_inits, ==, 2);
  old_cb (dev, old_data, NULL);
  old_cb (dev, old_data, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "late TLS"));
  g_assert_cmpuint (configs, ==, 0);
  g_assert_cmpuint (enables, ==, 0);
  g_assert_cmpuint (errors, ==, 1);
  g_assert_null (self->scan_ssm);
  tls_cb (dev, tls_data, NULL);
  g_assert_cmpuint (configs, ==, 1);
  goodix5e0a_suspend (dev);
}

static void test_late_probe_after_suspend (void)
{
  g_autoptr(FpDevice) dev = new_device ();
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  tls_alive = self->warm_ok = TRUE;
  goodix5e0a_deactivate ((FpImageDevice *) dev);
  dev_activate ((FpImageDevice *) dev);
  g_assert_cmpuint (probes, ==, 1);
  g_assert_nonnull (probe);
  goodix5e0a_suspend (dev);
  goodix5e0a_resume (dev);
  dev_activate ((FpImageDevice *) dev);
  ((GoodixNoneCallback) probe->callback) (dev, probe->user_data, NULL);
  ((GoodixNoneCallback) probe->callback) (dev, probe->user_data,
      g_error_new_literal (G_IO_ERROR, G_IO_ERROR_TIMED_OUT, "late probe"));
  g_assert_cmpuint (tls_inits, ==, 1);
  g_assert_cmpuint (enables, ==, 0);
  g_assert_cmpuint (errors, ==, 0);
  g_assert_true (tls_alive);
  goodix5e0a_suspend (dev);
  g_clear_pointer (&probe, g_free);
}

static void test_active_scan_cancel (void)
{
  g_autoptr(FpDevice) dev = new_device ();
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  dev_activate ((FpImageDevice *) dev);
  tls_cb (dev, tls_data, NULL);
  enable_cb (dev, enable_data, NULL);
  FpiSsm *old_ssm = self->scan_ssm;
  g_assert_nonnull (old_ssm);
  self->down_timeout = g_timeout_source_new (60000);
  GSource *timeout = g_source_ref (self->down_timeout);
  g_source_unref (self->down_timeout);
  self->frame_count = self->best_frame_no = 2;
  self->retry_guard = self->session_started = TRUE;
  guint old_scan_gen = self->scan_gen;
  dev_cancel (dev);
  g_assert_null (self->scan_ssm);
  g_assert_null (self->down_timeout);
  g_assert_true (g_source_is_destroyed (timeout));
  g_source_unref (timeout);
  g_assert_false (tls_alive);
  g_assert_false (self->tls_parked);
  g_assert_false (self->session_started);
  g_assert_false (self->retry_guard);
  g_assert_cmpuint (self->frame_count, ==, 0);
  g_assert_cmpuint (self->best_frame_no, ==, 0);
  g_assert_cmpuint (self->scan_gen, >, old_scan_gen);
  /* The timer guard only compares the orphan pointer, never dereferences it. */
  goodix5e0a_on_down_poll_timeout (dev, old_ssm);
  g_assert_cmpuint (scan_commands, ==, 1);
  g_assert_cmpuint (errors, ==, 1);
  goodix5e0a_suspend (dev);
  goodix5e0a_resume (dev);
  dev_activate ((FpImageDevice *) dev);
  g_assert_cmpuint (tls_inits, ==, 2);
  goodix5e0a_suspend (dev);
  g_clear_pointer (&scan_command, g_free);
}

/* Exercise the public libfprint dispatch too. Virtual type keeps the wakeup
 * path off USB/sysfs. Documents the observed dispatch: idle suspend/resume
 * never reaches the driver hooks, and a stale parked session can only be
 * reused after its health probe succeeds.
 */
static void test_public_idle_suspend (void)
{
  g_autoptr(FpDevice) dev = new_device ();
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  tls_alive = self->warm_ok = TRUE;
  goodix5e0a_deactivate ((FpImageDevice *) dev);
  g_assert_true (self->tls_parked);
  g_autoptr(GError) error = NULL;
  g_assert_true (fp_device_suspend_sync (dev, NULL, &error));
  g_assert_no_error (error);
  g_assert_true (fp_device_resume_sync (dev, NULL, &error));
  g_assert_no_error (error);
  /* Observed dispatch (reproducer test_idle_suspend_dispatch_c.c): with no
   * interactive action libfprint completes suspend/resume itself and never
   * calls the driver hooks. Parked TLS therefore survives the cycle. What
   * still protects the claim is the park health probe: dev_activate may not
   * send enable_chip, config, or a full-ladder TLS init while a suspended
   * park is only "candidate fresh". */
  g_assert_cmpuint (suspends, ==, 0);
  g_assert_cmpuint (shutdowns, ==, 0);
  g_assert_true (self->tls_parked);
  g_assert_true (tls_alive);
  dev_activate ((FpImageDevice *) dev);
  g_assert_cmpuint (probes, ==, 1);
  g_assert_cmpuint (configs, ==, 0);
  g_assert_cmpuint (enables, ==, 0);
  g_assert_false (self->tls_parked);
  goodix5e0a_suspend (dev);
}

/* Test the real normalizer with an affine ramp and an analytic impulse
 * response. These synthetic pixels are not fingerprint accuracy fixtures. */
static void test_frame_normalization (void)
{
  GoodixTls5xxPix raw[64 * 80] = {0};
  guint8 normalized[64 * 80];
  float low, high;

  g_assert_false (goodix5e0a_normalize_raw_frame (raw, normalized, NULL, NULL));
  for (guint i = 0; i < 63; i++)
    raw[i] = 1000;
  g_assert_false (goodix5e0a_normalize_raw_frame (raw, normalized, NULL, NULL));
  raw[63] = 1000;
  g_assert_true (goodix5e0a_normalize_raw_frame (raw, normalized, NULL, NULL));

  for (int y = 0; y < 80; y++)
    for (int x = 0; x < 64; x++)
      raw[y * 64 + x] = 1000 + 6 * x + 12 * y;
  g_assert_true (goodix5e0a_normalize_raw_frame (raw, normalized, &low, &high));
  g_assert_cmpfloat_with_epsilon (low, -37.5f, .001f);
  g_assert_cmpfloat_with_epsilon (high, 37.5f, .001f);
  g_assert_cmpuint (normalized[40 * 64 + 32], ==, 128);
  g_assert_cmpuint (normalized[0], ==, 0);
  g_assert_cmpuint (normalized[64 * 80 - 1], ==, 255);

  for (guint i = 0; i < G_N_ELEMENTS (raw); i++)
    raw[i] = 1000;
  g_assert_false (goodix5e0a_normalize_raw_frame (raw, normalized, &low, &high));
  g_assert_cmpfloat (low, ==, 0.0f);
  g_assert_cmpfloat (high, ==, 0.0f);
  for (int delta = -900; delta <= 900; delta += 1800)
    {
      raw[40 * 64 + 32] = 1000 + delta;
      g_assert_true (goodix5e0a_normalize_raw_frame (raw, normalized, NULL, NULL));
      g_assert_cmpuint (normalized[40 * 64 + 32], ==, delta < 0 ? 0 : 255);
      /* Separable 3x3 and 11x11 box kernels: the impulse spreads over
       * nine pixels, then its background spans 13x13. Away from frame
       * edges the exact response is delta/9 * (small - overlap/121). */
      double response[64 * 80], sum_sq = 0;
      for (int y = 0; y < 80; y++)
        for (int x = 0; x < 64; x++)
          {
            int dx = abs (x - 32), dy = abs (y - 40);
            int nx = CLAMP (7 - dx, 0, 3), ny = CLAMP (7 - dy, 0, 3);
            double value = delta / 9.0 * ((dx <= 1 && dy <= 1) - nx * ny / 121.0);
            response[y * 64 + x] = value;
            sum_sq += value * value;
          }
      double rms = sqrt (sum_sq / (64 * 80));
      for (guint i = 0; i < G_N_ELEMENTS (raw); i++)
        {
          int expected = CLAMP ((int) round (128 + response[i] * 80 / rms), 0, 255);
          g_assert_cmpint (abs ((int) normalized[i] - expected), <=, 1);
        }
      g_assert_cmpuint (normalized[0], ==, 128);
    }
}

static void test_print_processing_format (void)
{
  g_autoptr(FpDevice) dev = new_device ();
  g_autoptr(FpPrint) print = fp_print_new (dev);
  const guint8 payload[] = {1, 4, 9, 16};
  g_autoptr(GVariant) held = NULL;
  gsize len = 99;
  goodix5e0a_set_print_template (print, payload, sizeof (payload));
  const guint8 *bytes = goodix5e0a_get_print_template (print, &held, &len);
  g_assert_cmpmem (bytes, len, payload, sizeof (payload));
  g_clear_pointer (&held, g_variant_unref);

  g_autofree guchar *serialized = NULL;
  gsize serialized_len = 0;
  g_autoptr(GError) error = NULL;
  g_assert_true (fp_print_serialize (print, &serialized, &serialized_len, &error));
  g_assert_no_error (error);
  g_autoptr(FpPrint) restored = fp_print_deserialize (serialized, serialized_len, &error);
  g_assert_no_error (error);
  g_assert_nonnull (restored);
  bytes = goodix5e0a_get_print_template (restored, &held, &len);
  g_assert_cmpmem (bytes, len, payload, sizeof (payload));
  g_clear_pointer (&held, g_variant_unref);

  /* Untagged old prints, a different processing tag, malformed types and
   * empty payloads must never reach Milan's template unpacker. */
  GVariant *invalid[] = {
    g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, payload, sizeof (payload), 1),
    g_variant_new ("(s@ay)", "other-processing", g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, payload, sizeof (payload), 1)),
    g_variant_new_string ("not a print"),
    g_variant_new ("(s@ay)", GOODIX_5E0A_PRINT_FORMAT, g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, NULL, 0, 1)),
  };
  for (guint i = 0; i < G_N_ELEMENTS (invalid); i++)
    {
      g_object_set (print, "fpi-data", invalid[i], NULL);
      len = 99;
      g_assert_null (goodix5e0a_get_print_template (print, &held, &len));
      g_assert_null (held);
      g_assert_cmpuint (len, ==, 0);
    }
}

static guint probe_handler_calls, probe_complete_calls;
static GQuark probe_complete_domain;
static gint probe_complete_code;

static void probe_handler (FpiSsm *ssm, FpDevice *dev)
{
  probe_handler_calls++;
}

static void probe_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  probe_complete_calls++;
  if (error)
    {
      probe_complete_domain = error->domain;
      probe_complete_code = error->code;
      g_error_free (error);
    }
  else
    {
      probe_complete_domain = 0;
      probe_complete_code = -1;
    }
}

/* Real-priv teardown: this harness mocks send_protocol, so priv is never
 * armed and goodix_reset_state is a no-op in the cases above. Arm a real
 * priv waiter with goodix_read_tls (no USB needed) whose completion is a
 * live scan callback, then tear down mid-command. A correct teardown
 * abandons the SSM first: park is ineligible and exactly one completion
 * (deactivate_complete / suspend_complete) is reported, never a
 * session_error alongside it. */
static void test_deactivate_mid_command_real_priv (void)
{
  g_autoptr(FpDevice) dev = new_device ();
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  dev_activate ((FpImageDevice *) dev);
  tls_cb (dev, tls_data, NULL);
  enable_cb (dev, enable_data, NULL);
  g_assert_nonnull (self->scan_ssm);
  g_assert_true (tls_alive);
  g_assert_true (self->warm_ok);
  reading = TRUE;

  /* FDT_DOWN wait armed at the priv layer with the live scan SSM. */
  goodix_read_tls (dev, goodix5e0a_on_fdt_down_reply, self->scan_ssm);
  goodix5e0a_deactivate ((FpImageDevice *) dev);
  g_assert_null (self->scan_ssm);
  g_assert_false (self->tls_parked);
  g_assert_false (reading);
  g_assert_false (goodix_session_is_clean (dev));
  g_assert_cmpuint (shutdowns, ==, 1);
  g_assert_cmpuint (errors, ==, 0);
}

/* Same armed-priv setup through suspend: one suspend_complete, no error. */
static void test_suspend_mid_command_real_priv (void)
{
  g_autoptr(FpDevice) dev = new_device ();
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);
  dev_activate ((FpImageDevice *) dev);
  tls_cb (dev, tls_data, NULL);
  enable_cb (dev, enable_data, NULL);
  g_assert_nonnull (self->scan_ssm);

  goodix_read_tls (dev, goodix5e0a_on_fdt_down_reply, self->scan_ssm);
  goodix5e0a_suspend (dev);
  g_assert_null (self->scan_ssm);
  g_assert_false (self->tls_parked);
  g_assert_cmpuint (suspends, ==, 1);
  g_assert_cmpuint (errors, ==, 0);
  goodix5e0a_resume (dev);
  g_assert_cmpuint (resumes, ==, 1);
}

/* step_cb on teardown CANCELLED must fail the SSM, never advance it;
 * non-CANCELLED transients stay tolerant and advance. */
static void test_step_cb_cancelled_fails_fast (void)
{
  g_autoptr(FpDevice) dev = new_device ();
  FpiDeviceGoodixTls5e0a *self = FPI_DEVICE_GOODIXTLS5E0A (dev);

  probe_handler_calls = probe_complete_calls = 0;
  FpiSsm *probe = fpi_ssm_new (dev, probe_handler, 3);
  fpi_ssm_start (probe, probe_complete);
  g_assert_cmpuint (probe_handler_calls, ==, 1);
  self->scan_ssm = probe;
  goodix5e0a_step_cb (dev, probe,
                      g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                           "Command cancelled by state reset"));
  g_assert_cmpuint (probe_handler_calls, ==, 1);
  g_assert_cmpuint (probe_complete_calls, ==, 1);
  g_assert_cmpuint (probe_complete_domain, ==, G_IO_ERROR);
  g_assert_cmpint (probe_complete_code, ==, G_IO_ERROR_CANCELLED);
  self->scan_ssm = NULL; /* mark_failed auto-freed the SSM */

  probe_handler_calls = probe_complete_calls = 0;
  probe = fpi_ssm_new (dev, probe_handler, 3);
  fpi_ssm_start (probe, probe_complete);
  self->scan_ssm = probe;
  goodix5e0a_step_cb (dev, probe,
                      g_error_new_literal (G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                                           "transient timeout"));
  g_assert_cmpuint (probe_handler_calls, ==, 2);
  g_assert_cmpuint (probe_complete_calls, ==, 0);
  fpi_ssm_free (probe);
  self->scan_ssm = NULL;
}

int main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/goodix/lifecycle/park-suspend-resume", test_park_suspend_resume);
  g_test_add_func ("/goodix/lifecycle/late-tls-after-cancel", test_late_tls_after_cancel);
  g_test_add_func ("/goodix/lifecycle/late-probe-after-suspend", test_late_probe_after_suspend);
  g_test_add_func ("/goodix/lifecycle/active-scan-cancel", test_active_scan_cancel);
  g_test_add_func ("/goodix/lifecycle/public-idle-suspend", test_public_idle_suspend);
  g_test_add_func ("/goodix/frame/normalization", test_frame_normalization);
  g_test_add_func ("/goodix/lifecycle/deactivate-mid-command-real-priv", test_deactivate_mid_command_real_priv);
  g_test_add_func ("/goodix/lifecycle/suspend-mid-command-real-priv", test_suspend_mid_command_real_priv);
  g_test_add_func ("/goodix/lifecycle/step-cb-cancelled-fails-fast", test_step_cb_cancelled_fails_fast);
  g_test_add_func ("/goodix/prints/processing-format", test_print_processing_format);
  return g_test_run ();
}
