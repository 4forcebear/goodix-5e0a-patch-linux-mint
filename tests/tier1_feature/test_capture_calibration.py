"""Execute the real OTP callback and image-command path with synthetic OTP.

Only SSM/USB delivery is stubbed; calibration, GObject ownership and the
production callback/command functions run as compiled C. No biometric fixture.
"""
import pathlib
import shlex
import shutil
import subprocess
import tempfile
import unittest

from tests.repo_paths import repo


def function(source, signature):
    start = source.index(signature)
    return source[start:source.index("\n}", start) + 2]


class TestCaptureCalibration(unittest.TestCase):
    def test_otp_capture_handoff_and_failed_refresh(self):
        if not shutil.which("cc") or not shutil.which("pkg-config"):
            self.skipTest("requires a C compiler and GLib development headers")
        driver = pathlib.Path(repo("libfprint-driver"))
        otp_callback = function((driver / "goodix5e0a.c").read_text(),
                                "static void\non_device_otp (")
        image_command = function((driver / "goodix.c").read_text(),
                                 "void\ngoodix_send_mcu_get_image (")
        harness = r'''
#include <gio/gio.h>
#include <string.h>
typedef GObject FpDevice;
typedef struct { guint16 vid, pid; guint64 driver_data; } FpIdEntry;
#include "goodix5e0a.h"
#include "goodix5e0a_calibration.h"
typedef struct {
  guint8 calibrated_config[256], calibrated_down[35], calibrated_up[35];
} FpiDeviceGoodixTls5e0a;
static FpiDeviceGoodixTls5e0a device_state;
#define FPI_DEVICE_GOODIXTLS5E0A(dev) (&device_state)
#define FP_DEVICE_ERROR_DATA_INVALID G_IO_ERROR_INVALID_DATA
#define fpi_device_error_new_msg(code, msg) g_error_new_literal(G_IO_ERROR, code, msg)
static int advanced, failed, sent, callback_errors;
static guint8 wire[10];
static guint16 wire_length;
static void fpi_ssm_mark_failed(gpointer ssm, GError *error) {
  failed++; g_error_free(error);
}
static void fpi_ssm_next_state(gpointer ssm) { advanced++; }
typedef void (*GoodixImageCallback)(FpDevice *, guint8 *, guint16, gpointer, GError *);
typedef struct { GCallback callback; gpointer user_data; } GoodixCallbackInfo;
typedef struct { guint8 unused_flags; } GoodixDefault;
static const char *fp_device_get_driver(FpDevice *dev) { return "goodixtls5e0a"; }
static void record_payload(const guint8 *payload, guint16 len) {
  g_assert_cmpuint(len, ==, sizeof wire);
  memcpy(wire, payload, len); wire_length = len; sent++;
}
#define goodix_send_protocol(dev, cmd, payload, len, ...) record_payload(payload, len)
static void image_error(FpDevice *dev, guint8 *data, guint16 len,
                        gpointer user_data, GError *error) {
  g_assert_nonnull(error); g_assert_null(data); callback_errors++; g_error_free(error);
}
'''
        harness += "\n" + otp_callback + "\n" + image_command + r'''
static void make_otp(guint8 otp[64], guint8 dac) {
  memset(otp, 0, 64);
  otp[42] = otp[45] = 0x90; otp[43] = (guint8)~otp[42];
  for (int i = 0; i < 4; i++) otp[46+i] = otp[50+i] = dac+i;
  otp[22] = goodix5e0a_otp_crc(otp+46, 4);
  otp[62] = goodix5e0a_otp_crc(otp+50, 4);
  guint8 cp[15], ft[19], mt[27];
  memcpy(cp, otp, 11); memcpy(cp+11, otp+36, 4);
  memcpy(ft, otp+11, 9); ft[9] = otp[28];
  memcpy(ft+10, otp+50, 4); memcpy(ft+14, otp+56, 4); ft[18] = otp[62];
  memcpy(mt, otp+20, 8); memcpy(mt+8, otp+29, 7);
  memcpy(mt+15, otp+40, 10); memcpy(mt+25, otp+54, 2);
  otp[60] = goodix5e0a_otp_crc(cp, sizeof cp);
  otp[61] = goodix5e0a_otp_crc(ft, sizeof ft);
  otp[63] = goodix5e0a_otp_crc(mt, sizeof mt);
}
static void clobber_stack(void) {
  volatile guint8 bytes[4096];
  for (int i = 0; i < 4096; i++) bytes[i] = 0xdd;
}
int main(void) {
  FpDevice *dev = g_object_new(G_TYPE_OBJECT, NULL);
  guint8 otp[64];
  goodix_send_mcu_get_image(dev, image_error, NULL);
  g_assert_cmpint(sent, ==, 0); g_assert_cmpint(callback_errors, ==, 1);
  for (int pass = 0; pass < 2; pass++) {
    make_otp(otp, 160+pass*10);
    on_device_otp(dev, otp, 64, NULL, NULL);
    clobber_stack(); memset(otp, 0, sizeof otp);
    goodix_send_mcu_get_image(dev, NULL, NULL);
    g_assert_cmpint(advanced, ==, pass+1); g_assert_cmpint(failed, ==, 0);
    g_assert_cmpuint(wire_length, ==, 10);
    g_assert_cmpuint(wire[0], ==, 5); g_assert_cmpuint(wire[1], ==, 0);
    for (int i = 0; i < 4; i++) {
      g_assert_cmpuint(wire[2+2*i], ==, 160+pass*10+i);
      g_assert_cmpuint(wire[3+2*i], ==, 0);
    }
    g_assert_cmpmem(wire+2, 8, device_state.calibrated_down+2, 8);
    g_assert_cmpmem(wire+2, 8, device_state.calibrated_up+2, 8);
  }
  /* Invalid CRC clears a previous valid payload and sends no command. */
  make_otp(otp, 180); otp[60] ^= 1;
  on_device_otp(dev, otp, 64, NULL, NULL);
  g_assert_cmpint(failed, ==, 1); g_assert_cmpint(advanced, ==, 2);
  goodix_send_mcu_get_image(dev, image_error, NULL);
  g_assert_cmpint(sent, ==, 2); g_assert_cmpint(callback_errors, ==, 2);
  /* Transport failure also invalidates the previously calibrated state. */
  make_otp(otp, 190); on_device_otp(dev, otp, 64, NULL, NULL);
  on_device_otp(dev, NULL, 0, NULL,
    g_error_new_literal(G_IO_ERROR, G_IO_ERROR_FAILED, "OTP transport error"));
  goodix_send_mcu_get_image(dev, image_error, NULL);
  g_assert_cmpint(sent, ==, 2); g_assert_cmpint(callback_errors, ==, 3);
  g_assert_cmpint(failed, ==, 2); g_assert_cmpint(advanced, ==, 3);
  g_object_unref(dev);
  return 0;
}
'''
        flags = shlex.split(subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "gio-2.0"], text=True))
        with tempfile.TemporaryDirectory(prefix="goodix-calibration-test-") as tmp:
            src, exe = pathlib.Path(tmp) / "test.c", pathlib.Path(tmp) / "test"
            src.write_text(harness)
            result = subprocess.run(["cc", "-std=c11", "-Werror=incompatible-pointer-types", "-O0", "-I", str(driver),
                                     str(src), "-o", str(exe), *flags],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(exe)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
