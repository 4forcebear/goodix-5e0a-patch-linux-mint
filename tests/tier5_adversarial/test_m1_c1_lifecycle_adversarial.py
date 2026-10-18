"""
Tier 5 - Milestone 1 Adversarial Challenge: Driver Hardening Lifecycle & Cancellation
Empirically tests state teardown, SSM cleanup, and USB cancellation handling in Goodix 5e0a driver.
"""

import unittest
import os
import subprocess
from tests.repo_paths import repo

class TestM1C1LifecycleAdversarial(unittest.TestCase):
    """
    Adversarial verification of Milestone 1 driver hardening:
    - SSM lifecycle, NULL checks, and teardown idempotency
    - Dropping G_IO_ERROR_CANCELLED vs preserving genuine I/O errors
    - Verification image capture flow without deactivation race
    - Patch and packaging synchronization
    - Native C runtime invariant execution
    """

    def setUp(self):
        self.goodix5e0a_c = repo("libfprint-driver", "goodix5e0a.c")
        self.goodix5e0a_h = repo("libfprint-driver", "goodix5e0a.h")
        self.goodix_c = repo("libfprint-driver", "goodix.c")
        self.goodix_h = repo("libfprint-driver", "goodix.h")
        self.repo_patch = repo("goodix-5e0a-integration.patch")
        self.c_test_bin = os.environ.get("GOODIX_NATIVE_HARNESS", "")

    # --------------------------------------------------------------------------
    # 1. SSM Lifecycle & Deactivation Invariants
    # --------------------------------------------------------------------------

    def test_ssm_deactivation_cleanup_and_nullify(self):
        """Verify goodix5e0a_deactivate checks self->scan_ssm != NULL, frees it, and sets it to NULL."""
        with open(self.goodix5e0a_c, "r") as f:
            content = f.read()

        deact_idx = content.find("goodix5e0a_deactivate (FpImageDevice *img_dev)")
        self.assertNotEqual(deact_idx, -1, "goodix5e0a_deactivate must exist")
        # 2026-09-09: window 800 -> 1600; the 46 idle-gate comment block
        # pushes the SSM free below the old window. Invariant unchanged.
        deact_body = content[deact_idx:deact_idx + 1600]

        # Must check scan_ssm != NULL
        self.assertIn("if (self->scan_ssm != NULL)", deact_body)
        # Must call fpi_ssm_free
        self.assertIn("fpi_ssm_free (self->scan_ssm);", deact_body)
        # Must set scan_ssm to NULL to prevent dangling pointer / double free
        self.assertIn("self->scan_ssm = NULL;", deact_body)
        # Must clean down_timeout
        self.assertIn("g_source_destroy (self->down_timeout);", deact_body)
        self.assertIn("self->down_timeout = NULL;", deact_body)

    def test_ssm_nullified_before_final_report(self):
        """Verify scan_ssm is set to NULL prior to fpi_ssm_next_state and reporting finger status."""
        with open(self.goodix5e0a_c, "r") as f:
            content = f.read()

        fdt_up_idx = content.find("goodix5e0a_on_fdt_up_reply")
        self.assertNotEqual(fdt_up_idx, -1)
        # 2026-09-09: was a fixed 800/1600-char window; the 47 re-issue
        # block outgrew windows. Slice the whole function instead —
        # ordering invariant within it is unchanged.
        fdt_up_end = content.find(
            "goodix5e0a_scan_run_state", fdt_up_idx)
        self.assertNotEqual(fdt_up_end, -1)
        fdt_up_body = content[fdt_up_idx:fdt_up_end]

        null_pos = fdt_up_body.find("self->scan_ssm = NULL;")
        next_pos = fdt_up_body.find("fpi_ssm_next_state (ssm);")
        report_pos = fdt_up_body.find("fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), FALSE);")

        self.assertNotEqual(null_pos, -1, "scan_ssm must be cleared to NULL in fdt_up_reply")
        self.assertNotEqual(next_pos, -1, "fpi_ssm_next_state must be called")
        self.assertNotEqual(report_pos, -1, "report_finger_status must be called")

        # Ordering invariant: scan_ssm = NULL before next_state and report_finger_status
        self.assertLess(null_pos, next_pos, "self->scan_ssm = NULL must occur before fpi_ssm_next_state")
        self.assertLess(next_pos, report_pos, "fpi_ssm_next_state must occur before report_finger_status")

    def test_ssm_scan_start_concurrency_guard(self):
        """Verify goodix5e0a_scan_start rejects concurrent scan SSM creation if one is active."""
        with open(self.goodix5e0a_c, "r") as f:
            content = f.read()

        start_idx = content.find("goodix5e0a_scan_start (FpDevice *dev)")
        self.assertNotEqual(start_idx, -1)
        start_body = content[start_idx:start_idx + 400]

        self.assertIn("if (self->scan_ssm != NULL)", start_body)
        self.assertIn("return;", start_body)

    def test_ssm_down_poll_stale_pointer_guard(self):
        """Verify down poll timeout callback verifies ssm pointer validity against self->scan_ssm."""
        with open(self.goodix5e0a_c, "r") as f:
            content = f.read()

        poll_idx = content.find("goodix5e0a_on_down_poll_timeout")
        self.assertNotEqual(poll_idx, -1)
        poll_body = content[poll_idx:poll_idx + 400]

        self.assertIn("if (self->scan_ssm != ssm)", poll_body)
        self.assertIn("return;", poll_body)

    # --------------------------------------------------------------------------
    # 2. USB Transfer Cancellation Invariants
    # --------------------------------------------------------------------------

    def test_cancelled_usb_transfer_drop_in_read_callback(self):
        """Verify goodix_receive_data_cb drops cancelled transfers without resubmitting read loop."""
        with open(self.goodix_c, "r") as f:
            content = f.read()

        cb_idx = content.find("goodix_receive_data_cb (FpiUsbTransfer *transfer")
        self.assertNotEqual(cb_idx, -1)
        cb_body = content[cb_idx:cb_idx + 800]

        # Must check both token cancellation AND G_IO_ERROR_CANCELLED error code
        self.assertIn("g_cancellable_is_cancelled (priv->transfer_cancel_tkn)", cb_body)
        self.assertIn("g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)", cb_body)

        # Must free error if present
        cancel_block_idx = cb_body.find("aborting read loop...")
        self.assertNotEqual(cancel_block_idx, -1)
        self.assertIn("if (error)\n        g_error_free (error);", cb_body)
        self.assertIn("return;", cb_body[cancel_block_idx:cancel_block_idx + 100])

    def test_read_loop_cancellable_token_reset_on_start(self):
        """Verify goodix_start_read_loop resets cancelled token before submitting new transfer."""
        with open(self.goodix_c, "r") as f:
            content = f.read()

        start_idx = content.find("goodix_start_read_loop (FpDevice *dev)")
        self.assertNotEqual(start_idx, -1)
        start_body = content[start_idx:start_idx + 600]

        self.assertIn("if (g_cancellable_is_cancelled (priv->transfer_cancel_tkn))", start_body)
        self.assertIn("g_cancellable_reset (priv->transfer_cancel_tkn);", start_body)
        self.assertIn("goodix_receive_data (dev);", start_body)

    def test_genuine_io_error_preserved(self):
        """Verify genuine non-cancellation errors are reported via fp_warn and retried."""
        with open(self.goodix_c, "r") as f:
            content = f.read()

        cb_idx = content.find("goodix_receive_data_cb (FpiUsbTransfer *transfer")
        cb_body = content[cb_idx:cb_idx + 800]

        # Following the cancelled block, genuine errors are caught:
        self.assertIn("fp_warn (\"Receive data error: %s\", error->message);", cb_body)
        self.assertIn("goodix_receive_data (dev);", cb_body)

    # --------------------------------------------------------------------------
    # 3. Verification Capture Flow & Contrast Calibration
    # --------------------------------------------------------------------------

    def test_verification_mode_unconditional_image_capture(self):
        """Verify that in verify mode, images are unconditionally forwarded without retry_scan."""
        with open(self.goodix5e0a_c, "r") as f:
            content = f.read()

        img_cb_idx = content.find("goodix5e0a_on_read_img")
        self.assertNotEqual(img_cb_idx, -1)
        # Ticket 39: best-of-N burst logic lengthened this callback; the
        # window covers the whole body through the shared deliver tail.
        img_cb_body = content[img_cb_idx:img_cb_idx + 8000]

        # retry_scan must be guarded by ACTION_ENROLL only
        self.assertIn("if (action == FPI_DEVICE_ACTION_ENROLL)", img_cb_body)
        self.assertIn("fpi_image_device_image_captured (dev);", img_cb_body)

    def test_bandpass_calibration_value(self):
        """Verify the hardware-tested residual RMS is the production default."""
        with open(self.goodix5e0a_h, "r") as f:
            header_content = f.read()
        self.assertIn("#define GOODIX_5E0A_BANDPASS_TARGET_RMS (80.0f)", header_content)

        with open(repo("libfprint-driver", "goodix5e0a-image.h"), "r") as f:
            source_content = f.read()
        self.assertIn("GOODIX_5E0A_BANDPASS_TARGET_RMS / residual_rms", source_content)

    # --------------------------------------------------------------------------
    # 4. Upstream Integration Boundary
    # --------------------------------------------------------------------------

    def test_patch_integration_boundary(self):
        """Keep driver sources and obsolete matcher changes out of the patch."""
        with open(self.repo_patch, encoding="utf-8") as f:
            content = f.read()
        paths = {line.split()[2] for line in content.splitlines()
                 if line.startswith("diff --git ")}
        self.assertEqual(paths, {
            "a/libfprint/fp-device.h",
            "a/libfprint/fprint-list-udev-hwdb.c",
            "a/libfprint/meson.build",
            "a/meson.build",
        })
        # Current fprintd requires both the version and the new retry enum.
        self.assertIn("+    version: '1.94.9',", content)
        self.assertIn("+  FP_DEVICE_RETRY_TOO_FAST,", content)
        self.assertLess(len(content), 20000)

    # --------------------------------------------------------------------------
    # 5. Native C Empirical Invariant Execution
    # --------------------------------------------------------------------------

    def test_native_c_ssm_and_cancellation_invariants(self):
        """Execute compiled C test harness verifying 8 runtime invariants directly in libfprint."""
        mode = os.environ.get("GOODIX_NATIVE_TESTS", "required")
        if mode == "skip":
            self.skipTest("native C harness explicitly disabled by GOODIX_NATIVE_TESTS=skip")
        self.assertEqual(mode, "required", "GOODIX_NATIVE_TESTS must be required or skip")
        self.assertTrue(os.access(self.c_test_bin, os.X_OK),
                        "Native harness unavailable; run bash tests/run_all_tests.sh "
                        "or explicitly set GOODIX_NATIVE_TESTS=skip")

        env = dict(os.environ)
        # Use the packaged RUNPATH, not a developer's build tree.
        env.pop("LD_LIBRARY_PATH", None)

        res = subprocess.run(
            [self.c_test_bin],
            env=env,
            capture_output=True,
            text=True,
            timeout=10
        )
        self.assertEqual(res.returncode, 0, f"Native C test failed with stderr: {res.stderr}\nstdout: {res.stdout}")
        self.assertIn("ALL 8 EMPIRICAL INVARIANT TESTS PASSED CLEANLY!", res.stdout)

if __name__ == "__main__":
    unittest.main()
