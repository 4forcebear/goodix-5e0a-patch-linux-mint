"""Ticket 90: executable suspend/resume lifecycle coverage.

Two native C harnesses compile the actual driver (libfprint-driver/*.c, not a
Python model) and run it against mocked transport and real libfprint SSM:

- test_suspend_recovery_c.c: parked TLS teardown on suspend, clean fresh
  activation after resume, cancellation with stale TLS/probe callbacks,
  active-scan cancel hygiene, and the public idle suspend/resume dispatch.
- test_idle_suspend_dispatch_c.c: documents upstream libfprint behavior —
  with no interactive action, suspend/resume completes without calling the
  driver hooks, so idle park disposal relies on the park health probe.

The required lane builds fresh Nix harnesses (scripts/build_suspend_harness.sh
-> scripts/suspend-harness.nix) instead of reusing stale /tmp binaries.
Set GOODIX_SUSPEND_HARNESS / GOODIX_SUSPEND_DISPATCH_HARNESS to override with
a prebuilt pair, or GOODIX_SUSPEND_TESTS=skip to skip explicitly. Software
only: never touches USB, fprintd, system suspend or fingerprint claims.
"""
import os
import subprocess
import unittest
from tests.repo_paths import repo

BUILD_SCRIPT = repo("scripts", "build_suspend_harness.sh")


class TestF90SuspendRecovery(unittest.TestCase):
    def setUp(self):
        mode = os.environ.get("GOODIX_SUSPEND_TESTS", "required")
        if mode == "skip":
            self.skipTest("suspend lifecycle harness explicitly disabled by GOODIX_SUSPEND_TESTS=skip")
        self.assertEqual(mode, "required", "GOODIX_SUSPEND_TESTS must be required or skip")

        suspend = os.environ.get("GOODIX_SUSPEND_HARNESS", "")
        dispatch = os.environ.get("GOODIX_SUSPEND_DISPATCH_HARNESS", "")
        if not (suspend and dispatch):
            built = subprocess.run(["bash", BUILD_SCRIPT],
                                   capture_output=True, text=True, timeout=1200)
            self.assertEqual(built.returncode, 0,
                             f"Suspend harness build failed: {built.stderr}\n{built.stdout}")
            paths = built.stdout.strip().splitlines()
            self.assertEqual(len(paths), 2, f"Expected two harness paths, got: {built.stdout}")
            suspend, dispatch = paths
        self.suspend = suspend
        self.dispatch = dispatch

    def run_harness(self, path, expect=None):
        self.assertTrue(os.access(path, os.X_OK),
                        f"Native harness unavailable: {path}. Build it with "
                        "scripts/build_suspend_harness.sh or explicitly set GOODIX_SUSPEND_TESTS=skip")
        env = dict(os.environ)
        env.pop("LD_LIBRARY_PATH", None)  # packaged RUNPATH, not a developer's build tree
        res = subprocess.run([path], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(res.returncode, 0,
                         f"Native C test failed with stderr: {res.stderr}\nstdout: {res.stdout}")
        if expect is not None:
            self.assertIn(expect, res.stdout)
        return res.stdout

    def test_suspend_recovery_lifecycle(self):
        """Parked TLS dies on suspend; stale callbacks drop; fresh activation after resume."""
        out = self.run_harness(self.suspend, "1..10")
        self.assertIn("ok 9 /goodix/frame/normalization", out)
        self.assertIn("ok 10 /goodix/prints/processing-format", out)
        self.assertNotIn("not ok", out)
        for i, case in enumerate(("park-suspend-resume", "late-tls-after-cancel",
                                  "late-probe-after-suspend", "active-scan-cancel",
                                  "public-idle-suspend"), start=1):
            self.assertIn(f"ok {i} /goodix/lifecycle/{case}", out)
        # Real-priv teardown: armed waiter drops stale, single completion.
        self.assertIn("ok 6 /goodix/lifecycle/deactivate-mid-command-real-priv", out)
        self.assertIn("ok 7 /goodix/lifecycle/suspend-mid-command-real-priv", out)
        self.assertIn("ok 8 /goodix/lifecycle/step-cb-cancelled-fails-fast", out)

    def test_idle_suspend_dispatch_contract(self):
        """Upstream contract: idle suspend/resume completes without driver hooks."""
        self.run_harness(self.dispatch, "driver hooks: suspend=0 resume=0")


if __name__ == "__main__":
    unittest.main()
