"""Exercise installer profile selection and the actual PAM editing program.

All writes use temporary fixtures. No system PAM or sensor access occurs.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "install.sh"
PLAIN = """auth [success=2 default=ignore] pam_fprintd.so max-tries=1 timeout=10
auth [success=1 default=ignore] pam_unix.so nullok try_first_pass
auth requisite pam_deny.so
auth required pam_permit.so
auth required pam_ecryptfs.so unwrap
"""
GUARD = "auth [authinfo_unavail=1 default=ignore] pam_fingwit.so\n"


class EncryptedHomePAMTest(unittest.TestCase):
    def select_profile(self, installed, profile_exists):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profiles, bin_dir = root / "profiles", root / "bin"
            profiles.mkdir()
            bin_dir.mkdir()
            if profile_exists:
                (profiles / "fingwit").write_text("fixture profile\n")
            query = bin_dir / "dpkg-query"
            query.write_text(
                "#!/bin/sh\n"
                "test \"$1\" = -s && test \"$2\" = libpam-fingwit || exit 2\n"
                + ("echo 'Status: install ok installed'\n" if installed else "exit 1\n")
            )
            query.chmod(0o755)
            result = subprocess.run(
                ["bash", "-c", 'source "$1"; choose_pam_profile "$2"',
                 "test", str(INSTALLER), str(profiles)],
                env={**os.environ, "PATH": str(bin_dir) + ":" + os.environ["PATH"]},
                capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.strip()

    def test_installed_mint_guard_is_preferred(self):
        self.assertEqual(self.select_profile(True, True), "fingwit")

    def test_profile_without_module_is_not_selected(self):
        self.assertEqual(self.select_profile(False, True), "fprintd")

    def test_module_without_profile_is_not_selected(self):
        self.assertEqual(self.select_profile(True, False), "fprintd")

    def edit_fixture(self, content, profile):
        match = re.search(
            r"sudo python3 - \"\$pam_file\" \"\$pam_profile\" <<'PYTHON'\n(.*?)\nPYTHON",
            INSTALLER.read_text(), re.S,
        )
        self.assertIsNotNone(match, "Cannot locate production PAM editing program")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "common-auth"
            path.write_text(content)
            path.chmod(0o640)
            result = subprocess.run(
                [sys.executable, "-", str(path), profile], input=match.group(1),
                capture_output=True, text=True, timeout=5,
            )
            return result, path.read_text(), path.stat().st_mode & 0o777

    def test_valid_mint_stack_preserves_guard_and_password(self):
        content = GUARD + PLAIN
        result, edited, mode = self.edit_fixture(content, "fingwit")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(edited, content.replace("max-tries=1", "max-tries=3"))
        self.assertEqual(mode, 0o640)

    def test_missing_guard_refuses_without_writing(self):
        result, edited, _ = self.edit_fixture(PLAIN, "fingwit")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("guard missing", result.stderr)
        self.assertEqual(edited, PLAIN)

    def test_incorrect_or_detached_guard_refuses_without_writing(self):
        for content in (
            GUARD.replace("unavail=1", "unavail=2") + PLAIN,
            GUARD + "auth optional pam_permit.so\n" + PLAIN,
        ):
            with self.subTest(content=content):
                result, edited, _ = self.edit_fixture(content, "fingwit")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(edited, content)

    def test_missing_password_fallback_refuses_without_writing(self):
        content = GUARD + re.sub(r"^.*pam_unix.*\n", "", PLAIN, flags=re.M)
        result, edited, _ = self.edit_fixture(content, "fingwit")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("password fallback", result.stderr)
        self.assertEqual(edited, content)

    def test_non_mint_stack_keeps_existing_behavior(self):
        result, edited, _ = self.edit_fixture(PLAIN, "fprintd")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(edited, PLAIN.replace("max-tries=1", "max-tries=3"))
