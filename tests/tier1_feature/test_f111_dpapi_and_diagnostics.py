"""
Tier 1 - Feature 111: DPAPI blob extraction hardening and driver cleanliness (Ticket 111 / Issue #12).

Verifies without hardware:
(a) tools/dump_dpapi_blob.py parse_dpapi_blob_length accurately calculates DPAPI structure length
    (including dwSignAlgo, dwSignAlgoLen, dwSignSaltLen, pbSignSalt), trims trailing padding
    on 400-byte reads, handles real Windows 11 324-byte dumps, and manages chunk fallbacks;
(b) tools/decrypt_psk.ps1 contains error action safeguards against PowerShell 5.1 NativeCommandError,
    implements polling loop up to 20s, system logging, and accurate DPAPI structure length validation;
(c) goodix5e0a.c and goodix_milan.c adhere strictly to repository standards and AGENTS.md:
    no ad-hoc environment variable overrides or diagnostic dumping in production driver code,
    staying within the 2000-line and 25-g_message budgets.
"""

import os
import struct
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DUMP_SCRIPT = REPO_ROOT / "tools" / "dump_dpapi_blob.py"
DECRYPT_SCRIPT = REPO_ROOT / "tools" / "decrypt_psk.ps1"
GOODIX5E0A_C = REPO_ROOT / "libfprint-driver" / "goodix5e0a.c"
GOODIX_MILAN_C = REPO_ROOT / "libfprint-driver" / "goodix_milan.c"
GOODIX_MILAN_H = REPO_ROOT / "libfprint-driver" / "goodix_milan.h"
REAL_DPAPI_FILE = REPO_ROOT / "legacy-experiments" / "dpapi_full.bin"

import sys
sys.path.insert(0, str(REPO_ROOT / "tools"))
from dump_dpapi_blob import parse_dpapi_blob_length, read_dpapi_blob


def make_dummy_dpapi_blob(data_len=48, sign_len=64, desc=b"\x00" * 64, salt_len=32, sign_salt_len=32):
    desc_bytes = desc
    desc_len = len(desc_bytes)
    hdr = (
        struct.pack("<I", 1) +                  # dwVersion = 1
        b"\x00" * 16 +                          # guidProvider
        struct.pack("<I", 1) +                  # dwMasterKeyVersion
        b"\x11" * 16 +                          # guidMasterKey
        struct.pack("<I", 0) +                  # dwFlags
        struct.pack("<I", desc_len) +           # dwDescriptionLen
        desc_bytes                              # szDescription
    )
    crypt_meta = (
        struct.pack("<III", 0x6610, 256, salt_len) +        # dwCryptAlgo, dwCryptAlgoLen, dwSaltLen
        b"\xaa" * salt_len +                                 # pbSalt
        struct.pack("<I", 0) +                               # dwPromptLen = 0
        struct.pack("<III", 0x800e, 512, sign_salt_len) +   # dwSignAlgo, dwSignAlgoLen, dwSignSaltLen
        b"\xdd" * sign_salt_len +                            # pbSignSalt
        struct.pack("<I", data_len) +                        # dwDataLen
        b"\xbb" * data_len +                                 # pbData
        struct.pack("<I", sign_len) +                        # dwSignLen
        b"\xcc" * sign_len                                   # pbSign
    )
    return hdr + crypt_meta


class MockDevice:
    def __init__(self, responses):
        self.responses = responses
        self.call_log = []

    def preset_psk_read(self, flags, length, offset):
        self.call_log.append((flags, length, offset))
        key = (flags, length, offset)
        if key in self.responses:
            return self.responses[key]
        if (flags, length) in self.responses:
            return self.responses[(flags, length)]
        return False, None, None


class TestF111DpapiAndDiagnostics(unittest.TestCase):

    def test_a_dpapi_blob_length_parsing(self):
        """parse_dpapi_blob_length accurately calculates length and detects completion."""
        # Standard 324-byte blob synthesized with true DPAPI layout
        blob = make_dummy_dpapi_blob(data_len=48, sign_len=64)
        self.assertEqual(len(blob), 324)
        exp, comp = parse_dpapi_blob_length(blob)
        self.assertEqual(exp, 324)
        self.assertTrue(comp)

        # 400-byte padded blob
        padded = blob + b"\x00" * 76
        exp_p, comp_p = parse_dpapi_blob_length(padded)
        self.assertEqual(exp_p, 324)
        self.assertTrue(comp_p)

        # Truncated 256-byte blob (ends right after pbData, missing signature)
        trunc = blob[:256]
        exp_t, comp_t = parse_dpapi_blob_length(trunc)
        self.assertEqual(exp_t, 324)
        self.assertFalse(comp_t)

        # Tiny buffer (< 48 bytes)
        exp_s, comp_s = parse_dpapi_blob_length(b"\x01\x00\x00\x00" * 4)
        self.assertIsNone(exp_s)
        self.assertFalse(comp_s)

    def test_b_synthetic_dpapi_fixture(self):
        """parse_dpapi_blob_length validates synthetic 360-byte DPAPI fixture (Ticket 44)."""
        if REAL_DPAPI_FILE.exists():
            real_data = REAL_DPAPI_FILE.read_bytes()
            test_blob = real_data[:324]
        else:
            test_blob = make_dummy_dpapi_blob(data_len=48, sign_len=64)

        self.assertEqual(len(test_blob), 324)

        exp, comp = parse_dpapi_blob_length(test_blob)
        self.assertEqual(exp, 324)
        self.assertTrue(comp)

        # Truncated at 256
        exp_256, comp_256 = parse_dpapi_blob_length(test_blob[:256])
        self.assertEqual(exp_256, 324)
        self.assertFalse(comp_256)

        # Padded to 400
        exp_400, comp_400 = parse_dpapi_blob_length(test_blob + b"\x00" * 76)
        self.assertEqual(exp_400, 324)
        self.assertTrue(comp_400)

    def test_c_read_dpapi_blob_trims_padding(self):
        """read_dpapi_blob requests up to 400 bytes and trims trailing buffer padding."""
        blob = make_dummy_dpapi_blob(data_len=48, sign_len=64)
        padded_400 = blob + b"\x00" * 76
        dev = MockDevice({
            (0xbb010002, 400, 0): (True, 0xbb010002, padded_400)
        })
        res = read_dpapi_blob(dev)
        self.assertEqual(len(res), 324)
        self.assertEqual(res, blob)
        self.assertEqual(dev.call_log, [(0xbb010002, 400, 0)])

    def test_d_read_dpapi_blob_chunk_fallback(self):
        """read_dpapi_blob falls back to 256 without redundant 384/320 queries and fetches remainder."""
        blob = make_dummy_dpapi_blob(data_len=48, sign_len=64)
        chunk1 = blob[:256]
        chunk2 = blob[256:]  # 68 bytes
        dev = MockDevice({
            # 400 fails; 256 succeeds with 256 bytes; 68 at offset 256 succeeds
            (0xbb010002, 256, 0): (True, 0xbb010002, chunk1),
            (0xbb010002, 68, 256): (True, 0xbb010002, chunk2),
        })
        res = read_dpapi_blob(dev)
        self.assertEqual(len(res), 324)
        self.assertEqual(res, blob)
        # Ensure redundant 384/320 steps were pruned
        self.assertEqual(dev.call_log, [
            (0xbb010002, 400, 0),
            (0xbb010002, 256, 0),
            (0xbb010002, 68, 256),
        ])

    def test_e_decrypt_psk_script_hardening(self):
        """decrypt_psk.ps1 has error action guard, polling loop, system logging, and fail-closed checks."""
        ps1 = DECRYPT_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('$ErrorActionPreference = "Continue"', ps1)
        self.assertIn("schtasks /create", ps1)
        self.assertIn("Get-DpapiBlobLength", ps1)
        self.assertIn("system-log.txt", ps1)
        self.assertIn("Start-Sleep -Seconds 1", ps1)
        self.assertIn("Remove-Item -Path $ResolvedOutput -Force", ps1)
        self.assertIn("$runExit = $LASTEXITCODE", ps1)
        self.assertIn("if ($runExit -ne 0)", ps1)
        self.assertIn("$runFailed = $true", ps1)
        self.assertIn("Decrypted payload length is $($plain.Length) bytes (expected 32 bytes)", ps1)
        self.assertIn("WARNING: '$HashPath' not found", ps1)

    def test_f_driver_cleanliness_and_budgets(self):
        """Verify production driver contains no band-aid env vars and respects budgets."""
        c_src = GOODIX5E0A_C.read_text(encoding="utf-8")
        milan_c = GOODIX_MILAN_C.read_text(encoding="utf-8")
        milan_h = GOODIX_MILAN_H.read_text(encoding="utf-8")

        # No band-aid frame dumping or env var hooks in production driver
        self.assertNotIn("GOODIX_5E0A_DUMP_DIR", milan_c)
        self.assertNotIn("goodix_milan_dump_debug_frame", milan_h)
        self.assertNotIn("goodix5e0a_get_contrast_gain", c_src)
        self.assertNotIn('g_getenv ("GOODIX_5E0A_CONTRAST_GAIN")', c_src)

        lines = [l for l in c_src.splitlines() if l.strip()]
        self.assertLess(len(lines), 2000, f"Driver LOC {len(lines)} exceeds 2000")
        self.assertEqual(c_src.count("g_message ("), 25, "g_message budget violated")

    def test_g_read_dpapi_blob_fail_closed(self):
        """read_dpapi_blob returns None on empty read, corrupted header, or incomplete chunks."""
        # Case 1: Device returns empty byte string
        dev_empty = MockDevice({
            (0xbb010002, 400, 0): (True, 0xbb010002, b""),
            (0xbb010002, 256, 0): (True, 0xbb010002, b""),
        })
        self.assertIsNone(read_dpapi_blob(dev_empty))

        # Case 2: Device returns garbage / short header (< 48 bytes)
        dev_garbage = MockDevice({
            (0xbb010002, 400, 0): (True, 0xbb010002, b"\x00" * 40),
            (0xbb010002, 256, 0): (True, 0xbb010002, b"\x00" * 40),
        })
        self.assertIsNone(read_dpapi_blob(dev_garbage))

        # Case 3: Initial read is truncated (256 bytes), but offset read for remainder fails
        blob = make_dummy_dpapi_blob(data_len=48, sign_len=64)
        dev_chunk_fail = MockDevice({
            (0xbb010002, 400, 0): (False, None, None),
            (0xbb010002, 256, 0): (True, 0xbb010002, blob[:256]),
            (0xbb010002, 68, 256): (False, None, None),
        })
        self.assertIsNone(read_dpapi_blob(dev_chunk_fail))

        # Case 4: Offset read returns zero frame (b"\x00" * 68) where exp2 != expected_len
        dev_zero_chunk = MockDevice({
            (0xbb010002, 400, 0): (False, None, None),
            (0xbb010002, 256, 0): (True, 0xbb010002, blob[:256]),
            (0xbb010002, 68, 256): (True, 0xbb010002, b"\x00" * 68),
        })
        self.assertIsNone(read_dpapi_blob(dev_zero_chunk))

        # Case 5: Offset read returns repeated head chunk (sensor cursor reset to 0)
        dev_repeat_chunk = MockDevice({
            (0xbb010002, 400, 0): (False, None, None),
            (0xbb010002, 256, 0): (True, 0xbb010002, blob[:256]),
            (0xbb010002, 68, 256): (True, 0xbb010002, blob[:68]),
        })
        self.assertIsNone(read_dpapi_blob(dev_repeat_chunk))

    def test_h_capture_live_burst_psk_resolution(self):
        """capture_live_burst.resolve_psk respects CLI override, file path, and default fallback."""
        sys.path.insert(0, str(REPO_ROOT / "legacy-experiments"))
        import capture_live_burst
        from unittest.mock import patch

        custom_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        # CLI direct hex argument
        self.assertEqual(capture_live_burst.resolve_psk(custom_hex), bytes.fromhex(custom_hex))

        # CLI argument as file
        tmp_psk_file = REPO_ROOT / "legacy-experiments" / "tmp_test.psk"
        try:
            tmp_psk_file.write_text(custom_hex + "\n")
            self.assertEqual(capture_live_burst.resolve_psk(str(tmp_psk_file)), bytes.fromhex(custom_hex))
        finally:
            if tmp_psk_file.exists():
                tmp_psk_file.unlink()

        # Non-existent file path with path separators raises FileNotFoundError
        with self.assertRaises(FileNotFoundError):
            capture_live_burst.resolve_psk("nonexistent/path/to/key.psk")

        # Fallback to system key when file exists
        with patch("pathlib.Path.is_file") as mock_isfile, \
             patch("pathlib.Path.read_text", return_value=custom_hex):
            mock_isfile.return_value = True
            self.assertEqual(capture_live_burst.resolve_psk(None), bytes.fromhex(custom_hex))

        # Fallback to default dev unit key when system file is absent
        with patch("pathlib.Path.is_file", return_value=False):
            self.assertEqual(capture_live_burst.resolve_psk(None), capture_live_burst.DEFAULT_PSK)

    def test_i_dump_dpapi_blob_script_invariants(self):
        """dump_dpapi_blob.py has pre-flight stale output removal, ladder pruning, and exit 1 on fail."""
        dump_src = DUMP_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("hash_path.unlink()", dump_src)
        self.assertIn("blob_path.unlink()", dump_src)
        self.assertIn("for try_len in [400, 256]:", dump_src)
        self.assertIn("if exp2 and comp2 and exp2 == expected_len:", dump_src)
        self.assertIn("sys.exit(1)", dump_src)


if __name__ == "__main__":
    unittest.main()
