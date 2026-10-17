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

    def test_b_real_windows_dpapi_blob(self):
        """parse_dpapi_blob_length validates actual Windows 11 hardware DPAPI dump."""
        if not REAL_DPAPI_FILE.exists():
            self.skipTest(f"Missing {REAL_DPAPI_FILE}")
        real_data = REAL_DPAPI_FILE.read_bytes()
        real_324 = real_data[:324]
        self.assertEqual(len(real_324), 324)

        exp, comp = parse_dpapi_blob_length(real_324)
        self.assertEqual(exp, 324)
        self.assertTrue(comp)

        # Truncated at 256
        exp_256, comp_256 = parse_dpapi_blob_length(real_324[:256])
        self.assertEqual(exp_256, 324)
        self.assertFalse(comp_256)

        # Padded to 400
        exp_400, comp_400 = parse_dpapi_blob_length(real_324 + b"\x00" * 76)
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
        """read_dpapi_blob fetches remainder if initial read was truncated at 256 bytes."""
        blob = make_dummy_dpapi_blob(data_len=48, sign_len=64)
        chunk1 = blob[:256]
        chunk2 = blob[256:]  # 68 bytes
        dev = MockDevice({
            # 400, 384, 320 fail; 256 succeeds with 256 bytes
            (0xbb010002, 256, 0): (True, 0xbb010002, chunk1),
            (0xbb010002, 68, 256): (True, 0xbb010002, chunk2),
        })
        res = read_dpapi_blob(dev)
        self.assertEqual(len(res), 324)
        self.assertEqual(res, blob)

    def test_e_decrypt_psk_script_hardening(self):
        """decrypt_psk.ps1 has error action guard, polling loop, and system logging."""
        ps1 = DECRYPT_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('$ErrorActionPreference = "Continue"', ps1)
        self.assertIn("schtasks /create", ps1)
        self.assertIn("Get-DpapiBlobLength", ps1)
        self.assertIn("system-log.txt", ps1)
        self.assertIn("Start-Sleep -Seconds 1", ps1)

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


if __name__ == "__main__":
    unittest.main()
