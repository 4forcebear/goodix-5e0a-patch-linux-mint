"""
Tier 1 - Feature 101: per-touch enrollment burst reset (Ticket 101/103).

Verifies without hardware (hermetic static & structural validation):
(a) the enroll-continue branch of on_read_img resets the burst AFTER the
    deliver tail consumed the winner and BEFORE fpi_ssm_next_state, so each
    of the 12 enrollment touches banks its own 4-frame burst. Pre-fix,
    frame_count kept climbing past GOODIX_5E0A_FRAMES_PER_TOUCH (journal:
    "frame 5/4 ... 11/4"), so every touch after the first captured a single
    frame and competed against touch 1's stale winner; a mid-touch read
    error could also resubmit that stale winner via the best_frame_no > 0
    fallback;
(b) the pre-existing reset hygiene sites (claim, SSM completion, scan start,
    deactivate, suspend, both enroll rejection paths) are all still present;
(c) production normalization uses the issue-12 hardware-tested residual RMS
    target. Its numerical behavior is checked by the native frame harness.
"""

import os
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GOODIX5E0A_C = os.path.join(REPO_ROOT, "libfprint-driver", "goodix5e0a.c")
GOODIX5E0A_H = os.path.join(REPO_ROOT, "libfprint-driver", "goodix5e0a.h")

MARKER = ("goodix5e0a_reset_touch_frames (self); "
          "/* ticket 101: fresh burst per enroll touch */")


def _read(path):
    with open(path, "r") as f:
        return f.read()


def _function_body(src, signature):
    """Body of the function whose definition starts with `signature`."""
    start = src.index(signature)
    brace = src.index("\n{", start)
    end = src.index("\n}\n", brace)
    return src[brace:end]


class TestF101PerTouchBurst(unittest.TestCase):
    """Ticket 101/103: fresh burst per enrollment touch."""

    def setUp(self):
        self.src_c = _read(GOODIX5E0A_C)
        self.src_h = _read(GOODIX5E0A_H)

    def test_enroll_continue_resets_burst_per_touch(self):
        """(a) Reset sits in the enroll-continue branch, between deliver and re-arm."""
        self.assertEqual(self.src_c.count(MARKER), 1)
        body = _function_body(self.src_c, "goodix5e0a_on_read_img (FpDevice *dev")
        self.assertIn(MARKER, body)
        delivered = body.index("fpi_image_device_image_captured (dev);")
        completed = body.index("fpi_ssm_mark_completed (ssm);", delivered)
        reset_at = body.index(MARKER)
        self.assertLess(completed, reset_at,
                        "reset belongs to the else (continue) branch, after completion")
        self.assertIn("else", body[completed:reset_at])
        next_state_at = body.index("fpi_ssm_next_state (ssm);", reset_at)
        self.assertEqual(body[reset_at + len(MARKER):next_state_at].strip(), "",
                         "reset must immediately precede the SSM re-arm")

    def test_burst_hygiene_sites_preserved(self):
        """(b) All pre-existing reset sites survive the ticket-101 edit."""
        self.assertEqual(self.src_c.count("goodix5e0a_reset_touch_frames (self);"), 8)
        for fn in ("goodix5e0a_scan_complete", "goodix5e0a_scan_start",
                   "goodix5e0a_deactivate"):
            self.assertIn(fn, self.src_c)
        self.assertIn("a stale burst winner must never survive across claims",
                      self.src_c.lower())

    def test_bandpass_rms_calibrated(self):
        """(c) Residual RMS is the hardware-tested band-pass value."""
        self.assertIn("#define GOODIX_5E0A_BANDPASS_TARGET_RMS (80.0f)", self.src_h)


if __name__ == "__main__":
    unittest.main()
