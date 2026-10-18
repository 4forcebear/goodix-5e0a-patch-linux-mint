# Milan image processing correction

Some 27c6:5e0a units could capture fingerprint ridges but failed enrollment or
verification with the previous processing. The 3x3 residual retained pixel
noise while weakening ridges. Milan profile 10 also uses 64 rows of 80 columns;
the driver had supplied the canonical sensor buffer as 80 rows of 64 columns.

The normal driver now smooths with a clipped 3x3 mean, subtracts a clipped
11x11 mean of that smoothed image, and scales the residual RMS to 80 around
128, rounding and clipping to 8 bits. The public sensor raster stays 64x80.
The shared Milan bridge transposes it to 80x64 for quality, enrollment,
verification and gallery identification. Enrollment still targets 12 touches.

## Evidence

The investigation and reproducible replay tools remain in [PR #13](https://github.com/jitendradara12/goodix-5e0a/pull/13).
The production change uses its hardware-tested normalization and transpose,
without an experiment flag, calibration dependency or capture-settings change.

| Guided hardware run | Genuine matches | Wrong-finger rejections | Hands off, 20s | Steady hold, 20s |
| --- | --- | --- | --- | --- |
| Owner, NixOS | 5/5 | 5/5 | No enrollment activity | One advance |
| ptrip7, Mint | 5/5 | 5/5 | No enrollment activity | One advance |

Both runs completed fresh enrollment, verified isolated storage and restored
the original service. [ptrip7's report and ZIP](https://github.com/jitendradara12/goodix-5e0a/issues/12#issuecomment-6255563456)
record experiment revision `2c06c0f`; the owner used `bfb5852`. Both used candidate
patch SHA-256 `09c138bff5f4e6f4948fca565b0d5c025186027d96e63aca04249375facfef85`.

On ptrip7's saved labeled captures, the same band-pass filter improved from
5/10 genuine matches with the previous engine raster to 10/10 with the
transpose, with 0/10 wrong-finger matches in both cases. A separate session's
held-out frame matches improved from 62/96 to 82/96. These are small datasets
and repeated frames, not a general accuracy or false-accept-rate estimate.

Jet-Soup's unit requires separate capture settings and has not yet had this
hardware validation. This change does not establish a fix for that unit.

The clean production default was checked without the experiment flag: all 213
saved raw frames normalize byte for byte identically to the tested candidate.
The native C replay also preserves its enrollment selections, probe scores,
gallery decisions and both held-out session results. The software suite passes
368 tests with no skips; native tests cover pixel layout and print save/load.

## Enrollment compatibility

New saved prints carry the processing tag `milan-bandpass80-native-v1` around
the unchanged packed Milan template. Untagged, differently tagged, malformed
or empty prints are rejected before reaching the engine. Old templates cannot
be converted without new touches; users must remove old prints and enroll again.
Rolling back also requires a new enrollment for the older processing.

## Final installation check

The guided runs tested the image processing. The production build additionally
changes the default and saved-print tagging. After normal installation, use a
fresh enrollment and repeat the same hands-off/holding protocol and five genuine
and five wrong-finger attempts.

Confirm: no hands-off advances, one hold advance followed by waiting for
release, all 12 enrollment stages complete, genuine matches and wrong-finger
rejections. Falsify: repeated hold advances, spurious activity, genuine failures
or any wrong-finger match. Wrong build or old enrollment makes the run
inconclusive. The single next hardware check is this normal-install run on
ptrip7's affected laptop; no new dumps or Windows exports are requested.
