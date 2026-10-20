# v1.0.2: APP_10034 capture calibration hotfix

The v1.0.1 source accepts only `GFUSB_GM168SEC_APP_10036`. An installed
driver could therefore pass `--verify-install` but fail activation on an
APP_10034 sensor. Adding that exact firmware to the supported revisions
exposed a second defect: activation validates OTP, but the image-command
path cannot find its capture parameters and reports
`Missing Goodix sensor calibration` on the first touch.

The corrected source accepts APP_10034 and APP_10036 explicitly. After
successful OTP validation, it stores a device-owned copy of the 10-byte
capture payload for `goodix_send_mcu_get_image`. An unsuccessful OTP refresh
clears the previous payload, preventing capture with stale calibration.
The copy remains valid after the OTP callback returns and is released with
the device. Enrollment remains 24 accepted touches using Milan scoring.

## Validation, 2026-10-20

- The checked installer's build-only path compiled the private libfprint.
- A native regression test executes the production OTP callback, real OTP
  calibration, and production image-command function with synthetic OTP.
  It checks capture after callback return, replacement on recalibration,
  rejection of invalid CRC, and rejection after an OTP transport error.
- The focused firmware compatibility test passes.
- The native capture test fails with the original OTP callback, confirming
  that it detects the missing handoff rather than merely exercising a stub.
- Installed library SHA-256:
  `42d7de08257dc18cb26e25f5a8e27a13b3106a73950b8135c62ca1aa871bb365`.
- `./install.sh --verify-install` passes after deployment.
- Hands off from 17:32:23 MSK: no accepted stages before the first touch at
  17:33:24. A stationary touch produced one accepted stage; the extended
  hold reached the existing 30-second release guard. The hold exceeded the
  intended 20-second observation, so this run does not establish behavior
  across exactly 20 seconds. No release-timeout behavior was changed.
- A fresh enrollment from 17:35:10 to 17:36:58 MSK reached
  `accepted=24/24 progress=100%` and `enroll-completed`. Rejected samples
  preserved progress.
- Three independent genuine verification calls returned `verify-match`,
  with Milan scores 61, 67, and 61.
- A user-confirmed different, unenrolled finger returned `verify-no-match`;
  all four burst frames scored 0.

The capture fix, complete enrollment, repeated genuine matching, and one
different-finger rejection are confirmed on this APP_10034 Realme Book 14 i5.
These runs used root-started fprintd clients with the explicit account `mint`.
They do not verify desktop/PAM integration or suspend/resume reliability.

Run the focused software checks with:

```bash
PYTHONPATH=. python3 -m unittest \
  tests.tier1_feature.test_capture_calibration \
  tests.tier5_adversarial.test_m2_c2_activation_ssm.TestM2C2ActivationSSM.test_firmware_version_mismatch_adversarial -v
```

The original v1.0.1 bootstrap remains pinned to its original archive.
Re-running it does not obtain this hotfix; use the v1.0.2 bootstrap or the
corrected checkout. No fingerprint images or enrolled templates are included.
