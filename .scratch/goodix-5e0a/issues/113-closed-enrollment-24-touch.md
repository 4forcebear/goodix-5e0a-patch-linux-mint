# 113: Expand Milan Enrollment to 24 Touches

**Status:** closed (24-touch enrollment and repeated direct matches confirmed on hardware)

## Question

Do additional enrollment touches improve genuine verification reliability on the 5e0a sensor?

## Change

- The 16-touch run below produced two matches from three controlled direct verifies, but is not reliable enough to confirm.
- An isolated no-hardware SDK probe initialized `m_enrolStartEx` with a requested capacity of 24. The SDK returned `max_images=24` and created an enrollment context. This confirms context creation at 24 only; it does not confirm 24 accepted samples or a usable template.
- Set the single `GOODIX_MILAN_ENROLL_TOUCHES` constant to 24. This drives both the SDK's target count (`ctx+8`) and libfprint's enrollment stages.
- Keep the vendor matching decision and threshold unchanged.
- User enrollment should cover center, edges, tip, and sides across the 24 separate contacts.

## Predicted hardware outcomes

- **Confirm:** 24/24 accepted touches, template committed, then repeated right-index verifies produce positive vendor match scores and the Cinnamon unlock accepts the fingerprint.
- **Falsify:** enrollment reaches 24/24 but controlled verifies still return `match=0 pts=0`; touch count alone does not address the current template/capture mismatch.
- **Inconclusive:** enrollment does not complete cleanly, or the verification contacts do not use the enrolled right index finger.

## Safety and scope

- This experiment changes enrollment coverage only. It does not change frame normalization, Milan matching logic, score threshold, PAM fallback, or the existing password login.
- Re-enrollment replaces the current right-index template and is required for the new count to take effect.

## Hardware Run (2026-10-20)

- Build completed and installed under `/opt/goodix-libfprint`; the previous 12-touch library is preserved at `/opt/goodix-libfprint.backup-20261020-enroll12`.
- Milan engine loaded as `Milan_v_3.02.00.20`; enrollment committed at 16/16 and `fprintd-list` shows the right index finger.
- Direct verification: 2 matches from the first 3 controlled tries (`pts=71`, `pts=77`), then one no-match. The failed capture had `quality=31`, `overlap=99`, while the successful second capture had `quality=10`, `overlap=74`; the image quality proxy does not explain matcher acceptance.
- Verdict for 16: two of three direct tries matched, so reliability remains unconfirmed. The prior belief that SDK capacity was capped at 16 was disproven by the isolated 24-capacity context probe; full 24-stage hardware behavior is the next experiment.
- Follow-up diagnostic adds journal-only `identifyImage` result/index/raw score/details, template length, quality/overlap, and a truncated SHA-256 of each normalized probe. It does not save or log biometric pixels and does not change the vendor match decision.

## 24-Touch Follow-up (2026-10-20)

- Changed `GOODIX_MILAN_ENROLL_TOUCHES` to 24. This sets both the SDK target and libfprint stage count.
- `./install.sh --no-deps --build-only /tmp/goodix-5e0a-enroll24-stage-20261020` completed successfully; staged library SHA-256: `837a2e15ae309761a8a47f9dfbc10b6aae929feea682ed1afca0c1eef8050cc4`.
- Installed reversibly after sudo authorization. The new library is active at `/opt/goodix-libfprint` (SHA-256 `837a2e15ae309761a8a47f9dfbc10b6aae929feea682ed1afca0c1eef8050cc4`); the prior diagnostic 16-touch library is at `/opt/goodix-libfprint.backup-20261020-enroll16-diag` (SHA-256 `cdede8f99c9684cf9c832b1a1df31b08a559d50122179536200c8054e083c06f`).
- Runtime check: `fprintd-list mint` sees the device; journal confirms Milan engine load and TLS readiness, and `/proc/<fprintd-pid>/maps` maps the new `/opt/goodix-libfprint/lib/libfprint-2.so.2.0.0`.
- Before re-enrollment, copied the previous 16-touch right-index template to `/var/lib/fprint/.goodix-backup-20261020-enroll16/right-index-16-touch-template` with root-only directory/file permissions (0700/0600). The active template was then deleted for re-enrollment; the backup remains available for rollback.
- Two 24-touch attempts both stopped accepting at exactly 16 stages. Root cause found in `goodix_milan_enroll_start()`: libfprint target was 24 and `ctx+8` was set to 24, but the input capacity to SDK `m_enrolStartEx()` remained `max_imgs=16`. The SDK therefore kept a 16-image capacity. Some later frames were also correctly rejected by the independent false-touch gate, but this was not the 16-stage ceiling.
- Fixed the SDK request to initialize from `GOODIX_MILAN_ENROLL_TOUCHES` and added a guard that rejects startup if the SDK reports less capacity than requested. Build completed and was installed reversibly at `/opt/goodix-libfprint`; library SHA-256 `3475d73ab4a30cc36c91af8164abd737c3002c2a53b3845fde6d73cec125b020`. The prior 24-stage/16-capacity build is at `/opt/goodix-libfprint.backup-20261020-enroll24-cap16`.
- Runtime smoke check after the swap: fprintd restarts and `fprintd-list mint` sees the sensor and restored right-index template. The 16-touch template remains in the root-only rollback copy and the live store.
- Corrected hardware run completed 24/24 at 00:33:11; `fprintd-list mint` shows right-index-finger. Committed template length is 75,641 bytes.
- Subsequent direct identify checks logged successful `idx=0` matches with raw scores 58, 71, 77, 83, and 90. User reports the result is working well.
- Publication cleanup (2026-10-20): removed the truncated frame SHA-256 from the runtime journal message; the current source logs match diagnostics without a frame-derived hash.
- Verdict: 24-touch enrollment is supported once `m_enrolStartEx()` receives the requested capacity. The previous failures at 16 were caused by passing `max_imgs=16`, not by an SDK ceiling. The active build retains password/PAM behavior and matching thresholds.
