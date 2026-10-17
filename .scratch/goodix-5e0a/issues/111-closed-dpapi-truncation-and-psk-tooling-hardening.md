# 111 — Fix DPAPI blob truncation, PowerShell 5.1 elevation, and harden PSK extraction tooling (Issue #12)

**What was built:**
1. Fixed DPAPI blob truncation and hardened error paths in `tools/dump_dpapi_blob.py`: modern Windows DPAPI blobs are 324 bytes, and sensor firmware rejects requests > 400 bytes. The dumper requests 400 bytes (pruned ladder [400, 256]), parses the Windows DPAPI structure accurately (accounting for `dwSignAlgo`, `dwSignAlgoLen`, `dwSignSaltLen`, `pbSignSalt`, `dwDataLen`, `pbData`, `dwSignLen`, `pbSign`), trims trailing buffer padding down to exact structure length, and supports offset chunk reading fallback. Fails closed (returns `None` and exits 1) on corrupt headers, empty responses, zero frames, cursor-repeat chunks (`exp2 == expected_len` enforcement), or incomplete chunks. Added pre-flight cleanup of stale output files. Note: `legacy-experiments/dpapi_full.bin` is a 360-byte synthetic fixture (Ticket 44), verified byte-exact against real DPAPI decodes.
2. Hardened `tools/decrypt_psk.ps1`: pre-flight removal of stale `$ResolvedOutput` to prevent immediate false success on prior runs; checks `$LASTEXITCODE` after `schtasks /run` to detect launch failures; enforces 32-byte decrypted payload length (fails closed unless `-Force`); wraps `schtasks /create` error action preference to prevent terminating `NativeCommandError` on stderr warnings under non-English Windows PowerShell 5.1 locales; polls up to 20 seconds; logs SYSTEM task diagnostics to `system-log.txt`; surfaces warnings from SYSTEM log before log cleanup; and warns when hash verification is skipped.
3. Hardened `legacy-experiments/capture_live_burst.py`: added `--psk` command line option and `/etc/libfprint/goodix-5e0a.psk` resolution (falling back to dev unit default key), allowing external users (e.g. Issue #12 reporter) to capture live diagnostic bursts on their own laptops; validated dependencies before launching `s_server` to avoid process leaks on failure.
4. Preserved driver cleanliness without band-aids: rejected runtime environment variable overrides (`GOODIX_5E0A_CONTRAST_GAIN`) and driver-level debug file dumping (`GOODIX_5E0A_DUMP_DIR`) in production libfprint C driver code. Hardware diagnostics and raw frame captures are handled cleanly via standalone Python tools. Production driver adheres strictly to `AGENTS.md` (canonical 64x80 raster, 3x3 local-mean residual normalization, midpoint 128, gain 1.5, 12 enrollment touches).
5. Added comprehensive test coverage in `tests/tier1_feature/test_f111_dpapi_and_diagnostics.py` (9/9 passing).

**Successor:** Ticket 112 (`112-ready-for-agent-issue-12-overlap-zero-verify-investigation.md`) tracks Issue #12's primary symptom (`overlap=0` leading to verify no-match).

**Blocked by:** None.

**Status:** closed

**Verdict:** Closed (software-complete, test suite green). Resolves the concrete bugs in PSK extraction tooling and enforces driver cleanliness invariants.

