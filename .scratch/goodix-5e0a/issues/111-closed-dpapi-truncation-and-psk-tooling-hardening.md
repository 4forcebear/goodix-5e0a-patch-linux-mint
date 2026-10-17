# 111 — Fix DPAPI blob truncation, PowerShell 5.1 elevation, and harden PSK extraction tooling (Issue #12)

**What was built:**
1. Fixed DPAPI blob truncation in `tools/dump_dpapi_blob.py`: modern Windows DPAPI blobs are 324 bytes, and sensor firmware rejects requests > 400 bytes. The dumper now requests 400 bytes, parses the Windows DPAPI structure accurately (accounting for `dwSignAlgo`, `dwSignAlgoLen`, `dwSignSaltLen`, `pbSignSalt`, `dwDataLen`, `pbData`, `dwSignLen`, `pbSign`), trims trailing buffer padding down to exact structure length, and supports offset chunk reading fallback. Tested and verified against real Windows 11 hardware DPAPI dumps (`legacy-experiments/dpapi_full.bin`).
2. Fixed `tools/decrypt_psk.ps1` on Windows PowerShell 5.1 under non-English (e.g. German) locales: wrapped `schtasks /create` error action preference to prevent terminating `NativeCommandError` on stderr warnings, extended scheduled task polling loop to 20 seconds, added SYSTEM task logging (`system-log.txt`) for transparent failure diagnostics, and implemented matching DPAPI structure length validation and padding trimming without falsely rejecting valid 324-byte payloads.
3. Preserved driver cleanliness without band-aids: rejected runtime environment variable overrides (`GOODIX_5E0A_CONTRAST_GAIN`) and driver-level debug file dumping (`GOODIX_5E0A_DUMP_DIR`) in production libfprint C driver code. Hardware diagnostics and raw frame captures are handled cleanly via standalone Python tools (`legacy-experiments/capture_live_burst.py`). Production driver adheres strictly to `AGENTS.md` (canonical 64x80 raster, 3x3 local-mean residual normalization, midpoint 128, gain 1.5, 12 enrollment touches).
4. Added comprehensive test coverage in `tests/tier1_feature/test_f111_dpapi_and_diagnostics.py` (6/6 passing).

**Blocked by:** None.

**Status:** closed

**Verdict:** Closed (software-complete, test suite green). Resolves the concrete bugs in PSK extraction tooling and enforces driver cleanliness invariants.
