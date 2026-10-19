## Tickets (`.scratch/goodix-5e0a/issues/NN-<status>-*.md`)

- Statuses: `ready-for-agent`, `ready-for-hardware-verify`, `in-progress`,
  `superseded` (+successor), `closed` (+verdict). `verified` requires a
  deployed-driver hardware run.
- The filename carries the status: `NN-<first-word-of-Status>-slug.md`
  (e.g. `26-ready-for-agent-*.md`, `18-closed-*.md`). Change the filename
  in the same edit as the `Status:` header — never one without the other.
  `ls *closed* *superseded*` shows permanent history; `ls *ready-for-agent*
*ready-for-hardware-verify* *in-progress*` shows the live workfront.
- Each experiment states predicted journal signatures per branch (confirm /
  falsify). Supersede, don't delete.

## Verify protocol (every hardware run, exception: when not relevent or already verified)

1. Phase 1, hands off 20s ("hands off" + timestamp): silent vs cycles.
2. Phase 2, press-hold steady 20s ("holding" + timestamp): latency, advances.
3. Conclude only: confirmed / falsified /
   inconclusive-because-[flaw] + the single next experiment.

## Matching & Enrollment Engine

- The driver is committed fully to the Goodix Milan matching engine (`GoodixEngineAdapter.dll` via in-process PE loader `goodix_milan.c`).
- All legacy NBIS / Bozorth3 minutiae counting and fallback heuristics have been stripped.
- Sensor raster is canonical 64x80 with 3x3 smoothing minus an 11x11 background, residual RMS target 80, midpoint 128; only the Milan bridge transposes to the engine’s 80x64 raster.
- Current enrollment target is 24 touches (`*(ctx+8) = 24`, 24 enrollment stages). The corrected SDK-capacity request completed 24/24 enrollment and repeated direct-match checks on hardware; see the closed ticket 113 report.
