#!/usr/bin/env python3
"""Ticket 79 Step 0: capture one real 4-frame live burst as P2 12-bit PGM.

Same wire path as legacy-experiments/test_press_and_capture.py, but captures
GOODIX_5E0A_FRAMES_PER_TOUCH consecutive mcu_get_image frames during a single
hold (no release between frames) and saves each via tool.write_pgm(decoded,
80, 64, path) — byte-layout identical to legacy-experiments/fingerprint.pgm
(header "P2 / 64 80 / 4095", row-major 12-bit pixels).

User runs TWICE (agent has no fingers/sudo):
  1x deliberate firm press  -> --out-prefix legacy-experiments/live_burst_press
  1x casual light tap       -> --out-prefix legacy-experiments/live_burst_tap
Each run writes <prefix>_01.pgm .. <prefix>_04.pgm. Paste the full command +
output back; the ticket-79 probe then measures per-frame residual_range.

Hardware preconditions (AGENTS.md): stop fprintd first (else Resource busy),
run from repo root:
  PYTHONPATH=/home/sastauser/code/temp/goodix nix-shell -p python3Packages.pyusb openssl \\
    --run "python3 legacy-experiments/capture_live_burst.py --out-prefix legacy-experiments/live_burst_press"
"""
from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import time
from pathlib import Path

import goodix_protocol

sys.modules["protocol"] = goodix_protocol
vendor_dir = Path(__file__).resolve().parent / "vendor"
if vendor_dir.exists():
    sys.path.insert(0, str(vendor_dir))
try:
    import goodix  # noqa: E402
    import tool  # noqa: E402
except ImportError:
    goodix = None
    tool = None

DEFAULT_PSK = bytes.fromhex("d853ad1941b2dc5350c766cd726ef7a5df7d5fa39053bfac269ce752d7a8b2ab")


def resolve_psk(psk_arg: str | None = None) -> bytes:
    """Resolve TLS pre-shared key: explicit argument, /etc/libfprint/goodix-5e0a.psk, or default dev unit key."""
    if psk_arg:
        p = Path(psk_arg)
        if p.is_file():
            return bytes.fromhex(p.read_text(encoding="utf-8").strip())
        if "/" in psk_arg or "\\" in psk_arg:
            raise FileNotFoundError(f"PSK file not found: {psk_arg}")
        return bytes.fromhex(psk_arg.strip())
    system_psk = Path("/etc/libfprint/goodix-5e0a.psk")
    if system_psk.is_file():
        try:
            return bytes.fromhex(system_psk.read_text(encoding="utf-8").strip())
        except Exception as e:
            print(f"[-] Warning: Failed to read {system_psk}: {e}", file=sys.stderr)
    return DEFAULT_PSK
CONFIG_52XD = bytes.fromhex(
    "701160712c9d2cc91ce518fd00fd00fd03ba000180ca0008008400bec38600b1"
    "b68800baba8a00b3b38c00bcbc8e00b1b19000bbbb9200b1b194000000960000"
    "00980000009a000000d2000000d4000000d6000000d800000050000105d00000"
    "00700000007200785674003412200010402a0102042200012024003200800001"
    "005c000101560024205800010232000402660000027c00005882007f082a0182"
    "072200012024001400800001405c00ea00560006145800040232000c02660000"
    "027c000058820080082a0108005c000101540000016200080464001000660000"
    "027c0000582a0108005c00e8005200080054000001660000027c00005820c50e"
)

N_FRAMES = 4


WIDTH = 64
HEIGHT = 80
BLOCKS = 80
BLOCK_BYTES = 132
ACTIVE_BYTES = 96
WIRE_BYTES = BLOCKS * BLOCK_BYTES + 4  # 10564


def unpack_12bit(data: bytes) -> list[int]:
    pixels: list[int] = []
    for offset in range(0, len(data), 6):
        chunk = data[offset : offset + 6]
        if len(chunk) < 6:
            break
        pixels.extend(
            [
                ((chunk[0] & 0x0F) << 8) | chunk[1],
                (chunk[3] << 4) | (chunk[0] >> 4),
                ((chunk[5] & 0x0F) << 8) | chunk[2],
                (chunk[4] << 4) | (chunk[5] >> 4),
            ]
        )
    return pixels


def decode_canonical_frame(frame: bytes) -> list[int]:
    packed = bytearray()
    for block in range(BLOCKS):
        start = block * BLOCK_BYTES
        packed.extend(frame[start : start + ACTIVE_BYTES])
    return unpack_12bit(bytes(packed))


def write_canonical_pgm(path: str, pixels: list[int]) -> None:
    lines = ["P2", f"{WIDTH} {HEIGHT}", "4095"]
    lines.extend(str(value) for value in pixels)
    with open(path, "w", encoding="ascii") as f:
        f.write("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-prefix", required=True,
                    help="e.g. legacy-experiments/live_burst_press")
    ap.add_argument("--frames", type=int, default=N_FRAMES)
    ap.add_argument("--port", type=int, default=4433)
    ap.add_argument("--psk", default=None,
                    help="Hex PSK or path to PSK file (default: /etc/libfprint/goodix-5e0a.psk if present, else dev key)")
    args = ap.parse_args()

    if goodix is None or tool is None:
        print("ERROR: Missing goodix protocol helpers or pyusb. Please run under nix-shell as documented in header.", file=sys.stderr)
        return 1

    psk = resolve_psk(args.psk)

    tls_server = subprocess.Popen(
        ["openssl", "s_server", "-nocert", "-psk", psk.hex(),
         "-cipher", "PSK-AES128-CBC-SHA256", "-tls1_2",
         "-port", str(args.port), "-quiet"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(0.5)
    # Fail fast on a busy/dead port instead of hanging in connect/read:
    # never pkill -f a pattern containing our own command text (self-match
    # hangs) — list with `pgrep -af s_server`, kill stale PIDs, or retry with
    # a fresh --port. Verify with `ss -tlnp | grep <port>`.
    if tls_server.poll() is not None:
        print(f"FATAL: openssl s_server exited immediately (code "
              f"{tls_server.returncode}); port {args.port} busy or openssl "
              f"missing. Kill stale `s_server` PIDs (pgrep -af s_server) or "
              f"retry with --port <fresh>.", file=sys.stderr)
        return 2

    try:
        device = goodix.Device(0x5E0A, goodix_protocol.USBProtocol)
        device.nop()
        device.reset(True, False, 20)
        device.read_sensor_register(0x0000, 4)
        device.read_otp()

        tls_client = socket.socket()
        tls_client.connect(("localhost", args.port))
        try:
            tool.connect_device(device, tls_client)
            device.tls_successfully_established()
            device.upload_config_mcu(CONFIG_52XD)
            device.enable_chip(True)
            device.write_sensor_register(0x022C, b"\x05\x03")

            print("=" * 60)
            print(">>> PLACE FINGER AND HOLD STEADY — capturing %d frames <<<"
                  % args.frames)
            print("Do NOT lift between frames (one burst, one hold).")
            print("=" * 60)
            for i in range(5, 0, -1):
                print(f"  {i}...")
                time.sleep(1.0)
            print(">>> CAPTURING NOW — HOLD STEADY <<<")
            for n in range(1, args.frames + 1):
                img_req = device.mcu_get_image(
                    b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                    goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)
                tls_client.sendall(img_req[9:])
                time.sleep(0.15)
                dec = tls_server.stdout.read(WIRE_BYTES)
                print(f"frame {n}: encrypted={len(img_req)} decrypted={len(dec)}")
                if len(dec) != WIRE_BYTES:
                    print(f"frame {n}: SHORT READ ({len(dec)} != {WIRE_BYTES}) — "
                          f"not saving; hold stiller and re-run.",
                          file=sys.stderr)
                    continue
                pixels = decode_canonical_frame(dec)
                active = sum(1 for p in pixels if p > 30)
                print(f"frame {n}: pixels={len(pixels)} "
                      f"min={min(pixels)} max={max(pixels)} "
                      f"avg={sum(pixels)/len(pixels):.1f} active(>30)={active}")
                out = f"{args.out_prefix}_{n:02d}.pgm"
                write_canonical_pgm(out, pixels)
                print(f"frame {n}: saved {out}")
            print(">>> BURST DONE — you may lift <<<")
        finally:
            tls_client.close()
    finally:
        # Reap s_server so a timeout-killed run never leaves it holding the
        # port for the next attempt (AGENTS.md: verify ports with ss -tlnp).
        tls_server.terminate()
        try:
            tls_server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tls_server.kill()
            tls_server.wait(timeout=5)
        if tls_server.stdout:
            tls_server.stdout.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
