#!/usr/bin/env python3
"""Goodix 27c6:5e0a DPAPI Blob & MCU Hash Dumper (Linux).

This read-only utility reads:
  1. Slot 0xbb020001: The SHA-256 hash of the MCU operational PSK (saved to mcu_hash.txt)
  2. Slot 0xbb010002: The Windows DPAPI-sealed PSK blob (saved to dpapi_blob.bin)

Neither read modifies device state or hardware configuration.

Prerequisites:
  sudo systemctl stop fprintd
  Ensure USB access permissions (run with sudo or add udev rules)
  Python module 'pyusb' (sudo apt install python3-usb / pip install pyusb)

Output files:
  dpapi_blob.bin - Encrypted DPAPI payload to be decrypted in Windows.
  mcu_hash.txt   - Expected SHA-256 hash for verification.
"""

import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "legacy-experiments"))
sys.path.insert(0, str(repo_root / "legacy-experiments" / "vendor"))

def check_usb_deps():
    try:
        import usb.core
    except ImportError:
        print("ERROR: python package 'pyusb' is required.", file=sys.stderr)
        print("Install it with:", file=sys.stderr)
        print("  Fedora/RHEL:   sudo dnf install python3-pyusb", file=sys.stderr)
        print("  Debian/Ubuntu: sudo apt install python3-usb", file=sys.stderr)
        print("  Arch Linux:    sudo pacman -S python-pyusb", file=sys.stderr)
        print("  Pip fallback:  pip install pyusb", file=sys.stderr)
        sys.exit(1)

    try:
        import goodix_protocol
        sys.modules["protocol"] = goodix_protocol
        import goodix
        return goodix, goodix_protocol
    except ImportError as e:
        print(f"ERROR: Failed to import Goodix protocol helpers: {e}", file=sys.stderr)
        sys.exit(1)

import struct


def parse_dpapi_blob_length(data: bytes) -> tuple[int | None, bool]:
    """Parse Windows DPAPI blob header and calculate its total expected length.

    A standard Windows DPAPI blob structure:
      dwVersion (4), guidProvider (16), dwMasterKeyVersion (4),
      guidMasterKey (16), dwFlags (4), dwDescriptionLen (4), szDescription (var),
      dwCryptAlgo (4), dwCryptAlgoLen (4), dwSaltLen (4), pbSalt (var),
      dwPromptLen (4), pbPrompt (var),
      dwSignAlgo (4), dwSignAlgoLen (4), dwSignSaltLen (4), pbSignSalt (var),
      dwDataLen (4), pbData (var),
      dwSignLen (4), pbSign (var).

    Returns (expected_length, is_complete).
    """
    if len(data) < 48:
        return None, False
    try:
        desc_len = struct.unpack_from("<I", data, 44)[0]
        pos = 48 + desc_len
        if len(data) < pos + 12:
            return None, False
        algo, algo_len, salt_len = struct.unpack_from("<III", data, pos)
        pos += 12 + salt_len
        if len(data) < pos + 4:
            return None, False
        prompt_len = struct.unpack_from("<I", data, pos)[0]
        pos += 4 + prompt_len
        if len(data) < pos + 12:
            return None, False
        sign_algo, sign_algo_len, sign_salt_len = struct.unpack_from("<III", data, pos)
        pos += 12 + sign_salt_len
        if len(data) < pos + 4:
            return None, False
        data_len = struct.unpack_from("<I", data, pos)[0]
        pos += 4 + data_len
        sign_bytes = sign_algo_len // 8 if sign_algo_len else 64
        total_exp = pos + 4 + sign_bytes
        if len(data) < pos + 4:
            # pbData is complete, but dwSignLen and pbSign are truncated.
            return total_exp, False
        sign_len = struct.unpack_from("<I", data, pos)[0]
        pos += 4 + sign_len
        return pos, len(data) >= pos
    except Exception:
        return None, False



def read_dpapi_blob(device) -> bytes | None:
    """Read the Windows DPAPI blob from sensor slot 0xbb010002.

    The sensor firmware accepts reads up to ~400 bytes (larger reads like 512/1024 are rejected).
    Modern Windows DPAPI blobs are typically 324 bytes. We read up to 400 bytes,
    parse the DPAPI structure length, and trim any trailing buffer padding.
    If 400 fails, we retry with 256 bytes and fetch remaining chunks if needed.
    """
    blob = bytearray()
    for try_len in [400, 256]:
        try:
            reply = device.preset_psk_read(0xbb010002, try_len, 0)
            if reply and reply[0] and reply[2]:
                blob = bytearray(reply[2])
                print(f"[+] Read slot 0xbb010002: {len(blob)} bytes (requested {try_len})")
                break
        except Exception:
            continue

    if not blob:
        return None

    expected_len, is_complete = parse_dpapi_blob_length(blob)
    if expected_len is None:
        print("[-] Invalid DPAPI blob header (could not determine structure length).")
        return None

    if is_complete:
        if len(blob) > expected_len:
            print(f"[+] Trimming DPAPI blob from {len(blob)} to exact structure length {expected_len} bytes")
            blob = blob[:expected_len]
        else:
            print(f"[+] Validated complete DPAPI blob: {len(blob)} bytes")
        return bytes(blob)

    needed = expected_len - len(blob)
    print(f"[*] Blob truncated ({len(blob)} of {expected_len} bytes); fetching remaining {needed} bytes at offset {len(blob)}...")
    try:
        reply = device.preset_psk_read(0xbb010002, needed, len(blob))
        if reply and reply[0] and reply[2]:
            blob.extend(reply[2])
            print(f"[+] Successfully fetched chunk; total size is now {len(blob)} bytes")
            exp2, comp2 = parse_dpapi_blob_length(blob)
            if exp2 and comp2 and exp2 == expected_len:
                return bytes(blob[:exp2])
    except Exception as e:
        print(f"[-] Could not read remaining bytes with offset: {e}")

    print(f"[-] Incomplete DPAPI blob ({len(blob)} of {expected_len} bytes).")
    return None


def main():
    goodix, goodix_protocol = check_usb_deps()
    out_dir = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)
    hash_path = out_dir / "mcu_hash.txt"
    blob_path = out_dir / "dpapi_blob.bin"

    # Pre-flight removal of stale output files
    if hash_path.exists():
        hash_path.unlink()
    if blob_path.exists():
        blob_path.unlink()

    print("=" * 65)
    print("Goodix 27c6:5e0a Key Extractor")
    print(f"Output directory: {out_dir}")
    print("=" * 65)

    try:
        device = goodix.Device(0x5e0a, goodix_protocol.USBProtocol)
    except Exception as e:
        print(f"ERROR: Cannot open Goodix 27c6:5e0a USB device: {e}")
        print("Stop fprintd (sudo systemctl stop fprintd) and run as root.")
        sys.exit(1)

    try:
        device.nop()
        print("[+] Device communication verified (NOP OK)")
    except Exception as e:
        print(f"[-] NOP command failed: {e}")
        sys.exit(1)

    try:
        fw_data = device.firmware_version()
        fw_ver = fw_data.decode("ascii", errors="ignore").rstrip("\x00")
        print(f"[+] Firmware version: {fw_ver}")
    except Exception as e:
        print(f"[-] Could not read firmware version: {e}")

    # Read sensor key hash
    mcu_hash = None
    try:
        reply = device.preset_psk_read(0xbb020001, 32, 0)
        if reply and reply[0] and reply[2]:
            mcu_hash = reply[2]
            hash_hex = mcu_hash.hex()
            print(f"[+] Sensor key hash: {hash_hex}")
            hash_path.write_text(hash_hex + "\n")
            print(f"    -> Saved to {hash_path}")
        else:
            print("[-] Sensor returned error reading key hash")
    except Exception as e:
        print(f"[-] Exception reading key hash: {e}")

    # Read locked key file
    sealed_blob = None
    try:
        sealed_blob = read_dpapi_blob(device)
        if sealed_blob:
            print(f"[+] Locked sensor key: {len(sealed_blob)} bytes read")
            blob_path.write_bytes(sealed_blob)
            print(f"    -> Saved to {blob_path}")
        else:
            print("[-] Sensor returned error reading locked key")
    except Exception as e:
        print(f"[-] Exception reading locked key: {e}")

    print("\n" + "=" * 65)
    if sealed_blob:
        print("Extraction complete. Next steps:")
        if hash_path.exists():
            print(f"  1. Copy {blob_path.name} and {hash_path.name} to Windows (via USB drive or dual boot).")
        else:
            print(f"  1. Copy {blob_path.name} to Windows (via USB drive or dual boot).")
        print("  2. In Windows PowerShell as Administrator, run:")
        print("     powershell -ExecutionPolicy Bypass -File .\\tools\\decrypt_psk.ps1")
        print("  3. Copy the resulting goodix-5e0a.psk to /etc/libfprint/goodix-5e0a.psk on Linux:")
        print("     sudo cp goodix-5e0a.psk /etc/libfprint/goodix-5e0a.psk")
        print("     sudo chmod 600 /etc/libfprint/goodix-5e0a.psk")
        print("  See docs/psk-extraction.md for full instructions.")
    else:
        print("Extraction failed: could not read a valid locked key blob from the sensor.")
        sys.exit(1)
    print("=" * 65)


if __name__ == "__main__":
    main()
