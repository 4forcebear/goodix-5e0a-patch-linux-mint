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
except ImportError as e:
    print(f"ERROR: Failed to import Goodix protocol helpers: {e}", file=sys.stderr)
    sys.exit(1)


def main():
    out_dir = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)
    hash_path = out_dir / "mcu_hash.txt"
    blob_path = out_dir / "dpapi_blob.bin"

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
        if reply and reply[0]:
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
        reply = device.preset_psk_read(0xbb010002, 256, 0)
        if reply and reply[0]:
            sealed_blob = reply[2]
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
        print(f"  1. Copy {blob_path.name} and {hash_path.name} to Windows (via USB drive or dual boot).")
        print("  2. In Windows PowerShell as Administrator, run:")
        print("     powershell -ExecutionPolicy Bypass -File .\\tools\\decrypt_psk.ps1")
        print("  3. Copy the resulting goodix-5e0a.psk to /etc/libfprint/goodix-5e0a.psk on Linux:")
        print("     sudo cp goodix-5e0a.psk /etc/libfprint/goodix-5e0a.psk")
        print("     sudo chmod 600 /etc/libfprint/goodix-5e0a.psk")
        print("  See docs/psk-extraction.md for full instructions.")
    else:
        print("Extraction failed: could not read the locked key from the sensor.")
    print("=" * 65)


if __name__ == "__main__":
    main()
