# Tools

Helper scripts for extracting the hardware sensor key.

- `dump_dpapi_blob.py`: Reads the locked key file from the sensor over USB in Linux.
- `decrypt_psk.ps1`: Unlocks the key file in Windows and writes `goodix-5e0a.psk`.

For step-by-step instructions on dual boot and single boot setups, see [docs/psk-extraction.md](../docs/psk-extraction.md).
