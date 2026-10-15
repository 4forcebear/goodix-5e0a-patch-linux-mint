# Extracting Your Sensor Key (PSK)

When Windows sets up the sensor for the first time, it locks the hardware with a unique key. If your laptop uses its own key, enrollment fails with `enroll-unknown-error` (`bad record MAC` in the logs).

You only need to extract this key once. **Back up the final `goodix-5e0a.psk` file to Google Drive or somewhere safe**—if you distrohop or wipe Linux later, you can drop that same file back in without ever booting Windows again.

---

## Dual-Boot Laptops (Windows Installed)

### 1. Dump the locked key in Linux

Stop the fingerprint service and read the locked key from the sensor:

```bash
sudo systemctl stop fprintd
sudo python3 tools/dump_dpapi_blob.py
```

This creates `dpapi_blob.bin` and `mcu_hash.txt` in your current directory.

### 2. Move the files to Windows

Copy these three files to Windows (via a USB drive, cloud storage, or a mounted partition):
- `dpapi_blob.bin`
- `mcu_hash.txt`
- `tools/decrypt_psk.ps1`

### 3. Unlock the key in Windows

1. Boot into Windows.
2. Open **PowerShell as Administrator**.
3. Go to the folder containing the three files:
   ```powershell
   cd "$HOME\Downloads"
   ```
4. Run the unlock script:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\decrypt_psk.ps1
   ```

This writes `goodix-5e0a.psk` to the same folder. **Upload a copy of `goodix-5e0a.psk` to Google Drive now** so you don't lose it the next time you switch distros.

### 4. Install the key in Linux

Boot into Linux and install the key:

```bash
sudo mkdir -p /etc/libfprint
sudo cp goodix-5e0a.psk /etc/libfprint/goodix-5e0a.psk
sudo chown root:root /etc/libfprint/goodix-5e0a.psk
sudo chmod 600 /etc/libfprint/goodix-5e0a.psk
sudo systemctl restart fprintd
```

Test enrollment:

```bash
fprintd-enroll
```

---

## Linux-Only Laptops (No Windows Installed)

If you wiped Windows from your drive, the decryption keys on disk are gone. Virtual machines (QEMU/VirtualBox) will not work because the key is tied to Windows running on your laptop's physical hardware.

You need a temporary **Windows To Go** USB drive to generate and extract a fresh key:

1. Use **Rufus** on another computer to flash a Windows 10 or 11 ISO onto a USB drive in **Windows To Go** mode.
2. Download the official Windows Goodix fingerprint driver from your laptop manufacturer's website and put the installer on the USB drive.
3. Boot your laptop from the Windows To Go USB drive.
4. Install the fingerprint driver. Once installed, Windows pairs with the sensor and writes a fresh key to the hardware.
5. Reboot into Linux and dump the new locked key:
   ```bash
   sudo systemctl stop fprintd
   sudo python3 tools/dump_dpapi_blob.py
   ```
6. Copy `dpapi_blob.bin`, `mcu_hash.txt`, and `tools/decrypt_psk.ps1` to the USB drive.
7. Boot back into the Windows To Go USB, open **PowerShell as Administrator**, and run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\decrypt_psk.ps1
   ```
8. Copy the generated `goodix-5e0a.psk` to Linux, **back it up to Google Drive**, and install it using [Step 4](#4-install-the-key-in-linux) above.

---

## Troubleshooting

- **PowerShell blocks the script or says Access Denied:** Make sure you opened PowerShell via **Run as Administrator** and included `-ExecutionPolicy Bypass`.
- **Hash mismatch warning:** Re-run the PowerShell script with `-Force` to save the key anyway:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\decrypt_psk.ps1 -Force
  ```
- **Permission denied in Linux:** Ensure `/etc/libfprint/goodix-5e0a.psk` is owned by `root:root` with `600` permissions (see Step 4).
