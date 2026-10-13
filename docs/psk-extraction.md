# Extracting your sensor encryption key

Goodix 5e0a sensors encrypt communication using a key stored inside the sensor hardware.

When Windows sets up the sensor for the first time, it generates a unique key for that specific laptop. The driver includes a sample key from the developer machine. If your laptop uses a different key, enrollment fails with `enroll-unknown-error`, and `journalctl -u fprintd` reports a bad record MAC error.

To fix this, extract the key from your laptop once and save it to `/etc/libfprint/goodix-5e0a.psk`.

## How extraction works

The sensor keeps a copy of the key locked with Windows machine security.

1. You run a Linux script to read the locked key file from the sensor over USB.
2. You run a PowerShell script in Windows on the same laptop to unlock the key file.
3. You copy the unlocked key back to Linux.

---

## Dual boot laptops

If Windows is already installed on your laptop, key extraction takes only a few minutes.

### 1. Read the locked key in Linux

Stop the fingerprint daemon and run the extractor:

```bash
sudo systemctl stop fprintd
sudo python3 tools/dump_dpapi_blob.py
```

This creates two files in your current directory:

- `dpapi_blob.bin`
- `mcu_hash.txt`

### 2. Move the files to Windows

- `dpapi_blob.bin`
- `mcu_hash.txt`
- `tools/decrypt_psk.ps1`

You can also mount your Windows partition directly from Linux if your drive is unencrypted:

```bash
sudo mkdir -p /mnt/windows
sudo mount /dev/nvme0n1p3 /mnt/windows
cp dpapi_blob.bin mcu_hash.txt tools/decrypt_psk.ps1 /mnt/windows/Users/<YourUsername>/Downloads/
sudo umount /mnt/windows
```

If Windows has BitLocker or Fast Startup enabled, Linux will not mount the partition cleanly. Use a USB drive (or simply, the internet) instead.

### 3. Unlock the key in Windows

1. Reboot your laptop into Windows.
2. Open the Start menu, search for **PowerShell**, right-click it, and choose **Run as Administrator**.
3. Go to the folder containing your copied files, for example your USB drive or Downloads folder:
   ```powershell
   cd "$HOME\Downloads"
   ```
4. Run the unlock script:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\decrypt_psk.ps1
   ```

The script unlocks the key and writes `goodix-5e0a.psk`.

### 4. Install the key in Linux

1. Reboot back into Linux.
2. Copy `goodix-5e0a.psk` to `/etc/libfprint/`:
   ```bash
   sudo mkdir -p /etc/libfprint
   sudo cp goodix-5e0a.psk /etc/libfprint/goodix-5e0a.psk
   sudo chmod 600 /etc/libfprint/goodix-5e0a.psk
   sudo systemctl restart fprintd
   ```
3. Test enrollment:
   ```bash
   fprintd-enroll
   ```

---

## Linux-only laptops

If you wiped your drive and removed Windows, the original keys on disk were deleted.

Virtual machines like VirtualBox or QEMU will not work. The key is locked to the physical hardware security of Windows running directly on this laptop.

You will need a temporary Windows environment running on bare metal:

1. Use Rufus or Ventoy on another machine to create a bootable **Windows To Go** USB drive with Windows 10 or 11.
2. Download the official Goodix fingerprint driver for your laptop model from the manufacturer website. Put the installer on the USB drive.
3. Boot your laptop from the Windows To Go USB drive.
4. Install the manufacturer fingerprint driver. Once installed, Windows pairs with the sensor and writes a fresh key. Check Windows Settings to verify fingerprint setup appears.
5. Reboot into Linux. Run `sudo python3 tools/dump_dpapi_blob.py` to read the new locked key from the sensor.
6. Copy `dpapi_blob.bin`, `mcu_hash.txt`, and `tools/decrypt_psk.ps1` to the USB drive.
7. Reboot into Windows To Go. Open PowerShell as Administrator, run `decrypt_psk.ps1`, and collect `goodix-5e0a.psk`.
8. Boot back into Linux and install the key to `/etc/libfprint/goodix-5e0a.psk`.

---

## Common issues

### PowerShell blocks script execution

Always include `-ExecutionPolicy Bypass` when running the script:

```powershell
powershell -ExecutionPolicy Bypass -File .\decrypt_psk.ps1
```

### Script reports access denied

Open PowerShell by right-clicking and choosing **Run as Administrator**. Standard user accounts cannot unlock machine security keys.

### Hash mismatch warning

If the script warns that the key hash does not match, re-run with `-Force` to save the key anyway:

```powershell
powershell -ExecutionPolicy Bypass -File .\decrypt_psk.ps1 -Force
```

### Permission denied in Linux

The key file must belong to root:

```bash
sudo chown root:root /etc/libfprint/goodix-5e0a.psk
sudo chmod 600 /etc/libfprint/goodix-5e0a.psk
```
