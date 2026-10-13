# Goodix 27c6:5e0a Linux driver

Linux fingerprint driver for Goodix 27c6:5e0a sensors, found in laptops like the Realme Book Prime.

Runs as a libfprint module. It loads Goodix's Windows engine, `GoodixEngineAdapter.dll`, inside the process via a PE loader. This proprietary dependency prevents upstreaming.

## Installation

Run `install.sh` for all distributions except NixOS. See `./install.sh --help` for custom DLL paths or uninstalling.

```bash
git clone https://github.com/jitendradara12/goodix-5e0a.git
cd goodix-5e0a
./install.sh
sudo systemctl restart fprintd
./install.sh --integrate
fprintd-enroll
fprintd-verify
```

### SELinux on Fedora and RHEL

Install the policy module before running fprintd:

```bash
cd packaging/selinux
checkmodule -M -m -o goodix-engine.mod goodix-engine.te
semodule_package -o goodix-engine.pp -m goodix-engine.mod
sudo semodule -i goodix-engine.pp
```

### PAM login setup

Logging in requires the PAM module.

- Ubuntu and Debian: install `libpam-fprintd`, run `sudo pam-auth-update`, and enable fingerprint authentication.
- Fedora and RHEL: run `./install.sh --integrate` to enable `with-fingerprint` via authselect and apply the SELinux policy module.
- Arch: add `pam_fprintd.so` to `/etc/pam.d/system-local-login` and `/etc/pam.d/sudo`.

### Sensor encryption key

The sensor encrypts communications with a key stored in hardware. The driver includes a default key from the developer machine, but many laptops generate their own unique key during factory or Windows setup.

If `fprintd-enroll` fails with `enroll-unknown-error` and `journalctl -u fprintd` shows a bad record MAC error, extract your laptop key:

1. In Linux, stop the service and read the locked key file from the sensor:
   ```bash
   sudo systemctl stop fprintd
   sudo python3 tools/dump_dpapi_blob.py
   ```

2. Copy the resulting `dpapi_blob.bin`, `mcu_hash.txt`, and `tools/decrypt_psk.ps1` to Windows (using a USB drive or dual boot).

3. In Windows, open PowerShell as Administrator and unlock the key:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\decrypt_psk.ps1
   ```

4. Copy the generated `goodix-5e0a.psk` back to Linux:
   ```bash
   sudo mkdir -p /etc/libfprint
   sudo cp goodix-5e0a.psk /etc/libfprint/goodix-5e0a.psk
   sudo chmod 600 /etc/libfprint/goodix-5e0a.psk
   sudo systemctl restart fprintd
   ```

See [docs/psk-extraction.md](docs/psk-extraction.md) for full instructions, partition mounting notes, and Linux-only setup.

## NixOS

Add the repository to your flake inputs and import the module:

```nix
inputs.goodix.url = "github:jitendradara12/goodix-5e0a";

# configuration.nix
imports = [ inputs.goodix.nixosModules.default ];
services.fprintd.goodix.pamServices = true;
```

Set `services.fprintd.goodix.dllFile = ./path/to/dll;` to supply a custom engine DLL.

## Development

Run tests with `bash tests/run_all_tests.sh`. The sensor is not required.

## Known limits

- Units with a custom hardware PSK require the extraction steps above before the sensor completes the TLS handshake.
- Keep password login enabled as a fallback.

## License

Driver code is LGPL-2.1-or-later. See [LICENSE](LICENSE).

`windows_driver/GoodixEngineAdapter.dll` is a proprietary Goodix binary included for research.
