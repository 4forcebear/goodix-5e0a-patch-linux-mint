# Goodix 27c6:5e0a Linux Driver

Linux fingerprint driver for Goodix 27c6:5e0a sensors (found in laptops like the Realme Book Prime).

Runs as a libfprint module and loads Goodix's Windows engine (`GoodixEngineAdapter.dll`) via a PE loader.

## Installation

Run `./install.sh` on supported non-NixOS distributions. The repository includes the Windows engine DLL. For other options, see `./install.sh --help`.

### Quick setup: Linux Mint / Ubuntu

This path is for x86_64 systems with a Goodix `27c6:5e0a` sensor. It was
hardware-verified on a Realme Book 14 i5 running Linux Mint. The repository
includes the required `GoodixEngineAdapter.dll`; the installer builds the
private libfprint driver and installs it for `fprintd`.

#### One-command setup

First confirm the system is x86_64 and has the supported sensor:

```bash
uname -m
lsusb -d 27c6:5e0a
```

Run the installer as your normal user, without `sudo`. This command uses the
pinned `v1.0.1` release archive and hands off to the checked installer:

```bash
set -o pipefail
curl -fsSL https://raw.githubusercontent.com/4forcebear/goodix-5e0a-patch-linux-mint/v1.0.1/easy-install.sh | bash
```

For a full checkout instead of the bootstrap:

```bash
git clone --branch v1.0.1 --depth 1 https://github.com/4forcebear/goodix-5e0a-patch-linux-mint.git
cd goodix-5e0a-patch-linux-mint
./install.sh
./install.sh --verify-install
```

The bootstrap requires `curl` and `tar`. To inspect it before running:

```bash
curl -fsSLO https://raw.githubusercontent.com/4forcebear/goodix-5e0a-patch-linux-mint/v1.0.1/easy-install.sh
less easy-install.sh
bash easy-install.sh
```

After installation, restart `fprintd`, then enroll and verify the same finger:

```bash
sudo systemctl restart fprintd
fprintd-enroll -f right-index-finger "$USER"
fprintd-verify -f right-index-finger "$USER"
```

This driver uses 24 accepted enrollment touches. Enable optional PAM only after
enrollment and matching work; keep password authentication enabled as fallback:

```bash
set -o pipefail
curl -fsSL https://raw.githubusercontent.com/4forcebear/goodix-5e0a-patch-linux-mint/v1.0.1/easy-install.sh | bash -s -- --pam
```

This creates a root-only backup of the PAM files, sets three fingerprint
attempts, and keeps the Unix-password fallback. Desktop login, lock screens,
and `sudo` use different PAM stacks; test them separately. An eCryptfs home
may still require the account password at graphical login.

The bootstrap forwards installer options. Its `--uninstall` option uses the
standalone checked uninstaller; `--uninstall --check` runs its read-only
preflight.

For a custom sensor key or a `bad record MAC` error, follow
[PSK extraction](docs/psk-extraction.md).

`./install.sh --check` prints host setup hints. `./install.sh --verify-install`
checks an existing installation without testing the sensor. See
`./install.sh --help` for build-only, custom DLL, and uninstall options.

### Uninstall

Use the standalone script for a checked removal:

```bash
./uninstall.sh --check  # preflight only; makes no changes
./uninstall.sh          # verifies ownership, removes the private driver, then checks removal
```

If no private installation is present, the script reports that there is
nothing to remove. If only part of an installation remains, or the required library or DLL is
missing, it refuses to proceed. It also refuses if the ownership marker or
owned systemd configuration is changed. It preserves fingerprint templates, PAM configuration, and
distribution packages. `./install.sh --uninstall` remains available for
compatibility and applies the same ownership checks.

### Upgrading from an older matching pipeline

Enroll your fingers again after upgrading to the band-pass/native-raster driver.
Old saved prints use incompatible image processing and are rejected. Remove
existing prints with `fprintd-delete "$USER"`, then enroll again. The current
processing is enabled by default; no experiment flag or Windows calibration
export is needed. See [validation and scope](docs/native-raster-validation.md).

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

- Ubuntu and Debian: run ./install.sh --pam for the optional three-attempt fingerprint profile.
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

## Hardware validation

The latest driver revision was verified on a Realme Book 14 i5 with a Goodix
27c6:5e0a sensor: enrollment completed with 24 accepted touches, and later
fingerprint verification returned `verify-match`. The Linux PAM stack also
showed a fingerprint prompt for `sudo`; graphical login may still require the
account password when the home directory is encrypted with eCryptfs.

The latest matching change checks each sufficiently strong frame in a scan
burst with the bundled Milan engine. Contact quality chooses useful frames;
the engine's normal match decision remains authoritative. Per-device OTP
calibration is read during activation and applied to the volatile sensor
configuration. No custom 70% score gate is used.

For installation and testing on another machine, follow the normal
[installation instructions](#installation) and verify both enrollment and
matching with `fprintd-enroll` and `fprintd-verify` before changing PAM setup.
