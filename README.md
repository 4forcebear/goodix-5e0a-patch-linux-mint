# Goodix 27c6:5e0a Linux Driver

Linux fingerprint driver for Goodix 27c6:5e0a sensors (found in laptops like the Realme Book Prime).

Runs as a libfprint module and loads Goodix's Windows engine (`GoodixEngineAdapter.dll`) via a PE loader.

## Install

```bash
git clone https://github.com/jitendradara12/goodix-5e0a.git
cd goodix-5e0a
./install.sh
./install.sh --integrate
sudo systemctl restart fprintd
fprintd-enroll
```

See `./install.sh --help` for custom DLL paths or uninstalling.

### NixOS

```nix
inputs.goodix.url = "github:jitendradara12/goodix-5e0a";

# configuration.nix
imports = [ inputs.goodix.nixosModules.default ];
services.fprintd.goodix.pamServices = true;
```

## Login Setup (PAM)

- **Fedora / RHEL:** Handled automatically by `./install.sh --integrate`.
- **Ubuntu / Debian:** Install `libpam-fprintd` and run `sudo pam-auth-update`.
- **Arch:** Add `pam_fprintd.so` to `/etc/pam.d/system-local-login` and `/etc/pam.d/sudo`.

## Enroll Fails?

Many laptops lock the sensor with a unique hardware key during Windows setup. If `fprintd-enroll` fails with `enroll-unknown-error`, extract your laptop's key using **[docs/psk-extraction.md](docs/psk-extraction.md)**. 

## License

- Driver code: LGPL-2.1-or-later ([LICENSE](LICENSE)).
- `GoodixEngineAdapter.dll`: Proprietary Goodix binary included for research.
