#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
installer="$script_dir/install.sh"
prefix=/opt/goodix-libfprint
dropin=/etc/systemd/system/fprintd.service.d/90-goodix.conf
check_only=false

usage() {
    echo "Usage: $0 [--check]"
    echo '--check: verify the owned installation and removal preconditions without removing anything.'
}

[[ -x "$installer" ]] || { echo "ERROR: installer not found or not executable: $installer" >&2; exit 1; }

case "${1:-}" in
    --check)
        [[ $# == 1 ]] || { usage >&2; exit 2; }
        check_only=true
        ;;
    '') ;;
    *) usage >&2; exit 2 ;;
esac

has_prefix=false
has_dropin=false
[[ -e "$prefix" || -L "$prefix" ]] && has_prefix=true
[[ -e "$dropin" || -L "$dropin" ]] && has_dropin=true

if [[ $has_prefix == false && $has_dropin == false ]]; then
    unit_env=$(systemctl show fprintd.service -p Environment --value 2>/dev/null || true)
    if [[ $unit_env == *"LD_LIBRARY_PATH=$prefix/lib"* || \
          $unit_env == *"GOODIX_ENGINE_DLL_PATH=$prefix/GoodixEngineAdapter.dll"* ]]; then
        echo '[FAIL] private files are absent, but the effective fprintd unit still references their paths.' >&2
        echo 'Review the systemd configuration manually; no files were changed.' >&2
        exit 1
    fi
    echo '[OK] no private Goodix installation or owned drop-in is present; nothing to remove.'
    exit 0
fi

# Verify before asking sudo to remove anything. install.sh checks ownership
# markers again inside the privileged transaction, then checks removal results.
"$installer" --verify-install
if [[ $check_only == true ]]; then
    echo 'Uninstall preflight passed. No files were changed.'
    exit 0
fi

"$installer" --uninstall

if [[ -e "$prefix" || -L "$prefix" ]]; then
    echo "ERROR: private driver path remains after uninstall: $prefix" >&2
    exit 1
fi
if [[ -e "$dropin" || -L "$dropin" ]]; then
    echo "ERROR: Goodix drop-in remains after uninstall: $dropin" >&2
    exit 1
fi

echo 'Uninstall checks passed. Fingerprint templates, PAM configuration, and distro packages were not removed.'
