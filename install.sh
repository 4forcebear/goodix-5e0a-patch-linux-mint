#!/usr/bin/env bash
# Build as your normal user. Only dependencies and the file transaction use sudo.
set -euo pipefail

fail() { echo "ERROR: $*" >&2; return 1; }

# These transactions also run unprivileged against temporary paths in the tests.
# Production calls below use fixed paths, never a caller-supplied install root.
install_files() (
    set -euo pipefail
    local stage=$1 prefix=$2 dropdir=$3 made_prefix=false made_dropdir=false committed=false
    local marker='goodix-5e0a private install v1'
    [[ ! -e "$prefix" && ! -L "$prefix" ]] || { fail "Destination exists: $prefix"; exit 1; }
    [[ ! -e "$dropdir" && ! -L "$dropdir" ]] || { fail "Drop-in directory exists: $dropdir (preserving it)"; exit 1; }
    # shellcheck disable=SC2329 # Invoked by the EXIT trap.
    cleanup_install() {
        if [[ $committed == false ]]; then
            if [[ $made_dropdir == true ]]; then
                rm -f -- "$dropdir/90-goodix.conf"
                rmdir -- "$dropdir" || true
            fi
            if [[ $made_prefix == true ]]; then rm -rf -- "$prefix"; fi
            systemctl daemon-reload || true
        fi
    }
    trap cleanup_install EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    mkdir -m 0755 -- "$prefix"
    made_prefix=true
    mkdir -m 0755 -- "$dropdir"
    made_dropdir=true
    cp -R --no-preserve=ownership -- "$stage/." "$prefix/"
    chmod -R go-w -- "$prefix"
    printf '%s\n' "$marker" > "$prefix/.goodix-install"
    printf '# %s\n[Service]\nEnvironment=LD_LIBRARY_PATH=%s/lib\nEnvironment=GOODIX_ENGINE_DLL_PATH=%s/GoodixEngineAdapter.dll\n' \
        "$marker" "$prefix" "$prefix" > "$dropdir/90-goodix.conf"
    systemctl daemon-reload
    committed=true
)

uninstall_files() (
    set -euo pipefail
    local prefix=$1 dropdir=$2 marker='goodix-5e0a private install v1'
    # Validate both ownership records before removing anything. Never remove prints.
    [[ -d "$prefix" && ! -L "$prefix" && ! -L "$prefix/.goodix-install" ]] || { fail "Not an owned installation: $prefix"; exit 1; }
    [[ -d "$dropdir" && ! -L "$dropdir" && ! -L "$dropdir/90-goodix.conf" ]] || { fail "Not an owned drop-in: $dropdir"; exit 1; }
    printf '%s\n' "$marker" | cmp -s - "$prefix/.goodix-install" || { fail 'Installation marker differs; leaving files alone'; exit 1; }
    printf '# %s\n[Service]\nEnvironment=LD_LIBRARY_PATH=%s/lib\nEnvironment=GOODIX_ENGINE_DLL_PATH=%s/GoodixEngineAdapter.dll\n' \
        "$marker" "$prefix" "$prefix" | cmp -s - "$dropdir/90-goodix.conf" || { fail 'Drop-in differs; leaving files alone'; exit 1; }
    rm -- "$dropdir/90-goodix.conf"
    rmdir -- "$dropdir" 2>/dev/null || true # Preserve any drop-ins added afterwards.
    rm -rf -- "$prefix"
    systemctl daemon-reload
    [[ ! -e "$prefix" && ! -L "$prefix" ]] || { fail "Private install remains after uninstall: $prefix"; exit 1; }
    [[ ! -e "$dropdir/90-goodix.conf" && ! -L "$dropdir/90-goodix.conf" ]] || { fail 'Owned systemd drop-in remains after uninstall'; exit 1; }
)

build_stage() (
    set -euo pipefail
    local tmp=$1 script_dir=$2 dll=$3
    local rev=c343b6934e40dcd40a5f9e3095810d98f1175a4d
    local url=https://github.com/goodix-fp-linux-dev/libfprint
    # Pin the fork to the revision this patch targets; try a shallow fetch first.
    git init "$tmp/libfprint"
    git -C "$tmp/libfprint" remote add origin "$url"
    if ! git -C "$tmp/libfprint" fetch --depth 1 origin "$rev"; then
        rm -rf -- "$tmp/libfprint"
        git clone "$url" "$tmp/libfprint"
    fi
    cd "$tmp/libfprint"
    git checkout "$rev"
    # Upstream integration only; driver sources are copied from the repo
    # checkout (single source of truth, same mechanism as the flake).
    git apply "$script_dir/goodix-5e0a-integration.patch"
    mkdir -p libfprint/drivers/goodixtls
    cp "$script_dir"/libfprint-driver/*.c "$script_dir"/libfprint-driver/*.h libfprint/drivers/goodixtls/
    # fprintd runs as root; no world-writable USB rule or global linker changes.
    meson setup build -Ddrivers=goodixtls5e0a -Dgtk-examples=false -Ddoc=false \
        -Dudev_rules=disabled -Dudev_hwdb=disabled --prefix=/opt/goodix-libfprint --libdir=lib
    ninja -C build
    DESTDIR="$tmp/stage" ninja -C build install
    install -m 0644 -- "$dll" "$tmp/stage/opt/goodix-libfprint/GoodixEngineAdapter.dll"
    test -f "$tmp/stage/opt/goodix-libfprint/lib/libfprint-2.so.2"
)

usage() {
    echo 'Usage: ./install.sh [--no-deps] [--dll FILE] [--build-only DIRECTORY] | --check | --verify-install | --uninstall | --integrate | --pam | --help'
    echo 'Run as your normal user. Default: private /opt install for systemd and root-run fprintd.'
    echo '--no-deps: use installed dependencies on any distro; no package manager calls.'
    echo '--build-only DIRECTORY: build a staging tree without sudo, systemd, or package installation.'
    echo '--check: read-only host setup hints; does not test hardware.'
    echo '--verify-install: verify owned files and effective systemd configuration; no hardware test.'
    echo '--uninstall: remove only an intact, marked private install; preserve templates and distro packages.'
    echo '--pam: opt-in Debian/Ubuntu PAM setup; backs up the stack and sets fingerprint max-tries=3.'
    echo 'Default install does not change PAM; --pam is opt-in. No automatic restart or --no-timeout override. Uninstall preserves prints and distro packages.'
}

integration_hints() {
    if command -v getenforce >/dev/null 2>&1 && [[ $(getenforce 2>/dev/null) == Enforcing ]]; then
        if command -v semodule >/dev/null 2>&1 && semodule -l 2>/dev/null | grep -q "^goodix-engine\b"; then
            echo "SELinux is Enforcing: goodix-engine policy module is active."
        else
            echo "SELinux is Enforcing: the engine loader needs the memfd policy in packaging/selinux/"
            echo '(see packaging/selinux/README.md) or enrollment fails with "failed to load GoodixEngineAdapter.dll".'
            echo 'Run ./install.sh --integrate to install the policy automatically if checkmodule is present.'
        fi
    fi
    local psk_path=/etc/libfprint/goodix-5e0a.psk
    if [[ -f $psk_path ]]; then
        echo "Sensor key: $psk_path is present."
    else
        echo "Sensor key: using fallback key. If fprintd-enroll fails, see docs/psk-extraction.md."
    fi
    if command -v authselect >/dev/null; then
        echo 'Desktop/login setup is separate from driver installation. Keep a password session open.'
        if ! command -v rpm >/dev/null || ! rpm -q fprintd-pam >/dev/null 2>&1; then
            echo 'PAM gap: fprintd-pam is not installed. Fedora/RHEL: sudo dnf install fprintd-pam'
        fi
        if ! authselect current 2>/dev/null | grep -q with-fingerprint; then
            echo 'PAM gap: with-fingerprint is not enabled. Run: ./install.sh --integrate'
        fi
        echo 'Log out/in, then GNOME Settings > Users > Fingerprint Login. Other desktops vary.'
    else
        echo 'Desktop/login setup is separate: install your distro pam_fprintd module and follow its PAM documentation.'
        echo 'Debian/Ubuntu: run ./install.sh --pam to enable fingerprint PAM with three attempts.'
    fi
}

# ponytail: authselect-only on purpose; other distros keep their README steps.
apply_integration() (
    set -euo pipefail
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if command -v getenforce >/dev/null 2>&1 && [[ $(getenforce 2>/dev/null) == Enforcing ]]; then
        if command -v semodule >/dev/null 2>&1 && semodule -l 2>/dev/null | grep -q "^goodix-engine\b"; then
            echo "SELinux: goodix-engine module already installed."
        elif command -v checkmodule >/dev/null 2>&1 && command -v semodule_package >/dev/null 2>&1; then
            echo "Building and installing SELinux policy module..."
            local se_tmp
            se_tmp="$(mktemp -d)"
            checkmodule -M -m -o "$se_tmp/goodix-engine.mod" "$script_dir/packaging/selinux/goodix-engine.te"
            semodule_package -o "$se_tmp/goodix-engine.pp" -m "$se_tmp/goodix-engine.mod"
            sudo semodule -i "$se_tmp/goodix-engine.pp"
            rm -rf -- "$se_tmp"
            echo "Installed SELinux policy goodix-engine."
        else
            echo "SELinux is Enforcing; install checkpolicy to compile packaging/selinux/goodix-engine.te."
        fi
    fi
    command -v authselect >/dev/null || { fail 'authselect not found; wire PAM manually (see README)'; exit 1; }
    if command -v rpm >/dev/null; then
        rpm -q fprintd-pam >/dev/null 2>&1 || { fail 'fprintd-pam is not installed. Fedora/RHEL: sudo dnf install fprintd-pam'; exit 1; }
    fi
    if authselect current 2>/dev/null | grep -q with-fingerprint; then
        echo 'with-fingerprint already enabled.'
    else
        echo 'Keep a password session open while PAM changes apply.'
        sudo authselect enable-feature with-fingerprint
        sudo authselect apply-changes
        echo 'Enabled with-fingerprint. Log out/in, then GNOME Settings > Users > Fingerprint Login.'
    fi
)

apply_pam() (
    set -euo pipefail
    local ID='' ID_LIKE='' backup_dir='' pam_file=/etc/pam.d/common-auth
    # shellcheck disable=SC1091
    if [[ -r /etc/os-release ]]; then . /etc/os-release; fi
    case " $ID $ID_LIKE " in
        *' debian '*|*' ubuntu '*) ;;
        *) fail '--pam currently supports Debian/Ubuntu-based systems only'; exit 1 ;;
    esac
    [[ $EUID != 0 ]] || { fail 'Run ./install.sh --pam as your normal user, without sudo'; exit 1; }
    for tool in sudo dpkg-query pam-auth-update python3; do
        command -v "$tool" >/dev/null || { fail "Required command missing: $tool"; exit 1; }
    done
    [[ -r $pam_file ]] || { fail "PAM file missing: $pam_file"; exit 1; }

    backup_dir="/var/backups/goodix-5e0a-pam-$(date +%Y%m%d-%H%M%S)"
    [[ ! -e $backup_dir ]] || { fail "PAM backup already exists: $backup_dir"; exit 1; }
    sudo install -d -m 0700 "$backup_dir"
    sudo cp -a /etc/pam.d/common-* "$backup_dir/"
    if sudo test -f /var/lib/pam/seen; then
        sudo cp -a /var/lib/pam/seen "$backup_dir/pam-seen"
    fi
    echo "PAM backup saved at $backup_dir"

    if ! dpkg-query -s libpam-fprintd 2>/dev/null | grep -q '^Status: install ok installed$'; then
        sudo apt-get update
        sudo apt-get install -y libpam-fprintd
    fi
    [[ -r /usr/share/pam-configs/fprintd ]] || {
        fail 'libpam-fprintd did not provide the fprintd PAM profile'
        exit 1
    }
    if ! grep -Eq '^[[:space:]]*auth[[:space:]].*pam_fprintd\.so' "$pam_file"; then
        # Never use --force: preserve locally customized PAM stacks.
        sudo env DEBIAN_FRONTEND=noninteractive pam-auth-update --enable fprintd
    fi

    sudo python3 - "$pam_file" <<'PYTHON'
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

path = Path(sys.argv[1])
st = path.stat()
lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
active_auth = [
    i for i, line in enumerate(lines)
    if re.match(r"^[ \t]*auth(?:[ \t]|$)", line)
    and not line.lstrip().startswith("#")
    and "pam_fprintd.so" in line
]
if len(active_auth) != 1:
    raise SystemExit(
        "Expected exactly one active pam_fprintd.so rule in common-auth; "
        "left PAM unchanged. If pam-auth-update declined local edits, "
        "review the saved backup and configure the profile manually."
    )
if not any(
    re.match(r"^[ \t]*auth(?:[ \t]|$)", line)
    and not line.lstrip().startswith("#")
    and "pam_unix.so" in line
    for line in lines
):
    raise SystemExit("No active pam_unix.so password fallback found; left PAM unchanged.")

idx = active_auth[0]
line = lines[idx]
if "default=ignore" not in line:
    raise SystemExit("Fingerprint rule has no default=ignore fallback; left PAM unchanged.")
if len(re.findall(r"\bmax-tries=\d+\b", line)) > 1:
    raise SystemExit("Fingerprint rule has multiple max-tries values; left PAM unchanged.")
if re.search(r"\bmax-tries=\d+\b", line):
    line = re.sub(r"\bmax-tries=\d+\b", "max-tries=3", line, count=1)
else:
    line = line.replace("pam_fprintd.so", "pam_fprintd.so max-tries=3", 1)
lines[idx] = line

fd, tmp_name = tempfile.mkstemp(prefix=".common-auth.goodix-", dir=str(path.parent))
try:
    os.fchmod(fd, stat.S_IMODE(st.st_mode))
    os.fchown(fd, st.st_uid, st.st_gid)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
        stream.writelines(lines)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp_name, path)
except BaseException:
    try:
        os.unlink(tmp_name)
    except FileNotFoundError:
        pass
    raise
PYTHON
    sudo grep -n 'pam_fprintd\.so' "$pam_file"
    echo 'Enabled fingerprint PAM with max-tries=3; existing password fallback is preserved.'
    echo 'The driver installer still leaves PAM unchanged unless --pam is explicitly used.'
)

check_setup() {
    echo "Architecture: $(uname -m) (engine requires x86_64)"
    if command -v lsusb >/dev/null; then
        lsusb -d 27c6:5e0a || echo 'Sensor 27c6:5e0a not found.'
    else
        echo 'Install usbutils to check for USB sensor 27c6:5e0a.'
    fi
    if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then
        systemctl show fprintd.service -p LoadState -p User -p Environment || true
    else
        echo 'No running systemd: configure the D-Bus-activated fprintd environment with your service manager. See README.'
    fi
    command -v fprintd-enroll >/dev/null || echo 'Missing fprintd-enroll: install fprintd and its client utilities.'
    integration_hints
    echo 'These checks do not establish a working driver. Test with fprintd-enroll and fprintd-verify before enabling PAM.'
}

verify_install() {
    local prefix=/opt/goodix-libfprint
    local dropdir=/etc/systemd/system/fprintd.service.d
    local marker='goodix-5e0a private install v1'
    local failed=0 unit_load='' unit_user='' unit_env=''

    if [[ -d "$prefix" && ! -L "$prefix" ]] && printf '%s\n' "$marker" | cmp -s - "$prefix/.goodix-install"; then
        echo '[OK] private installation marker'
    else
        echo '[FAIL] private installation marker missing or changed'
        failed=1
    fi
    if [[ -s "$prefix/lib/libfprint-2.so.2" && -f "$prefix/lib/libfprint-2.so.2" ]]; then
        echo '[OK] private libfprint shared library'
    else
        echo '[FAIL] private libfprint shared library missing or broken'
        failed=1
    fi
    if [[ -s "$prefix/GoodixEngineAdapter.dll" && -f "$prefix/GoodixEngineAdapter.dll" ]]; then
        echo '[OK] Goodix engine DLL'
    else
        echo '[FAIL] Goodix engine DLL missing or empty'
        failed=1
    fi
    if [[ -f "$dropdir/90-goodix.conf" && ! -L "$dropdir/90-goodix.conf" ]] && \
       printf '# %s\n[Service]\nEnvironment=LD_LIBRARY_PATH=%s/lib\nEnvironment=GOODIX_ENGINE_DLL_PATH=%s/GoodixEngineAdapter.dll\n' \
           "$marker" "$prefix" "$prefix" | cmp -s - "$dropdir/90-goodix.conf"; then
        echo '[OK] owned systemd drop-in'
    else
        echo '[FAIL] owned systemd drop-in missing or changed'
        failed=1
    fi

    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        unit_load=$(systemctl show fprintd.service -p LoadState --value 2>/dev/null || true)
        unit_user=$(systemctl show fprintd.service -p User --value 2>/dev/null || true)
        unit_env=$(systemctl show fprintd.service -p Environment --value 2>/dev/null || true)
        if [[ $unit_load == loaded && ( -z $unit_user || $unit_user == root ) ]]; then
            echo '[OK] fprintd systemd unit is loaded and runs as root'
        else
            echo '[FAIL] fprintd systemd unit is missing or has a non-root service user'
            failed=1
        fi
        if [[ $unit_env == *"LD_LIBRARY_PATH=$prefix/lib"* && $unit_env == *"GOODIX_ENGINE_DLL_PATH=$prefix/GoodixEngineAdapter.dll"* ]]; then
            echo '[OK] effective fprintd environment points to the private driver'
        else
            echo '[FAIL] effective fprintd environment does not point to the private driver'
            failed=1
        fi
    else
        echo '[FAIL] systemd is not available; cannot verify the fprintd unit'
        failed=1
    fi

    if (( failed )); then
        echo 'Installation verification failed. No files were changed.' >&2
        return 1
    fi
    echo 'Installation files and systemd configuration are present. Hardware enrollment and matching are not tested.'
}

main() (
    set -euo pipefail
    umask 022
    local mode=install DLL=${GOODIX_ENGINE_DLL_PATH:-} script_dir tmp tool pc
    local no_deps=false output='' argc=$#
    while (($#)); do
        case $1 in
            --help|--check|--verify-install|--uninstall|--integrate|--pam)
                [[ $argc == 1 ]] || { usage >&2; exit 1; }
                mode=${1#--}; shift ;;
            --no-deps) no_deps=true; shift ;;
            --dll)
                [[ $# -ge 2 && -n $2 && $2 != --* ]] || { usage >&2; fail '--dll requires a file'; exit 1; }
                DLL=$2; shift 2 ;;
            --build-only)
                [[ $# -ge 2 && -n $2 && $2 != --* && $mode == install ]] || { usage >&2; exit 1; }
                mode=build; output=$2; no_deps=true; shift 2 ;;
            *) usage >&2; exit 1 ;;
        esac
    done
    if [[ $mode == help ]]; then usage; return; fi
    if [[ $mode == check ]]; then check_setup; return; fi
    if [[ $mode == verify-install ]]; then verify_install; return; fi
    if [[ $mode == integrate ]]; then apply_integration; return; fi
    if [[ $mode == pam ]]; then apply_pam; return; fi
    # os-release is supplied by the OS; sourcing handles single/double quoted IDs.
    local ID='' ID_LIKE=''
    # shellcheck disable=SC1091
    if [[ -r /etc/os-release ]]; then . /etc/os-release; fi
    if [[ $ID == nixos && $mode != build ]]; then
        fail "NixOS detected. Import nixos-module.nix or nixosModules.default and rebuild your configuration."
        exit 1
    fi
    [[ $(uname -m) == x86_64 ]] || { fail 'The Windows PE loader requires x86_64'; exit 1; }
    [[ $EUID != 0 ]] || { fail 'Run ./install.sh as your normal user, without sudo'; exit 1; }
    local manager=''
    case " $ID $ID_LIKE " in
        *' debian '*|*' ubuntu '*) manager=apt-get ;;
        *' fedora '*|*' rhel '*) manager=dnf ;;
        *' arch '*) manager=pacman ;;
        *' suse '*|*' opensuse '*|*' opensuse-tumbleweed '*|*' opensuse-leap '*) manager=zypper ;;
        *) no_deps=true; echo "No dependency recipe for ${ID:-this OS}; checking installed tools/libraries instead. See README." ;;
    esac
    if [[ $mode != build ]]; then
        for tool in sudo systemctl; do
            command -v "$tool" >/dev/null || { fail "Required command missing: $tool. For manual integration use --build-only DIRECTORY."; exit 1; }
        done
        [[ -d /run/systemd/system ]] || { fail 'Automatic installation requires systemd; use --build-only DIRECTORY for manual integration'; exit 1; }
    fi
    local prefix=/opt/goodix-libfprint dropdir=/etc/systemd/system/fprintd.service.d
    if [[ $mode == uninstall ]]; then
        sudo bash -c "$(declare -f fail uninstall_files); uninstall_files \"\$@\"" bash "$prefix" "$dropdir"
        echo 'Removed private driver and owned drop-in. Enrolled prints and distro packages were preserved.'
        echo 'Restart when ready: sudo systemctl restart fprintd'
        return
    fi
    if [[ $mode == build ]]; then
        [[ ! -e $output && ! -L $output ]] || { fail "Output already exists: $output"; exit 1; }
    else
        [[ ! -e $prefix && ! -L $prefix && ! -e $dropdir && ! -L $dropdir ]] || {
            fail "Refusing existing $prefix or $dropdir. No files overwritten; uninstall an owned installation first."; exit 1;
        }
    fi
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    [[ -n $DLL || ! -f $script_dir/windows_driver/GoodixEngineAdapter.dll ]] || DLL="$script_dir/windows_driver/GoodixEngineAdapter.dll"
    [[ -n $DLL || ! -f /var/lib/fprint/GoodixEngineAdapter.dll ]] || DLL=/var/lib/fprint/GoodixEngineAdapter.dll
    if [[ -z $DLL || ! -r $DLL || ! -f $DLL ]]; then
        fail 'GoodixEngineAdapter.dll not found. Use --dll /path/to/GoodixEngineAdapter.dll or GOODIX_ENGINE_DLL_PATH.'
        echo 'Copy from Windows dual-boot, e.g. C:\Windows\System32\WinDriver\ or the vendor driver directory, or extract the vendor Windows driver installer.' >&2
        exit 1
    fi
    tmp="$(mktemp -d)"
    trap 'rm -rf -- "$tmp"' EXIT
    cp -- "$DLL" "$tmp/GoodixEngineAdapter.dll"
    if [[ $no_deps == false ]]; then
    command -v "$manager" >/dev/null || { fail "Missing $manager; install dependencies manually and use --no-deps"; exit 1; }
    case $manager in
        apt-get)
            sudo apt-get update
            sudo apt-get install -y git meson ninja-build pkg-config gcc g++ fprintd libglib2.0-dev libusb-1.0-0-dev \
                libgusb-dev libpixman-1-dev libssl-dev libnss3-dev libnspr4-dev libgirepository1.0-dev ;;
        dnf)
            sudo dnf install -y git meson ninja-build pkgconf-pkg-config gcc gcc-c++ fprintd fprintd-pam glib2-devel libusb1-devel \
                libgusb-devel pixman-devel openssl-devel nss-devel nspr-devel gobject-introspection-devel checkpolicy ;;
        pacman)
            sudo pacman -S --needed --noconfirm git meson ninja pkgconf gcc fprintd glib2 libusb libgusb \
                pixman openssl nss nspr gobject-introspection ;;
        zypper)
            sudo zypper --non-interactive install git meson ninja pkg-config gcc gcc-c++ fprintd glib2-devel libusb-1_0-devel \
                libgusb-devel pixman-devel openssl-devel mozilla-nss-devel mozilla-nspr-devel gobject-introspection-devel ;;
    esac
    fi
    for tool in git meson ninja pkg-config gcc g++; do
        command -v "$tool" >/dev/null || { fail "Required command missing after dependency installation: $tool"; exit 1; }
    done
    local missing=()
    for pc in glib-2.0 gusb libusb-1.0 pixman-1 nss nspr openssl gobject-introspection-1.0; do
        pkg-config --exists "$pc" || missing+=("$pc")
    done
    [[ ${#missing[@]} == 0 ]] || { fail "Missing development libraries: ${missing[*]}"; exit 1; }
    if [[ $mode == build ]]; then
        build_stage "$tmp" "$script_dir" "$tmp/GoodixEngineAdapter.dll"
        mkdir -- "$output"
        cp -R -- "$tmp/stage/." "$output/"
        echo "Staged under $output/opt/goodix-libfprint. Nothing installed or restarted. See README for service integration."
        return
    fi
    [[ $(systemctl show fprintd.service -p LoadState --value) == loaded ]] || { fail 'fprintd.service not available'; exit 1; }
    local daemon_user
    daemon_user=$(systemctl show fprintd.service -p User --value)
    [[ -z $daemon_user || $daemon_user == root ]] || { fail "fprintd must run as root; found User=$daemon_user. No USB permissions changed."; exit 1; }
    build_stage "$tmp" "$script_dir" "$tmp/GoodixEngineAdapter.dll"
    sudo bash -c "$(declare -f fail install_files); install_files \"\$@\"" bash "$tmp/stage/opt/goodix-libfprint" "$prefix" "$dropdir"
    verify_install
    echo "Installed private libfprint and DLL under $prefix; added $dropdir/90-goodix.conf."
    echo 'No global library replacement, USB permission changes, PAM changes, or automatic service restart.'
    echo 'No --no-timeout override: daemon idle-exit may discard parked TLS sessions.'
    echo 'Non-NixOS end-to-end operation is unverified. Keep password login available.'
    echo 'When ready: sudo systemctl restart fprintd; then fprintd-enroll and fprintd-verify.'
    integration_hints
    if [[ ${GOODIX_EASY_INSTALLER:-0} == 1 ]]; then
        printf 'Uninstall with checked removal: %s\n' "${GOODIX_EASY_UNINSTALL_COMMAND:-easy-install.sh --uninstall}"
    else
        printf 'Uninstall with preflight and postflight checks: %q\n' "$script_dir/uninstall.sh"
    fi
    echo 'Uninstall preserves enrolled prints and installed distro packages.'
)

# Sourcing exposes the same transactions to unprivileged fixture tests.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
