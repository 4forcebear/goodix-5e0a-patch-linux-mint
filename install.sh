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
    echo 'Usage: ./install.sh [--no-deps] [--dll FILE] [--build-only DIRECTORY] | --check | --uninstall | --integrate | --help'
    echo 'Run as your normal user. Default: private /opt install for systemd and root-run fprintd.'
    echo '--no-deps: use installed dependencies on any distro; no package manager calls.'
    echo '--build-only DIRECTORY: build a staging tree without sudo, systemd, or package installation.'
    echo '--check: read-only runtime and desktop setup hints; does not test hardware.'
    echo 'No automatic restart, PAM changes, or --no-timeout override. Uninstall preserves prints and distro packages.'
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
        echo 'Debian/Ubuntu: sudo apt install libpam-fprintd; sudo pam-auth-update'
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

main() (
    set -euo pipefail
    umask 022
    local mode=install DLL=${GOODIX_ENGINE_DLL_PATH:-} script_dir tmp tool pc
    local no_deps=false output='' argc=$#
    while (($#)); do
        case $1 in
            --help|--check|--uninstall|--integrate)
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
    if [[ $mode == integrate ]]; then apply_integration; return; fi
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
    echo "Installed private libfprint and DLL under $prefix; added $dropdir/90-goodix.conf."
    echo 'No global library replacement, USB permission changes, PAM changes, or automatic service restart.'
    echo 'No --no-timeout override: daemon idle-exit may discard parked TLS sessions.'
    echo 'Non-NixOS end-to-end operation is unverified. Keep password login available.'
    echo 'When ready: sudo systemctl restart fprintd; then fprintd-enroll and fprintd-verify.'
    integration_hints
    printf 'Uninstall: %q --uninstall\n' "$script_dir/install.sh"
    echo 'Uninstall preserves enrolled prints and installed distro packages.'
)

# Sourcing exposes the same transactions to unprivileged fixture tests.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
