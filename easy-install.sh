#!/usr/bin/env bash
set -euo pipefail

readonly REPOSITORY='4forcebear/goodix-5e0a-patch-linux-mint'
readonly RELEASE_TAG='v1.0.1'
readonly ARCHIVE_URL="https://github.com/${REPOSITORY}/archive/refs/tags/${RELEASE_TAG}.tar.gz"
readonly BOOTSTRAP_URL="https://raw.githubusercontent.com/${REPOSITORY}/${RELEASE_TAG}/easy-install.sh"

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<USAGE
Usage:
  curl -fsSL ${BOOTSTRAP_URL} | bash
  curl -fsSL ${BOOTSTRAP_URL} | bash -s -- INSTALL_OPTIONS
  curl -fsSL ${BOOTSTRAP_URL} | bash -s -- --uninstall [--check]

Downloads the pinned ${RELEASE_TAG} source archive, then runs its checked installer.
Run as your normal user, without sudo. Installer options are forwarded.
USAGE
}

if (( $# == 1 )) && [[ $1 == --help || $1 == -h ]]; then
    usage
    exit 0
fi

[[ ${EUID:-$(id -u)} -ne 0 ]] || fail 'Run as your normal user, without sudo.'
command -v curl >/dev/null 2>&1 || fail 'curl is required.'
command -v tar >/dev/null 2>&1 || fail 'tar is required.'

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/goodix-5e0a-easy.XXXXXXXX")"
cleanup() {
    rm -rf -- "$work_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

archive="$work_dir/source.tar.gz"
source_dir="$work_dir/source"
mkdir -p -- "$source_dir"

printf 'Downloading Goodix release %s...\n' "$RELEASE_TAG"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
    --retry 2 --retry-delay 1 "$ARCHIVE_URL" --output "$archive"
tar --extract --gzip --file "$archive" --directory "$source_dir" \
    --strip-components=1 --no-same-owner --no-same-permissions

for required in install.sh uninstall.sh goodix-5e0a-integration.patch libfprint-driver/goodix5e0a.c windows_driver/GoodixEngineAdapter.dll; do
    [[ -s "$source_dir/$required" ]] || fail "Release archive is missing $required."
done

if [[ ${1:-} == --uninstall ]]; then
    shift
    bash "$source_dir/uninstall.sh" "$@"
else
    export GOODIX_EASY_INSTALLER=1
    export GOODIX_EASY_UNINSTALL_COMMAND="curl -fsSL ${BOOTSTRAP_URL} | bash -s -- --uninstall"
    bash "$source_dir/install.sh" "$@"
fi
