#!/usr/bin/env bash
# FIDO2 Guard Linux compatibility layer.
# Safe to source; detection and --check/--packages are read-only.
# Package installation is an explicit root-only action.
#
# Package names are distribution-family specific.  Nothing here edits PAM.
# shellcheck shell=bash

fido_linux_detect() {
  local osfile="${1:-/etc/os-release}"
  local ID='' ID_LIKE='' PRETTY_NAME='' NAME=''
  if [[ -r "$osfile" ]]; then
    # os-release is an OS-controlled, root-owned shell-compatible data file.
    # Tests may pass an explicit fixture path.
    . "$osfile"
  fi
  FIDO_OS_ID="${ID:-unknown}"
  FIDO_OS_LIKE="${ID_LIKE:-}"
  FIDO_OS_PRETTY="${PRETTY_NAME:-${NAME:-$FIDO_OS_ID}}"
  FIDO_OS_PACKAGE_MANAGER=unsupported
  local identifiers=" ${FIDO_OS_ID,,} ${FIDO_OS_LIKE,,} "
  case "$identifiers" in
    *' arch '*|*' manjaro '*|*' endeavouros '*|*' cachyos '*)
      FIDO_OS_PACKAGE_MANAGER=pacman ;;
    *' opensuse '*|*' opensuse-leap '*|*' opensuse-tumbleweed '*|*' suse '*|*' sles '*)
      FIDO_OS_PACKAGE_MANAGER=zypper ;;
    *' fedora '*|*' rhel '*|*' centos '*|*' rocky '*|*' almalinux '*)
      FIDO_OS_PACKAGE_MANAGER=dnf ;;
    *' debian '*|*' ubuntu '*|*' linuxmint '*|*' pop '*|*' elementary '*|*' kali '*)
      FIDO_OS_PACKAGE_MANAGER=apt ;;
  esac
  FIDO_OS_IMMUTABLE=no
  # ostree systems (Bazzite/Silverblue/Kinoite) need native package layering
  # and a reboot; never run host dnf install through this tool.
  [[ -e /run/ostree-booted ]] && FIDO_OS_IMMUTABLE=yes
  FIDO_OS_SYSTEMD=no
  [[ -d /run/systemd/system ]] && FIDO_OS_SYSTEMD=yes
  # A distro ID is informational, never enough to prove that PAM/desktop
  # authentication is safe to activate on this machine.
}

fido_linux_packages() {
  # Print the family-specific package plan. No install / network requests.
  # The first group is required for enrollment and FIDO2 USB observation.
  # Optional packages provide pamtester, Textual venv, or TUI alternatives.
  local group="${1:-core}"
  case "${FIDO_OS_PACKAGE_MANAGER:-unsupported}:$group" in
    apt:core)
      printf '%s\n' 'libpam-u2f pamu2fcfg fido2-tools python3 python3-pyudev' ;;
    apt:optional)
      printf '%s\n' 'pamtester whiptail python3-venv python3-pip' ;;
    dnf:core)
      printf '%s\n' 'pam-u2f pamu2fcfg fido2-tools python3 python3-pyudev' ;;
    dnf:optional)
      printf '%s\n' 'pamtester newt python3-pip' ;;
    pacman:core)
      # libfido2 provides fido2-token; pam-u2f provides pamu2fcfg.
      printf '%s\n' 'pam-u2f libfido2 python python-pyudev' ;;
    pacman:optional)
      printf '%s\n' 'python-pip' ;;
    zypper:core)
      # SUSE calls the PAM package pam_u2f (not pam-u2f).
      printf '%s\n' 'pam_u2f libfido2-1 python3' ;;
    zypper:optional)
      # Package names for pyudev/tools can vary with openSUSE release.
      printf '%s\n' 'fido2-tools python3-pyudev pamtester python3-pip' ;;
    *) return 1 ;;
  esac
}

fido_linux_report() {
  fido_linux_detect "${1:-/etc/os-release}"
  printf 'Distribution : %s (%s)\n' "$FIDO_OS_PRETTY" "$FIDO_OS_ID"
  printf 'Family       : %s\n' "$FIDO_OS_PACKAGE_MANAGER"
  printf 'Immutable    : %s\n' "$FIDO_OS_IMMUTABLE"
  printf 'systemd      : %s\n' "$FIDO_OS_SYSTEMD"
  if [[ "$FIDO_OS_IMMUTABLE" == yes ]]; then
    echo 'ACTION: No automatic package/PAM changes on OSTree/immutable hosts.'
  fi
  if [[ "$FIDO_OS_SYSTEMD" != yes ]]; then
    echo 'ACTION: systemd monitoring services unavailable; key enrollment may still work.'
  fi
  printf 'Core packages: '
  fido_linux_packages core 2>/dev/null || echo '(automatic installation unsupported)'
  printf 'Optional pkgs: '
  fido_linux_packages optional 2>/dev/null || echo '(none)'
  echo 'Known limitation: USB monitoring is not automatic PAM retry.'
}

fido_linux_install_deps() {
  fido_linux_detect
  if (( EUID != 0 )); then
    echo 'ERROR: dependency installation requires root (sudo).' >&2
    return 1
  fi
  if [[ "$FIDO_OS_IMMUTABLE" == yes ]]; then
    echo 'ERROR: Immutable/OSTree host; package layering is not automated.' >&2
    echo 'Install the packages using your distribution-specific host mechanism and reboot.' >&2
    return 1
  fi
  local core optional
  core=$(fido_linux_packages core) || {
    echo "ERROR: Unsupported package manager for $FIDO_OS_ID. No changes." >&2
    return 1
  }
  optional=$(fido_linux_packages optional) || optional=''
  local -a core_array optional_array
  read -r -a core_array <<< "$core"
  read -r -a optional_array <<< "$optional"
  case "$FIDO_OS_PACKAGE_MANAGER" in
    apt)
      command -v apt-get >/dev/null || return 1
      apt-get update || return 1
      DEBIAN_FRONTEND=noninteractive apt-get install -y "${core_array[@]}" || return 1
      DEBIAN_FRONTEND=noninteractive apt-get install -y "${optional_array[@]}" ||
        echo 'WARNING: Some optional packages are unavailable; check pamtester/venv manually.'
      ;;
    dnf)
      local dnf_cmd=dnf
      command -v dnf >/dev/null || dnf_cmd=dnf5
      command -v "$dnf_cmd" >/dev/null || return 1
      "$dnf_cmd" install -y "${core_array[@]}" || return 1
      "$dnf_cmd" install -y "${optional_array[@]}" ||
        echo 'WARNING: Optional packages unavailable; check pamtester manually.'
      ;;
    pacman)
      command -v pacman >/dev/null || return 1
      echo 'Arch: do not use -Sy or partial upgrades. Keep the system fully updated.'
      pacman -S --needed "${core_array[@]}" || return 1
      pacman -S --needed "${optional_array[@]}" ||
        echo 'WARNING: Optional packages unavailable.'
      ;;
    zypper)
      command -v zypper >/dev/null || return 1
      zypper --non-interactive install --no-recommends "${core_array[@]}" || return 1
      # openSUSE package names vary by release; optional failures are explicit.
      local package
      for package in "${optional_array[@]}"; do
        zypper --non-interactive install --no-recommends "$package" ||
          echo "WARNING: Optional '$package' unavailable. Install the matching package for your release."
      done
      ;;
    *) return 1 ;;
  esac
  local missing=0
  local binary
  for binary in pamu2fcfg fido2-token python3; do
    if ! command -v "$binary" >/dev/null; then
      echo "ERROR: Missing mandatory binary after installation: $binary" >&2
      missing=1
    fi
  done
  if command -v python3 >/dev/null && ! python3 -c 'import pyudev' >/dev/null 2>&1; then
    echo 'WARNING: python3-pyudev missing. Hotplug features are not available.'
  fi
  if ! command -v pamtester >/dev/null; then
    echo 'WARNING: pamtester missing. Never enable KDE PAM until its test can be completed.'
  fi
  return "$missing"
}

# Read-only when run as a standalone program.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:---check}" in
    --check)
      fido_linux_report ;;
    --packages)
      fido_linux_detect
      fido_linux_packages "${2:-core}" ;;
    --help|-h)
      printf '%s\n' 'Usage: bash fido-linux-compat.sh [--check|--packages [core|optional]]' ;;
    *)
      echo 'Only read-only inspection is supported directly; use manager menu 1 for installation.' >&2
      exit 2 ;;
  esac
fi
