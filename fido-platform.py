#!/usr/bin/env python3
"""FIDO2 Guard: read-only Linux desktop and KDE auth capability detection.

This module NEVER writes PAM, lockscreen QML, credentials, or session state.
It deliberately does not equate a running USB watcher with automatic retry.
"""
import shlex
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys


def command(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=4, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None



def distribution_capabilities():
    """Read os-release without executing its values (Python 3.9 compatible)."""
    values = {}
    try:
        for row in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" not in row or row.lstrip().startswith("#"):
                continue
            key, value = row.split("=", 1)
            try:
                parts = shlex.split(value, comments=False)
            except ValueError:
                continue
            if parts:
                values[key.strip()] = parts[0]
    except OSError:
        pass
    distro = values.get("ID", "unknown").lower()
    tokens = set([distro] + values.get("ID_LIKE", "").lower().split())
    if tokens.intersection(("debian", "ubuntu", "linuxmint", "pop", "kali")):
        family = "apt"
    elif tokens.intersection(("fedora", "rhel", "centos", "rocky", "almalinux")):
        family = "dnf"
    elif tokens.intersection(("arch", "manjaro", "endeavouros", "cachyos")):
        family = "pacman"
    elif tokens.intersection(("opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles", "suse")):
        family = "zypper"
    else:
        family = "unsupported"
    return {"id": distro,
            "pretty_name": values.get("PRETTY_NAME", distro),
            "package_manager": family,
            "immutable": Path("/run/ostree-booted").exists(),
            "systemd": Path("/run/systemd/system").is_dir()}


def login_session(uid):
    result = command("loginctl", "list-sessions", "--no-legend", "--no-pager")
    if not result or result.returncode:
        return {"type": "unknown", "id": None}
    for row in result.stdout.splitlines():
        items = row.split()
        if len(items) < 2 or items[1] != str(uid):
            continue
        sid = items[0]
        state = command("loginctl", "show-session", sid,
                        "-p", "Type", "-p", "Active", "-p", "Remote")
        if not state or state.returncode:
            continue
        data = dict(line.split("=", 1) for line in state.stdout.splitlines() if "=" in line)
        if data.get("Remote") == "no" and data.get("Active") == "yes":
            return {"type": data.get("Type", "unknown"), "id": sid}
    return {"type": "unknown", "id": None}


def plasma_version():
    command_path = shutil.which("plasmashell")
    if not command_path:
        return {"major": None, "version": None}
    result = command(command_path, "--version")
    match = re.search(r"\b(\d+)\.(\d+)(?:\.(\d+))?", result.stdout if result else "")
    if not match:
        return {"major": None, "version": None}
    return {"major": int(match.group(1)), "version": match.group(0)}


def desktop_manager():
    result = command("systemctl", "show", "display-manager.service", "-p", "Id")
    if result and result.returncode == 0:
        for line in result.stdout.splitlines():
            if line.startswith("Id=") and line[3:] not in ("", "display-manager.service"):
                return line[3:].removesuffix(".service")
    path = Path("/etc/X11/default-display-manager")
    try:
        return Path(path.read_text().strip()).name
    except OSError:
        return "unknown"


def home_filesystem(home):
    result = command("findmnt", "-T", home, "--noheadings", "-o", "FSTYPE")
    if result and result.returncode == 0 and result.stdout.strip():
        return result.stdout.splitlines()[0].strip()
    return "unknown"


def active_pam_rules(path):
    try:
        return [row.strip() for row in Path(path).read_text().splitlines()
                if row.strip() and not row.lstrip().startswith("#")]
    except OSError:
        return []


def lockscreen_qml(plasma_major):
    """Locate known QML lockscreen entry points; never modify package files."""
    roots = ([Path("/usr/share/plasma/look-and-feel"),
              Path("/usr/local/share/plasma/look-and-feel")]
             if plasma_major == 5 else
             [Path("/usr/share/plasma/shells"),
              Path("/usr/local/share/plasma/shells")])
    matches = []
    for root in roots:
        if not root.is_dir():
            continue
        try:
            files = root.glob("*/contents/lockscreen/LockScreenUi.qml")
            for path in files:
                if len(matches) >= 20:
                    break
                try:
                    source = path.read_text(encoding="utf-8")
                except (OSError, UnicodeError):
                    continue
                if "authenticator.tryUnlock()" in source:
                    entry = "tryUnlock"
                elif "authenticator.startAuthenticating()" in source:
                    entry = "startAuthenticating"
                else:
                    entry = "unrecognized"
                matches.append({
                    "path": str(path),
                    "reauth_api": entry,
                    "passwordless_branch": "NoPasswordUnlock.qml" in source,
                })
        except OSError:
            continue
    return matches


def detect(user):
    user_info = pwd.getpwnam(user)
    session = login_session(user_info.pw_uid)
    distribution = distribution_capabilities()
    plasma = plasma_version()
    de = "KDE Plasma" if plasma["major"] else "unknown / other"
    manager = desktop_manager()
    filesystem = home_filesystem(user_info.pw_dir)
    has_map = Path("/etc/thetis-auth/u2f_keys").is_file()
    kde_auth = active_pam_rules("/etc/pam.d/kde")
    kde_u2f = active_pam_rules("/etc/pam.d/kde-u2f")
    qml = lockscreen_qml(plasma["major"])
    u2f_rule = any("pam_u2f.so" in line for line in kde_auth)
    separate_u2f = any("pam_u2f.so" in line for line in kde_u2f)
    # Plasma 6 may have a separate native U2F authenticator, but a
    # kde-u2f PAM file alone is not proof of an enabled, working UI.
    if plasma["major"] == 5:
        adapter = "KDE5_PAM"
        auto = "NOT_IMPLEMENTED"
        note = "Plasma 5 does not provide a validated external PAM-retry API."
    elif plasma["major"] == 6:
        adapter = "KDE6_NATIVE_U2F_CANDIDATE" if separate_u2f else "KDE6_PAM"
        auto = "NOT_VERIFIED"
        note = ("Separate kde-u2f PAM rules detected; confirm native authenticator "
                "availability and test real lock screen before activation."
                if separate_u2f else
                "No separate native U2F PAM rules; automatic switching is unverified.")
    else:
        adapter = "GENERIC_LINUX"
        auto = "NOT_IMPLEMENTED"
        note = "Only the USB monitor is currently generic; desktop UI needs an adapter."
    result = {
        "user": user,
        "distribution": distribution,
        "desktop": de,
        "plasma": plasma,
        "session": session,
        "display_manager": manager,
        "home_fs": filesystem,
        "encrypted_home_needs_password": filesystem == "ecryptfs",
        "kde_pam_has_u2f": u2f_rule,
        "native_u2f_pam_candidate": separate_u2f,
        "mapped_key_file_exists": has_map,
        "adapter": adapter,
        "qml": qml,
        "auto_retry": auto,
        "explanation": note,
    }
    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Read-only FIDO2 desktop compatibility report")
    parser.add_argument("--user", default=os.environ.get("SUDO_USER") or os.environ.get("USER"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        report = detect(args.user)
    except (KeyError, ValueError, TypeError) as error:
        parser.exit(2, "Unable to inspect user: " + str(error) + "\n")
    if args.json:
        print(json.dumps(report, ensure_ascii=False))
        return
    print("FIDO2 Guard Linux compatibility")
    distro = report["distribution"]
    print("Linux: {} | Packages: {} | Immutable: {} | systemd: {}".format(
        distro["pretty_name"], distro["package_manager"],
        "yes" if distro["immutable"] else "no",
        "yes" if distro["systemd"] else "no"))
    print(f"Desktop: {report['desktop']} {report['plasma']['version'] or ''}"
          f" | Session: {report['session']['type']}"
          f" | Login: {report['display_manager']}")
    print(f"Home FS: {report['home_fs']} | KDE PAM U2F: "
          f"{'present' if report['kde_pam_has_u2f'] else 'not detected'}")
    print(f"Adapter: {report['adapter']} | Automatic insertion retry: {report['auto_retry']}")
    print(report["explanation"])
    for item in report["qml"][:3]:
        print("QML: {} ({})".format(item["reauth_api"], item["path"]))
    if distro["immutable"]:
        print("WARNING: OSTree/immutable host; package layering and PAM changes are not automated.")
    if not distro["systemd"]:
        print("WARNING: systemd services unavailable; key management may work, but automatic monitoring is unsupported.")
    if report["encrypted_home_needs_password"]:
        print("WARNING: eCryptfs first login requires a home-unwrapping secret;"
              " FIDO2 touch alone does not provide it.")


if __name__ == "__main__":
    main()
