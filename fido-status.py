#!/usr/bin/env python3
"""Read-only, cross-distribution FIDO2 Guard status report for the TUI.

No authentication, PAM edits, USB event injection, or service modifications.
Only local systemd, standard Linux paths, and /etc/thetis-auth are inspected.
"""
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
from pathlib import Path

MAP = Path("/etc/thetis-auth/u2f_keys")
ALLOWED = {"READY", "CONFIGURED", "ACTIVE", "DISABLED", "MISSING", "ERROR", "UNSUPPORTED"}

def cmd(args, timeout=3, env=None):
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              check=False, timeout=timeout, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None

def system_unit(name, user=None):
    """Read systemd states without opening a PAM session at every refresh."""
    if not Path("/run/systemd/system").is_dir() or not shutil.which("systemctl"):
        return {"state": "UNSUPPORTED", "detail": "systemd is not running"}
    arguments = ["systemctl"]
    env = None
    if user is not None:
        try:
            identity = pwd.getpwnam(user)
        except KeyError:
            return {"state": "ERROR", "detail": "User not found"}
        runtime = f"/run/user/{identity.pw_uid}"
        if not Path(runtime, "bus").is_socket():
            return {"state": "UNSUPPORTED", "detail": "User systemd bus unavailable"}
        env = dict(os.environ, XDG_RUNTIME_DIR=runtime,
                   DBUS_SESSION_BUS_ADDRESS=f"unix:path={runtime}/bus")
        # setpriv drops credentials without the PAM session opened by runuser.
        if not shutil.which("setpriv"):
            return {"state": "UNSUPPORTED", "detail": "setpriv unavailable (util-linux)"}
        arguments = ["setpriv", "--reuid", str(identity.pw_uid),
                     "--regid", str(identity.pw_gid), "--init-groups",
                     "--", "systemctl", "--user"]
    result = cmd(arguments + ["show", name, "--property=LoadState",
                              "--property=UnitFileState", "--property=ActiveState"],
                 env=env)
    if not result:
        return {"state": "ERROR", "detail": "Unable to query systemd"}
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    load = values.get("LoadState", "")
    enabled = values.get("UnitFileState", "")
    active = values.get("ActiveState", "")
    if load == "not-found":
        return {"state": "MISSING", "detail": "Unit not installed"}
    if load == "masked" or enabled == "masked" or active == "failed":
        return {"state": "ERROR", "detail": f"{load or 'unknown'} / {active or 'unknown'}"}
    if active == "active":
        return {"state": "ACTIVE", "detail": f"Running (startup: {enabled or 'unknown'})"}
    if load == "loaded":
        return {"state": "DISABLED", "detail": f"Installed; {enabled or 'unknown'} / {active or 'unknown'}"}
    return {"state": "ERROR", "detail": f"Unknown systemd state: {load or result.stderr.strip()[:60]}"}


def login_environment(user):
    """Show the actual display manager and home encryption without PAM changes."""
    service_result = cmd(["systemctl", "show", "display-manager.service", "-p", "Id"])
    display = "UNKNOWN"
    if service_result and service_result.returncode == 0:
        for line in service_result.stdout.splitlines():
            if line.startswith("Id="):
                display = line[3:].removesuffix(".service").upper()
                break
    identity = pwd.getpwnam(user)
    result = cmd(["findmnt", "--noheadings", "-T", identity.pw_dir, "-o", "FSTYPE"])
    fstype = result.stdout.strip().splitlines()[0].strip() if result and result.returncode == 0 and result.stdout.strip() else "UNKNOWN"
    encrypted = fstype == "ecryptfs"
    return {
        "display": display, "fstype": fstype, "ecryptfs": encrypted,
        "detail": ("Password needed to unwrap eCryptfs home at first login; "
                   "FIDO2-only LightDM login not established"
                   if encrypted else "Initial login authentication not verified"),
    }

def fido_map(user):
    if not MAP.exists():
        return {"state": "MISSING", "detail": "No registered keys (menu 2)", "count": 0}
    try:
        rows = MAP.read_text(encoding="utf-8").splitlines()
        own = [row for row in rows if row.partition(":")[0] == user]
        if len(own) != 1:
            return {"state": "ERROR" if own else "MISSING",
                    "detail": "Invalid or missing account mapping", "count": 0}
        tokens = own[0].split(":")[1:]
        if not tokens or not all("," in token for token in tokens):
            return {"state": "ERROR", "detail": "Malformed FIDO2 mapping", "count": 0}
        return {"state": "CONFIGURED", "detail": f"{len(tokens)} credential(s) recorded; not physically verified", "count": len(tokens)}
    except (OSError, UnicodeError):
        return {"state": "ERROR", "detail": "Unable to read credential mapping", "count": 0}

def kde_pam():
    for service in ("kde", "kscreenlocker"):
        file = Path("/etc/pam.d") / service
        try:
            data = file.read_text(encoding="utf-8")
        except OSError:
            continue
        active_rules = [x.strip() for x in data.splitlines() if x.strip() and not x.lstrip().startswith("#")]
        u2f = any("pam_u2f.so" in x and "userpresence=1" in x and str(MAP) in x for x in active_rules)
        fallback = any(re.match(
            r"^(auth\s+.*(common-auth|pam_unix\.so|system-auth|password-auth)"
            r"|@include\s+(common-auth|system-auth|password-auth))", x)
            for x in active_rules)
        if u2f and fallback:
            return {"state": "CONFIGURED", "detail": f"{service} PAM touch + password rules present; lock-screen testing required"}
        if u2f:
            return {"state": "ERROR", "detail": f"{service} has FIDO2 but fallback not confirmed"}
    return {"state": "MISSING", "detail": "No compatible KDE PAM rules detected (menu 13)"}

def dependencies():
    missing = [name for name in ("fido2-token", "pamu2fcfg") if not shutil.which(name)]
    python = shutil.which("python3")
    if not python:
        missing.append("python3")
    else:
        result = cmd([python, "-c", "import pyudev"])
        if not result or result.returncode:
            missing.append("python3-pyudev")
    optional = []
    if not shutil.which("pamtester"):
        optional.append("pamtester (needed before changing PAM)")
    if Path("/run/systemd/system").is_dir() and not shutil.which("loginctl"):
        optional.append("loginctl (needed for USB monitoring)")
    detail = ("Core tools installed" if not missing
              else "Missing core tools: " + ", ".join(missing))
    if optional:
        detail += "; Optional: " + ", ".join(optional)
    return {"state": "READY" if not missing else "MISSING", "detail": detail}

def main():
    user = sys.argv[1] if len(sys.argv) == 2 else ""
    if not user or not re.fullmatch(r"[A-Za-z0-9_.@-]+", user):
        print(json.dumps({"error": "Invalid username"}))
        return 2
    keys = fido_map(user)
    pam = kde_pam()
    deps = dependencies()
    lock = system_unit("thetis-guard.service")
    retry = system_unit("fido2-kde-retry.service", user=user)
    login = login_environment(user)
    platform_path = Path(__file__).with_name("fido-platform.py")
    platform = {"auto_retry": "UNKNOWN", "adapter": "UNKNOWN", "plasma": {"version": None},
                "session": {"type": "unknown"}, "display_manager": login["display"]}
    if platform_path.is_file():
        check = cmd(["/usr/bin/python3", str(platform_path), "--user", user, "--json"])
        if check and check.returncode == 0:
            try:
                platform = json.loads(check.stdout)
            except (ValueError, TypeError):
                pass
    retry_path = Path(pwd.getpwnam(user).pw_dir) / ".config/systemd/user/fido2-kde-retry.service"
    if not retry_path.exists() and retry["state"] != "ACTIVE":
        retry = {"state": "MISSING", "detail": "Not installed; menu 18 installs the portable USB watcher"}
    issues = []
    if deps["state"] != "READY":
        issues.append("Install missing dependencies (1)")
    if keys["state"] != "CONFIGURED":
        issues.append("Register or repair security key mapping (2 / 3)")
    if pam["state"] != "CONFIGURED":
        issues.append("Review KDE PAM configuration (13)")
    if retry["state"] == "MISSING":
        issues.append("Optional: USB insertion watcher not installed (18)")
    elif retry["state"] == "DISABLED":
        issues.append("Optional: USB insertion watcher disabled (18)")
    if lock["state"] == "DISABLED":
        issues.append("Optional: USB removal locking disabled (14)")
    if login["ecryptfs"]:
        issues.append("First login: use your Linux password to unlock eCryptfs")
    overall = "ACTION NEEDED" if any(x["state"] not in ("CONFIGURED", "READY") for x in (keys, pam, deps)) else "KDE CONFIGURED"
    print(json.dumps({"overall": overall, "keys": keys, "pam": pam, "dependencies": deps,
                      "removal": lock, "retry": retry, "login": login, "platform": platform,
                      "advice": issues}, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    sys.exit(main())
