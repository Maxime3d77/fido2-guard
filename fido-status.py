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
    arguments = ["systemctl"]
    if user is not None:
        try:
            identity = pwd.getpwnam(user)
        except KeyError:
            return {"state": "ERROR", "detail": "User not found"}
        runtime = f"/run/user/{identity.pw_uid}"
        if not Path(runtime, "bus").exists():
            return {"state": "MISSING", "detail": "User systemd bus unavailable"}
        env = dict(os.environ, XDG_RUNTIME_DIR=runtime,
                   DBUS_SESSION_BUS_ADDRESS=f"unix:path={runtime}/bus")
        arguments = ["runuser", "-u", user, "--", "env",
                     f"XDG_RUNTIME_DIR={runtime}",
                     f"DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus", "systemctl", "--user"]
    else:
        env = None
    enabled = cmd(arguments + ["is-enabled", name], env=env)
    running = cmd(arguments + ["is-active", name], env=env)
    e = enabled.stdout.strip() if enabled else "unknown"
    a = running.stdout.strip() if running else "unknown"
    if e == "enabled" and a == "active":
        return {"state": "ACTIVE", "detail": "Running and enabled"}
    if a == "active":
        return {"state": "ACTIVE", "detail": f"Running (startup: {e})"}
    if e in ("disabled", "static", "indirect") or a == "inactive":
        return {"state": "DISABLED", "detail": f"Installed; {e} / {a}"}
    if e == "masked":
        return {"state": "ERROR", "detail": "Service masked"}
    return {"state": "MISSING", "detail": "Unit not installed"}

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
        fallback = any(re.match(r"^(auth\s+.*(common-auth|pam_unix\.so)|@include\s+common-auth)", x) for x in active_rules)
        if u2f and fallback:
            return {"state": "CONFIGURED", "detail": f"{service} PAM touch + password rules present; lock-screen testing required"}
        if u2f:
            return {"state": "ERROR", "detail": f"{service} has FIDO2 but fallback not confirmed"}
    return {"state": "MISSING", "detail": "No compatible KDE PAM rules detected (menu 13)"}

def dependencies():
    missing = [name for name in ("fido2-token", "pamu2fcfg", "loginctl", "pamtester") if not shutil.which(name)]
    if cmd(["/usr/bin/python3", "-c", "import pyudev"]) is None:
        missing.append("python3-pyudev")
    else:
        result = cmd(["/usr/bin/python3", "-c", "import pyudev"])
        if not result or result.returncode:
            missing.append("python3-pyudev")
    return {"state": "READY" if not missing else "MISSING",
            "detail": "Core tools installed" if not missing else "Missing: " + ", ".join(missing)}

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
    retry_path = Path(pwd.getpwnam(user).pw_dir) / ".config/systemd/user/fido2-kde-retry.service"
    if not retry_path.exists() and retry["state"] != "ACTIVE":
        retry = {"state": "MISSING", "detail": "Not installed; menu 18 installs and enables (KDE X11 only)"}
    issues = []
    if deps["state"] != "READY":
        issues.append("Install missing dependencies (1)")
    if keys["state"] != "CONFIGURED":
        issues.append("Register or repair security key mapping (2 / 3)")
    if pam["state"] != "CONFIGURED":
        issues.append("Review KDE PAM configuration (13)")
    if retry["state"] == "MISSING":
        issues.append("Optional: KDE X11 insertion watcher not installed (18)")
    elif retry["state"] == "DISABLED":
        issues.append("Optional: KDE X11 insertion watcher disabled (18)")
    if lock["state"] == "DISABLED":
        issues.append("Optional: USB removal locking disabled (14)")
    overall = "ACTION NEEDED" if any(x["state"] not in ("CONFIGURED", "READY") for x in (keys, pam, deps)) else "CONFIGURED"
    print(json.dumps({"overall": overall, "keys": keys, "pam": pam, "dependencies": deps,
                      "removal": lock, "retry": retry, "advice": issues}, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    sys.exit(main())
