#!/usr/bin/env python3
"""FIDO2 Guard v2.9: portable Linux FIDO2 insertion watcher (safe mode).

KDE's password entry can treat a synthetic Return as a failed password
attempt. This monitor deliberately NEVER sends keyboard events or unlocks
the session. The service keeps observing insertion/removal and reports the
KDE state in the log. Authentication must still be initiated in the greeter.
No PAM configuration or enrolled credentials are changed by this watcher.
"""
import logging
import os
import pwd
import shutil
import subprocess
import time
from pathlib import Path

try:
    import pyudev
except ImportError:
    raise SystemExit("python3-pyudev is required")

logging.basicConfig(level=logging.INFO, format="%(asctime)s FIDO2-RETRY %(message)s")
CTX = pyudev.Context()
USER = pwd.getpwuid(os.getuid()).pw_name
UID = os.getuid()

def run(argv, env=None, timeout=8):
    try:
        return subprocess.run(argv, env=env, text=True, capture_output=True,
                              timeout=timeout, check=False, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None

def discover():
    command = shutil.which("fido2-token")
    result = run([command, "-L"], timeout=12) if command else None
    if result is None or result.returncode != 0:
        return None
    devices = set()
    for line in result.stdout.splitlines():
        dev = line.partition(":")[0].strip()
        if not dev.startswith("/dev/hidraw"):
            continue
        try:
            device = pyudev.Devices.from_device_file(CTX, dev)
            usb = device.find_parent("usb", "usb_device")
            if usb is not None:
                devices.add(usb.sys_path)
        except (OSError, ValueError, pyudev.DeviceNotFoundError):
            continue
    return devices

def current_desktop_session():
    """Report local session state on X11 and Wayland, without changing it."""
    sessions = run(["loginctl", "list-sessions", "--no-legend", "--no-pager"])
    if sessions is None or sessions.returncode != 0:
        logging.warning("Unable to enumerate logind sessions")
        return None
    seen = []
    for line in sessions.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1] != str(UID):
            continue
        sid = parts[0]
        info = run(["loginctl", "show-session", sid, "-p", "Type",
                    "-p", "Active", "-p", "LockedHint", "-p", "Remote"])
        if info is None or info.returncode:
            continue
        values = dict(item.split("=", 1) for item in info.stdout.splitlines() if "=" in item)
        seen.append(f"{sid} type={values.get('Type', '?')} active={values.get('Active', '?')} locked={values.get('LockedHint', '?')}")
        if values.get("Active") == "yes" and values.get("Remote") == "no":
            return {"id": sid, "type": values.get("Type", "unknown"),
                    "locked": values.get("LockedHint", "unknown")}
    logging.info("No active local logind session for %s: %s", USER, "; ".join(seen) or "none")
    return None

def verified_greeter_pid():
    """Find KScreenLocker by UID + process identity without ptrace.

    KDE calls PR_SET_DUMPABLE(0) on the greeter, intentionally denying
    /proc/<pid>/exe and /proc/<pid>/environ reads. Never try to defeat that
    protection. We additionally require X11 focus's _NET_WM_PID to match.
    """
    candidates = []
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            if directory.stat().st_uid != UID:
                continue
            comm = (directory / "comm").read_text().strip()
            if comm not in ("kscreenlocker_g", "kscreenlocker_greet"):
                continue
            pid = int(directory.name)
            try:
                executable = os.readlink(directory / "exe")
            except PermissionError:
                logging.info("KScreenLocker PID=%s has protected /proc/exe (normal KDE security); using X11 focus PID verification", pid)
            except OSError:
                logging.info("KScreenLocker PID=%s /proc/exe inaccessible; using X11 focus PID verification", pid)
            else:
                if Path(executable.removesuffix(" (deleted)")).name != "kscreenlocker_greet":
                    logging.info("Rejecting PID=%s: unexpected executable %s", pid, Path(executable).name)
                    continue
            candidates.append(pid)
        except (OSError, UnicodeError, ValueError):
            continue
    if len(candidates) != 1:
        logging.info("Expected one own KScreenLocker greeter; found %d", len(candidates))
        return None
    return candidates[0]


def request_retry():
    """Safe mode: inspect session/greeter state and log only; never inject keys."""
    session = current_desktop_session()
    if not session:
        return
    if session["locked"] != "yes":
        logging.info("FIDO2 USB inserted; logind session=%s %s locked=%s (no auth action)",
                     session["id"], session["type"], session["locked"])
        return
    if session["type"] == "x11":
        pid = verified_greeter_pid()
        if pid is not None:
            logging.info("FIDO2 inserted on locked X11 session=%s; KDE greeter=%s; "
                         "manual authentication still required", session["id"], pid)
            return
    logging.info("FIDO2 inserted on locked %s session=%s; passive monitoring only",
                 session["type"], session["id"])

def main():
    known = discover()
    if known is None:
        raise SystemExit("Unable to enumerate FIDO2 devices")
    monitor = pyudev.Monitor.from_netlink(CTX)
    monitor.filter_by("usb")
    monitor.start()
    logging.info("Watching USB insertions; existing tokens: %s; portable safe monitoring only", len(known))
    last = 0.0
    try:
        while True:
            event = monitor.poll(timeout=1)
            if event is None or event.device_type != "usb_device":
                continue
            if event.action == "remove":
                known.discard(event.sys_path)
                continue
            if event.action != "add":
                continue
            # USB nodes can appear after the usb_device event; allow udev to settle.
            refreshed = None
            added = set()
            for attempt in range(7):
                time.sleep(0.5)
                refreshed = discover()
                if refreshed is not None:
                    added = refreshed - known
                    if added:
                        break
            if refreshed is None:
                logging.warning("Unable to enumerate FIDO2 devices after USB event")
                continue
            known = refreshed
            if not added:
                logging.info("USB insert observed, but no new FIDO2 token was enumerated")
            if added and time.monotonic() - last > 3:
                last = time.monotonic()
                logging.info("FIDO2 USB inserted (%d new), checking KDE lock", len(added))
                request_retry()
    except KeyboardInterrupt:
        return

if __name__ == "__main__":
    main()
