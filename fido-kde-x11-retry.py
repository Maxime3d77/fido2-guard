#!/usr/bin/env python3
"""FIDO2 Guard v2.9 - opt-in KDE Plasma 5 X11 lock-screen FIDO retry.

This is a guarded X11 compatibility adapter, NOT a native KScreenLocker API:
- Does nothing on Wayland, when unlocked, or when active-window ownership cannot be verified.
- Never calls an unlock API, writes credentials, or modifies PAM.
- Sends one Return to the confirmed KScreenLocker greeter on FIDO2 USB insertion,
  equivalent to the manually successful blank-field Enter workflow.
- This may submit existing text in the focused field. Opt-in only; disable if unreliable.
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

def current_x11_session():
    sessions = run(["loginctl", "list-sessions", "--no-legend", "--no-pager"])
    if sessions is None or sessions.returncode != 0:
        return None
    for line in sessions.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[1] != str(UID):
            continue
        sid = parts[0]
        info = run(["loginctl", "show-session", sid, "-p", "Type",
                    "-p", "Active", "-p", "LockedHint", "-p", "Remote"])
        if info is None or info.returncode:
            continue
        values = dict(line.split("=", 1) for line in info.stdout.splitlines() if "=" in line)
        if (values.get("Type") == "x11" and values.get("Active") == "yes"
                and values.get("LockedHint") == "yes" and values.get("Remote") == "no"):
            return sid
    return None

def greeter_environment():
    """Identify a single greeter *belonging to this user* and its X11 display."""
    candidates = []
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            if directory.stat().st_uid != UID:
                continue
            process = (directory / "comm").read_text().strip()
            if process != "kscreenlocker_g" and process != "kscreenlocker_greet":
                continue
            exe = os.readlink(directory / "exe")
            if Path(exe).name != "kscreenlocker_greet":
                continue
            items = (directory / "environ").read_bytes().split(b"\0")
            values = {}
            for item in items:
                key, sep, value = item.partition(b"=")
                if sep and key in (b"DISPLAY", b"XAUTHORITY"):
                    values[key.decode()] = value.decode(errors="replace")
            if not values.get("DISPLAY", "").startswith(":"):
                continue
            candidates.append((int(directory.name), values))
        except (OSError, UnicodeError, ValueError):
            continue
    return candidates[0] if len(candidates) == 1 else None

def request_retry():
    if not current_x11_session():
        logging.info("No verified locked local X11 session; skip")
        return
    greeter = greeter_environment()
    if not greeter:
        logging.info("Unable to identify exactly one user greeter; skip")
        return
    pid, values = greeter
    xdotool = shutil.which("xdotool")
    if not xdotool:
        logging.warning("xdotool unavailable")
        return
    env = os.environ.copy()
    env.update(values)
    # The currently active X11 window MUST belong to the greeter process.
    window = run([xdotool, "getactivewindow"], env=env)
    if window is None or window.returncode or not window.stdout.strip().isdigit():
        logging.info("Cannot identify active X11 window; no keystroke")
        return
    window_id = window.stdout.strip()
    active = run([xdotool, "getwindowpid", window_id], env=env)
    if active is None or active.returncode or active.stdout.strip() != str(pid):
        logging.info("Active X11 window does not belong to KScreenLocker; no keystroke")
        return
    result = run([xdotool, "key", "--clearmodifiers", "--window",
                  window_id, "Return"], env=env)
    if result is None or result.returncode:
        logging.warning("X11 PAM retry was not delivered")
    else:
        logging.info("Sent one Enter to verified greeter; FIDO2 touch still required")

def main():
    if not shutil.which("xdotool"):
        raise SystemExit("Install xdotool to enable KDE X11 retry")
    known = discover()
    if known is None:
        raise SystemExit("Unable to enumerate FIDO2 devices")
    monitor = pyudev.Monitor.from_netlink(CTX)
    monitor.filter_by("usb")
    monitor.start()
    logging.info("Watching USB insertions; existing tokens: %s; X11 only", len(known))
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
            time.sleep(0.9)
            refreshed = discover()
            if refreshed is None:
                logging.warning("Unable to enumerate after USB event")
                continue
            added = refreshed - known
            known = refreshed
            if added and time.monotonic() - last > 3:
                last = time.monotonic()
                logging.info("FIDO2 USB inserted (%d new), checking KDE lock", len(added))
                request_retry()
    except KeyboardInterrupt:
        return

if __name__ == "__main__":
    main()
