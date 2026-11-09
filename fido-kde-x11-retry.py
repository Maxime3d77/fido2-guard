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
        values = dict(line.split("=", 1) for line in info.stdout.splitlines() if "=" in line)
        seen.append(f"{sid} type={values.get('Type', '?')} active={values.get('Active', '?')} locked={values.get('LockedHint', '?')} remote={values.get('Remote', '?')}")
        if (values.get("Type") == "x11" and values.get("Active") == "yes"
                and values.get("LockedHint") == "yes" and values.get("Remote") == "no"):
            return sid
    logging.info("No verified locked X11 logind session; inspected: %s", "; ".join(seen) or "none")
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


def x11_environment():
    """Use the logged-in user's X11 session environment, not protected /proc."""
    env = os.environ.copy()
    if not env.get("DISPLAY") or not env.get("XAUTHORITY"):
        inherited = run(["systemctl", "--user", "show-environment"])
        if inherited and inherited.returncode == 0:
            for line in inherited.stdout.splitlines():
                key, sep, value = line.partition("=")
                if sep and key in ("DISPLAY", "XAUTHORITY") and not env.get(key):
                    env[key] = value
    if not env.get("DISPLAY", "").startswith(":"):
        logging.info("No local X11 DISPLAY in user systemd environment; skip")
        return None
    return env


def focused_greeter_window(xdotool, env, pid):
    """Check keyboard focus, not EWMH _NET_ACTIVE_WINDOW.

    The screen locker may hold a keyboard grab while KWin still reports the
    previously active normal desktop window in _NET_ACTIVE_WINDOW.
    """
    focus = run([xdotool, "getwindowfocus"], env=env)
    if not focus or focus.returncode or not focus.stdout.strip().isdigit():
        logging.info("Cannot inspect X11 keyboard-focus window; skip")
        return None
    window_id = focus.stdout.strip()
    owner = run([xdotool, "getwindowpid", window_id], env=env)
    window_pid = owner.stdout.strip() if owner and owner.returncode == 0 else ""
    if window_pid != str(pid):
        logging.info("X11 focus window=%s PID=%s; KDE greeter PID=%s: skip",
                     window_id, window_pid or "<unknown>", pid)
        return None
    return window_id


def request_retry():
    if not current_x11_session():
        return
    pid = verified_greeter_pid()
    if pid is None:
        return
    env = x11_environment()
    if env is None:
        return
    xdotool = shutil.which("xdotool")
    if not xdotool:
        logging.warning("xdotool unavailable")
        return
    window_id = focused_greeter_window(xdotool, env, pid)
    if window_id is None:
        return
    # Verify both conditions immediately again before generating input.
    if not current_x11_session() or focused_greeter_window(xdotool, env, pid) != window_id:
        logging.info("Locked session/focus changed while checking; skip")
        return
    # XTEST sends a normal keyboard event through the existing X11 focus/grab.
    # The physical security key must still be touched to authenticate via PAM.
    result = run([xdotool, "key", "--clearmodifiers", "Return"], env=env)
    if result is None or result.returncode:
        logging.warning("Unable to send FIDO2 retry Enter via X11")
    else:
        logging.info("Sent one X11 Enter to verified focused KScreenLocker; touch still required")

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
