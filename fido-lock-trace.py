#!/usr/bin/env python3
"""Read-only, cross-distro trace for intermittent Linux screen-lock failures.

Run as the logged-in desktop user, not root. No key captures, injected input,
PAM modifications, service changes, screen captures or secret file reads.
"""
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

PROCESS_NAMES = {"kscreenlocker_g", "kscreenlocker_greet",
                 "kwin_x11", "kwin_wayland", "plasmashell"}
JOURNAL_PATTERN = re.compile(
    r"kscreenlocker|pam_u2f|pam_ecryptfs|kwin_x11|kwin_wayland|plasmashell|"
    r"fido2-retry|fido2-guard|xrandr|kscreenlock", re.IGNORECASE)


def run(argv, timeout=5):
    try:
        return subprocess.run(argv, text=True, capture_output=True,
                              check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def parse_monitors(output):
    match = re.search(r"(?m)^Monitors:\s*(\d+)\s*$", output)
    return int(match.group(1)) if match else None


def screen_layout():
    """X11 monitor count/names only, without grabbing screen contents."""
    # xrandr under Wayland describes XWayland, not physical monitor layout.
    if os.environ.get("XDG_SESSION_TYPE", "").lower() == "wayland":
        return {"count": None, "names": [], "source": "wayland-not-probed"}
    if not os.environ.get("DISPLAY") or not shutil.which("xrandr"):
        return {"count": None, "names": [], "source": "unavailable"}
    output = run(["xrandr", "--listmonitors"])
    if not output or output.returncode != 0:
        return {"count": None, "names": [], "source": "unavailable"}
    names = []
    for line in output.stdout.splitlines()[1:]:
        columns = line.strip().split()
        if len(columns) >= 3 and columns[0].rstrip(":").isdigit():
            names.append(columns[-1])
    return {"count": parse_monitors(output.stdout), "names": names, "source": "xrandr"}


def session_id(uid):
    result = run(["loginctl", "list-sessions", "--no-legend", "--no-pager"])
    if not result or result.returncode:
        return None
    active = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[1] != str(uid):
            continue
        state = run(["loginctl", "show-session", fields[0],
                     "-p", "Active", "-p", "Remote"])
        if state and "Active=yes" in state.stdout and "Remote=no" in state.stdout:
            active.append(fields[0])
    return active[0] if active else None


def session_state(sid):
    if sid is None:
        return {"type": "unknown", "active": "unknown", "locked_hint": "unknown"}
    result = run(["loginctl", "show-session", sid, "-p", "Type",
                  "-p", "Active", "-p", "LockedHint"])
    values = dict(line.split("=", 1) for line in result.stdout.splitlines()
                  if "=" in line) if result and result.returncode == 0 else {}
    return {"type": values.get("Type", "unknown"),
            "active": values.get("Active", "unknown"),
            "locked_hint": values.get("LockedHint", "unknown")}


def desktop_processes(uid):
    """Only PID and binary name; never inspect process command lines."""
    result = run(["ps", "-e", "-o", "pid=", "-o", "uid=", "-o", "comm="])
    if not result or result.returncode:
        return {}
    found = {}
    for line in result.stdout.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3 or fields[1] != str(uid):
            continue
        pid, _, comm = fields
        if comm in PROCESS_NAMES or comm.startswith("kscreenlocker_g"):
            found.setdefault(comm, []).append(int(pid))
    return found


def local_time():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def journal_excerpt(start_epoch, destination):
    """Save only per-user journal lines for display/lock components."""
    result = run(["journalctl", "--user", "-b", "--since",
                  "@{}".format(start_epoch), "--no-pager", "-o", "short-iso"], timeout=12)
    if not result or result.returncode:
        destination.write_text(
            "User journal unavailable; use 'journalctl --user -b' to inspect manually.\n",
            encoding="utf-8")
        return 0
    lines = [row for row in result.stdout.splitlines() if JOURNAL_PATTERN.search(row)]
    destination.write_text("\n".join(lines[-300:]) + ("\n" if lines else ""), encoding="utf-8")
    return len(lines)


def capture(seconds, interval):
    if os.geteuid() == 0:
        print("Run this diagnostic without sudo, in the desktop user's terminal.", file=sys.stderr)
        return 2
    os.umask(0o077)
    state_home = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
    directory = state_home / "fido2-guard" / "diagnostics"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    prefix = "lock-{}-{}".format(datetime.now().strftime("%Y%m%d-%H%M%S"), os.getpid())
    trace_path = directory / (prefix + ".jsonl")
    journal_path = directory / (prefix + ".journal.txt")
    start_epoch = int(time.time())
    sid = session_id(os.getuid())
    deadline = time.monotonic() + seconds
    previous = None
    last_heartbeat = 0.0
    events = 0
    print("Read-only lock diagnostics started; {} s maximum.".format(seconds))
    print("Lock the screen, unlock using your usual method, then return here.")
    print("Ctrl+C stops the trace early and saves the log.")
    with trace_path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps({
            "event": "start", "time": local_time(), "session": sid,
            "monitor_layout": screen_layout(),
            "note": "LockedHint is an unreliable lock indicator on some desktops.",
        }, ensure_ascii=False) + "\n")
        try:
            while time.monotonic() < deadline:
                status = session_state(sid)
                processes = desktop_processes(os.getuid())
                layout = screen_layout()
                signature = (status["locked_hint"], status["active"], status["type"],
                             tuple(sorted((k, tuple(v)) for k, v in processes.items())),
                             layout["count"], tuple(layout["names"]))
                if signature != previous or time.monotonic() - last_heartbeat >= 15:
                    entry = {"event": "sample", "time": local_time(),
                             "session": status, "processes": processes,
                             "monitors": layout}
                    stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
                    stream.flush()
                    previous = signature
                    last_heartbeat = time.monotonic()
                    events += 1
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nCapture stopped by user.")
        finally:
            stream.write(json.dumps({"event": "end", "time": local_time()}) + "\n")
    journal_lines = journal_excerpt(start_epoch, journal_path)
    print("Saved trace: {}".format(trace_path))
    print("Saved user journal: {} ({} matching lines)".format(journal_path, journal_lines))
    print("Captured {} state events. Review files before sharing: journal lines may "
          "contain local filenames or personal information.".format(events))
    return 0


def main():
    parser = argparse.ArgumentParser(description="Passive KDE/Linux screen-lock diagnostic")
    parser.add_argument("--seconds", type=int, default=120,
                        help="Maximum capture time, 15-900 seconds (default: 120)")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="Sampling interval, 0.5-10 seconds (default: 1)")
    args = parser.parse_args()
    if not 15 <= args.seconds <= 900 or not 0.5 <= args.interval <= 10:
        parser.error("Expected --seconds 15..900 and --interval 0.5..10")
    return capture(args.seconds, args.interval)


if __name__ == "__main__":
    sys.exit(main())
