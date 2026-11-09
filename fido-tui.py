#!/usr/bin/env python3
"""Interactive Textual front end for FIDO2 Guard.

Only returns a menu action to the existing Bash manager; does not change PAM,
USB device access, or the lock state. Requires Python >=3.9 and textual.
"""
import sys
import json
import subprocess
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, OptionList, Static
from textual.widgets.option_list import Option

ACTIONS = [
    ("1", "Install dependencies", "ENVIRONMENT", "Install required FIDO2/PAM packages (apt, dnf or pacman)."),
    ("2", "Add a FIDO2 security key", "SECURITY KEYS", "Register another key without removing existing keys."),
    ("3", "List registered security keys", "SECURITY KEYS", "Display registered security keys and labels."),
    ("4", "Revoke a security key", "SECURITY KEYS", "Revoke a credential with confirmation."),
    ("5", "Import existing security keys", "SECURITY KEYS", "Import existing U2F mappings if the current file is empty."),
    ("6", "Prepare a FIDO2 PAM test", "AUTHENTICATION", "Create an isolated PAM test profile."),
    ("7", "Integrated setup / repair", "AUTHENTICATION", "Install or repair PAM and the monitor; not needed for menu updates."),
    ("8", "PAM configuration help", "AUTHENTICATION", "Explain the secure installation workflow."),
    ("9", "Restore KDE PAM configuration", "AUTHENTICATION", "Restore the PAM profile modified by this manager."),
    ("10", "Service status and logs", "MONITORING", "Show service status and recent logs."),
    ("11", "Remove the removal-monitor service", "MONITORING", "Remove the USB removal monitor without changing PAM or keys."),
    ("12", "Full removal", "MAINTENANCE", "Remove manager settings with backups and confirmation."),
    ("13", "KDE PAM diagnostics", "DIAGNOSTICS", "Inspect PAM profiles and KDE configuration."),
    ("14", "Enable lock on key removal", "MONITORING", "Lock the session when a recognized USB FIDO2 device is removed."),
    ("15", "Disable lock on key removal", "MONITORING", "Keep PAM and keys; stop the monitoring daemon."),
    ("16", "Connected key and KDE status", "DIAGNOSTICS", "Check USB detection and PAM U2F rule without unlocking."),
    ("17", "Live FIDO2 insertion / removal monitor", "DIAGNOSTICS", "Stream real USB token changes. Read-only; cannot restart KDE authentication."),
    ("18", "Enable portable USB hotplug monitor (safe)", "MONITORING", "Observe FIDO USB events on systemd Linux desktops, including X11 and Wayland; no automatic unlock."),
    ("19", "Disable USB hotplug monitor", "MONITORING", "Stop the optional USB monitor; password fallback is unchanged."),
    ("20", "Desktop compatibility report", "DIAGNOSTICS", "Detect KDE 5/6, X11/Wayland, login manager and eCryptfs; explain features not yet supported."),
]
BY_ID = {item[0]: item for item in ACTIONS}


class GuardUI(App):
    TITLE = "FIDO2 GUARD"
    SUB_TITLE = "Security key control center · v2.9"
    CSS = """
    Screen { background: #0b1320; color: #e4edf9; }
    Header { background: #101f34; color: #7fc4fc; }
    Footer { background: #101f34; }
    #hero { dock: top; height: 10; padding: 0 2; background: #10243a; color: #d7ebff; }
    #hero_title { text-style: bold; color: #80c8ff; height: 1; }
    #hero_status { color: #b2c6db; height: 1; }
    #health { height: 5; color: #d9edf8; }
    #remediation { height: 2; color: #facb7a; }
    #health .green { color: #7ce1ba; }
    #health .yellow { color: #ffce84; }
    #health .red { color: #ffa3a3; }
    #workspace { height: 1fr; padding: 1 2 0 2; }
    #left { width: 2fr; min-width: 32; }
    #right { width: 1fr; min-width: 25; margin-left: 2; background: #122036; padding: 1 2; border: tall #284a69; }
    #search { margin-bottom: 1; background: #172b44; border: tall #335575; }
    #items { height: 1fr; border: tall #284a69; background: #0e1c2e; }
    OptionList > .option-list--option-highlighted { background: #1b5d92; color: white; text-style: bold; }
    #detail_title { color: #7fc4fc; text-style: bold; height: 3; }
    #detail_group { color: #71d1c3; height: 3; }
    #detail_text { color: #d4e0f2; height: 8; }
    #notice { color: #f6cf89; margin-top: 1; }
    #help { dock: bottom; height: 2; padding: 0 3; color: #9fb7d2; background: #101f34; }
    """

    BINDINGS = [
        Binding("escape", "quit", "Quit"),
        Binding("ctrl+q", "quit", "Quit", show=False),
        Binding("slash", "focus_search", "Search"),
        Binding("f5", "refresh_health", "Refresh status"),
        Binding("ctrl+l", "clear_search", "Clear filter"),
    ]

    def __init__(self, output: Path, user: str, distro: str, keys: str, service: str):
        super().__init__()
        self.output = output
        self.user = user
        self.distro = distro
        self.keys = keys
        self.service = service
        self.health = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Vertical(id="hero"):
            yield Static("◆  FIDO2 GUARD   /   CONTROL CENTER", id="hero_title")
            yield Static(
                f"User: {self.user}   •   Linux: {self.distro}   •   Registered keys: {self.keys}",
                id="hero_status",
            )
            yield Static("Checking FIDO2 Guard components…", id="health")
            yield Static("F5 refreshes configuration and service status.", id="remediation")
        with Horizontal(id="workspace"):
            with Vertical(id="left"):
                yield Input(placeholder="Search actions…  (press /)", id="search")
                yield OptionList(*[Option(f"{int(n):>2}    {label}", id=n) for n, label, _, _ in ACTIONS], id="items")
            with Vertical(id="right"):
                yield Static("SELECT AN ACTION", id="detail_title")
                yield Static("NAVIGATION", id="detail_group")
                yield Static("↑ ↓  Move selection\nEnter  Run selected action\n/  Search\nEsc  Quit", id="detail_text")
                yield Static("Safe monitor only. KDE auto-switch is disabled; use blank-field Enter + FIDO2 touch.", id="notice")
        yield Static("↑↓ Navigate   •   Enter Select   •   / Search   •   Esc Quit", id="help")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#items", OptionList).focus()
        self.update_detail()
        self.action_refresh_health()
        self.set_interval(15, self.action_refresh_health)

    def action_refresh_health(self) -> None:
        script = Path(__file__).with_name("fido-status.py")
        if not script.is_file():
            self.query_one("#health", Static).update("[red]Status checker missing: update your Git checkout.[/]")
            self.query_one("#remediation", Static).update("Run: git pull --ff-only")
            return
        try:
            result = subprocess.run(["/usr/bin/python3", str(script), self.user],
                                    capture_output=True, text=True, timeout=8, check=False)
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or "Status check failed")
            self.health = json.loads(result.stdout)
        except (OSError, ValueError, subprocess.TimeoutExpired, RuntimeError) as error:
            self.query_one("#health", Static).update(f"[red]Health check unavailable: {str(error)[:95]}[/]")
            self.query_one("#remediation", Static).update("Check read-only status checker and systemd connectivity.")
            return

        data = self.health
        def indicator(name: str, label: str) -> str:
            state = data.get(name, {}).get("state", "ERROR")
            tone = "green" if state in ("READY", "ACTIVE", "CONFIGURED") else (
                "yellow" if state in ("DISABLED", "MISSING") else "red")
            return f"{label} [{tone}]{state}[/]"
        login = data.get("login", {})
        display = str(login.get("display", "UNKNOWN"))
        fstype = str(login.get("fstype", "UNKNOWN"))
        login_note = "[yellow]PASSWORD REQUIRED FOR ECRYPTFS[/]" if login.get("ecryptfs") else "login not validated"
        platform = data.get("platform", {})
        version = str(platform.get("plasma", {}).get("version") or "?")
        session_type = str(platform.get("session", {}).get("type", "unknown"))
        auto = str(platform.get("auto_retry", "UNKNOWN"))
        lines = [
            f"{data.get('overall', 'UNKNOWN')}  •  " + indicator("dependencies", "Packages"),
            indicator("keys", "Keys") + "   •   " + indicator("pam", "KDE unlock PAM"),
            f"Login: {display}   •   Home: {fstype}   •   {login_note}",
            indicator("removal", "Removal lock") + "   •   " + indicator("retry", "Insertion monitor"),
            f"KDE {version} / {session_type}   •   [yellow]Auto-switch: {auto}[/]",
        ]
        self.query_one("#health", Static).update("\n".join(lines))
        advice = data.get("advice", [])
        if advice:
            self.query_one("#remediation", Static).update("\n".join("Next: " + str(x) for x in advice[:2]))
        else:
            self.query_one("#remediation", Static).update("Components configured; verify both unlock methods on the KDE lock screen.")

    def update_detail(self) -> None:
        selected = self.query_one("#items", OptionList)
        item = selected.highlighted_option
        entry = BY_ID.get(str(item.id)) if item is not None else None
        if not entry:
            return
        _, label, category, description = entry
        self.query_one("#detail_title", Static).update(label)
        self.query_one("#detail_group", Static).update(category)
        self.query_one("#detail_text", Static).update(description)

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        self.update_detail()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        action_id = str(event.option.id)
        if action_id in BY_ID:
            self.output.write_text(action_id + "\n", encoding="ascii")
        self.exit()

    def on_input_changed(self, event: Input.Changed) -> None:
        query = event.value.strip().casefold()
        options = self.query_one("#items", OptionList)
        options.clear_options()
        for num, label, group, description in ACTIONS:
            if query in f"{num} {label} {group} {description}".casefold():
                options.add_option(Option(f"{int(num):>2}    {label}", id=num))
        if options.option_count:
            options.highlighted = 0
            self.update_detail()
        else:
            self.query_one("#detail_title", Static).update("No matching actions")
            self.query_one("#detail_group", Static).update("SEARCH")
            self.query_one("#detail_text", Static).update("Try another search term.")

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def action_clear_search(self) -> None:
        field = self.query_one("#search", Input)
        field.value = ""
        self.query_one("#items", OptionList).focus()


if __name__ == "__main__":
    if len(sys.argv) != 6:
        sys.exit("Usage: fido-tui.py <output-file> <user> <distro> <key-count> <service-state>")
    output = Path(sys.argv[1])
    if not output.exists() or not output.is_file():
        sys.exit("Output marker must be pre-created by the manager")
    GuardUI(output, *sys.argv[2:]).run()
