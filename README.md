# FIDO2 Guard — v2.9

A Linux **FIDO2/U2F security key manager** with PAM authentication for KDE Plasma and **optional automatic screen locking when a USB FIDO2 key is removed**.

> **Experimental, not security-audited.** Intermittent KScreenLocker issues (black screens and unexpected behavior) have been observed during testing on Linux Mint KDE. Test on a non-critical computer, keep a working password and an administrator recovery console available, and do not deploy directly to production.

## KDE key insertion and screen unlock (v2.8)

**Important limitation:** Inserting a FIDO2 key while KScreenLocker is already waiting for a password does **not** reliably switch the existing PAM conversation to a touch prompt. This depends on KDE's lock-screen implementation; it cannot safely be fixed by a systemd USB watcher or by reloading PAM files. The v2.8 manager therefore **does not claim to automatically switch the locked screen UI**.

Menu **16 — KDE / FIDO2 state diagnostics** checks for detected FIDO devices, registered key count, and whether the KDE PAM profile has a touch-required U2F rule. It is read-only and does not authenticate, unlock, or send keystrokes. This is a diagnostic step toward a future KDE integration rather than the final adaptive UI.

If PAM is already prompting for a touch, touch the key; otherwise use the regular password. The existing password fallback remains available. A true automatic UI transition requires validated changes to KScreenLocker/Plasma that can restart PAM authentication safely when a key arrives, including correct behavior across X11 and Wayland.

## v2.9 — KDE Plasma 5 X11 auto-retry watcher (experimental)

**Existing installations:** update the checkout and launch the manager:

```bash
cd ~/Documents/git/fido2-guard
git pull --ff-only
sudo bash fido2-guard.sh
```

Select **18 — Enable KDE X11 FIDO auto-retry (experimental)**. This option installs `fido-kde-x11-retry.py` under `/usr/local/libexec`, sets up a **user-level systemd service**, and offers to install the `xdotool` dependency. When prompted, enter **`ENABLE X11 RETRY`**. It **does not overwrite** the existing PAM profile or re-register any keys; there is no need to rerun integrated setup (7). **Option 19** stops and disables this watcher without changing PAM or the separate lock-on-removal service.

**Mechanism:** when a USB FIDO2 device appears, this optional adapter checks that the local X11 session is locked according to logind, that exactly one `kscreenlocker_greet` process belongs to the current user, and that the X11 active window belongs to that greeter. Only then does it send a single Return key event to re-trigger the same PAM pathway that the user tested manually. A physical FIDO2 touch is still required before unlocking. Other windows must not receive the keystroke.

**Risks and limitations:** this is a best-effort **X11 compatibility adapter**, **not a native KDE API**. The X server / KScreenLocker may reject synthetic keys or may not expose the greeter as the active window, in which case the watcher logs a skip. Sending Return may submit text the user already typed into a password field; it does not read that text. This feature is **not supported on Wayland**, not proven on KDE Plasma 6, and is not guaranteed across all Linux distributions. It must be enabled voluntarily and tested on the intended system; an external process cannot guarantee a universal, reliable lock-screen UI transition.

Diagnostics:

```bash
# User-level watcher status / logs (run as the logged-in desktop user)
systemctl --user status fido2-kde-retry.service
journalctl --user -u fido2-kde-retry.service -f

# Immediate rollback
systemctl --user disable --now fido2-kde-retry.service
```

**Testing sequence:** ensure the session still unlocks with the normal password; insert a key while unlocked (nothing should happen); remove the key; lock with Meta+L; insert the key while locked; watch for the FIDO2 touch challenge and unlock only by physically touching it. Disable the adapter if there are black screens or unexpected keyboard actions. Keep another session/TTY available for recovery. See KDE's documented PAM configuration caution.

The rest of the manager and USB detection continue to use distribution-independent Linux tools (`pyudev`, `fido2-token`, PAM and systemd); the *retry integration* is specifically scoped to KDE Plasma on X11. Other desktops require different native adapters.

## Features

- Manage multiple Thetis, YubiKey, and other FIDO2 authenticators.
- Register, list, import, and revoke security keys, with confirmations and backups.
- Authenticate through `pam_u2f` with **physical touch required** (`userpresence=1`).
- Keep your **Linux account password** as a fallback.
- Enable or disable **automatic locking on USB key removal** from the menu (**options 14 / 15**).
- **Never unlock automatically**: the monitoring daemon does **not** call `loginctl unlock-session`.
- KDE PAM diagnostics, service logs, PAM rollback, and confirmed full removal.
- Detect mainstream distribution families using **apt**, **dnf**, or **pacman**.

## Get the latest version

Install Git if it is not already available:

```bash
# Debian / Ubuntu / Linux Mint
sudo apt update && sudo apt install -y git

# Fedora (run instead on Fedora)
# sudo dnf install -y git

# Arch / Manjaro (run instead on Arch-based systems)
# sudo pacman -S --needed git
```

Clone the repository and launch the manager:

```bash
git clone https://github.com/Maxime3d77/fido2-guard.git
cd fido2-guard
sudo bash fido2-guard.sh
```

The tool requires **systemd**, a terminal, and administrator privileges. On supported distributions, select **01 — Dependencies** to install the relevant packages, including `pam-u2f`, `pamu2fcfg`, `fido2-tools`, and `pyudev`.

## Setup

1. Select **02 — Add a key**. Unplug other authenticators and touch the key when prompted.
2. Select **03 — List keys** to confirm registration.
3. Select **07 — Integrated installation**. This checks FIDO2 touch authentication, KDE PAM, and the fallback password path.
4. **Test the actual KDE unlock screen** using both a key touch and your regular password.
5. Only once both methods work, select **14 — Enable lock on removal**, if desired.

Option **07 installs the monitoring daemon but leaves lock-on-removal disabled by default**. This avoids automatically locking a session before its unlock methods have been validated. Option **15** disables removal monitoring without removing the keys or changing PAM.

### Menu reference

| Option | Action |
| --- | --- |
| 01 | Install dependencies |
| 02 / 03 / 04 | Add, list, and revoke keys |
| 05 | Import existing keys |
| 06 | Prepare a FIDO2 PAM touch test |
| 07 | Integrated setup |
| 09 | Restore previous KDE PAM configuration |
| 10 / 13 | Service logs / PAM diagnostics |
| 11 | Remove the monitoring service only |
| 12 | Full removal with explicit confirmation and backup |
| 14 / 15 | Enable / disable lock on removal |
| 16 | Read-only KDE key/PAM state diagnostics |
| 17 | Live USB FIDO2 insertion/removal diagnostics |
| 18 / 19 | Enable / disable experimental KDE X11 auto-retry watcher |

*The current terminal interface may display some menu text in French.*

## Automatic dependencies and English interface

The administration dashboard and fallback menu are now in **English**. The package manager's **Install dependencies** action installs the Linux FIDO2/PAM packages and the Python prerequisites for the Textual UI. On Debian, Ubuntu and Linux Mint, this includes `python3-venv` and `python3-pip`.

The first interactive launch also offers to install **Textual inside a dedicated virtual environment**, `/opt/fido2-guard/ui-venv`, using `pip` (requires internet access and Python 3.9+). Confirm with **`y`**. Textual is not installed system-wide. If the virtual environment cannot be created, the manager falls back to the basic menu. Installing prerequisites does not overwrite key registrations or PAM profiles.

Dependency support varies by distribution; in particular, package availability on Arch-based systems may require manual resolution. Verify the actual versions and installed commands before proceeding.

### Key insertion while KDE is already locked

**Re-running Integrated setup (option 7) will not enable automatic switching from a password prompt to the FIDO2 touch prompt.** That feature is **not implemented**. The current daemon monitors USB insertion/removal for lock behavior only, and KDE's lock screen owns the active PAM conversation.

If the key is inserted *after* KDE started a password-only conversation, KDE may not recognize it until authentication is restarted by the lock screen itself. Do not attempt to force `loginctl unlock-session`, inject an OTP, or kill/restart `kscreenlocker` as an automated workaround. Keep password unlock available. A native, version-aware KDE lock-screen integration is required to implement an automatic prompt transition correctly.

To diagnose your current setup without changing PAM:

```bash
sudo bash fido2-guard.sh
# Select "Connected key and KDE status" (option 16).
# Verify the real KDE login and lock screens separately.
```

## Live USB FIDO2 hotplug diagnostics

Use **menu option 17 — Live FIDO2 USB hotplug diagnostics** to observe actual insertion and removal events on Linux, without modifying PAM or the lock screen. This is a useful first check when testing Thetis and YubiKey devices across supported Linux distributions.

Direct command (from your Git clone):

```bash
sudo /usr/bin/python3 fido-hotplug.py --watch
```

Unplug and reinsert your security key. The output should include `REMOVED` and `INSERTED` for recognized USB FIDO2 devices. Press Ctrl+C to stop. The tool uses `fido2-token` and `python3-pyudev`, not a distribution-specific USB polling loop. NFC authenticators are not included.

**This is a diagnostic watcher, not an automatic KDE authenticator.** USB detection proves only that a FIDO2 device is connected, not that it matches a registered PAM credential. The watcher cannot terminate or restart an existing PAM conversation in KScreenLocker, and it never unlocks a session.

The KDE 5.27 lock screen does not provide an independently validated external API for safely replacing an already-active password prompt with an FIDO2 prompt. Delivering this specific UX requires a separately developed and tested KScreenLocker integration, with version-specific handling for Plasma 5 and 6. **Do not run the integrated setup repeatedly to fix this behavior.**

## Modern terminal dashboard

The manager now includes a **full-screen Textual TUI**, with a live action search field, scrollable selection list, detail panel, and status header. It runs in a **dedicated Python virtual environment** under `/opt/fido2-guard/ui-venv`, without installing Python packages into the system interpreter.

On first launch, the script can offer to install Textual. On Debian, Ubuntu, or Linux Mint, if virtual environment creation is unavailable, first run:

```bash
sudo apt install -y python3-venv
```

Then launch again:

```bash
git pull --ff-only
sudo bash fido2-guard.sh
```

When prompted, choose `y` to install the terminal UI. This requires Python 3.9+ and network access to PyPI. Textual is optional; if installation fails, the existing fallback menu remains available. The terminal UI is only an administrative interface and never modifies PAM or unlocks sessions by itself.

## Navigating the menu

In the Textual UI, use the **Up/Down arrow keys** to scroll through the options, **Enter** to select, and **Esc** to exit. Use `/` to focus the search input and `F5` to clear the filter. A basic dialog or plain-text fallback remains available if Textual is missing.

**Updating from v2.7 to v2.8:** Running `git pull --ff-only` and launching `sudo bash fido2-guard.sh` is sufficient to use the updated menu and diagnostic option 16. **Do not rerun option 7** merely to update the menu: integrated installation re-tests PAM and related services and should only be used when setting up or repairing that integration. Existing key mappings and installed service configuration remain unchanged after a Git pull.

## Update from Git

From the cloned repository directory:

```bash
git pull --ff-only
sudo bash fido2-guard.sh
```

When upgrading from an earlier v1.x or v2.x build, **do not purge first**: existing key mappings in `/etc/thetis-auth/u2f_keys` can be reused. Disable the previous monitoring service while testing:

```bash
sudo systemctl disable --now thetis-guard.service
```

Then use option **07** to update the installed component, followed by option **14** if you want to explicitly enable lock-on-removal.

## Service management and troubleshooting

```bash
# Inspect the service
sudo systemctl status thetis-guard.service

# View recent service logs
sudo journalctl -u thetis-guard.service -n 80 --no-pager

# Disable lock-on-removal immediately
sudo systemctl disable --now thetis-guard.service
```

Stopping the daemon does **not** remove registered keys or KDE PAM authentication. If KDE unlock stops working as expected, use **option 09** to restore the prior PAM configuration. Do **not** manually delete `/etc/pam.d/kde`.

To inspect KScreenLocker-related logs:

```bash
journalctl --user -b --no-pager | grep -Ei 'kscreenlocker|kwin|plasmashell|sddm' | tail -80
sudo journalctl -b --no-pager | grep -Ei 'pam_u2f|pam_unix\(kde:auth\)|kscreenlocker' | tail -80
```

If touching a YubiKey types a long string into the password field, that is the keyboard-emulating **OTP interface**, **not** successful FIDO2 authentication.

## Compatibility and security limitations

The installer recognizes `apt`, `dnf`, and `pacman` distributions, but **PAM integration is not guaranteed across all Linux configurations**. KDE's actual PAM service name can depend on how it was built and packaged. Immutable distributions, GNOME, and SELinux-enforcing environments require separate evaluation. On Arch-based systems, `pamtester` might not be available through the default `pacman` repositories.

USB removal detection monitors **recognized FIDO devices**, not exclusively individually registered keys. Therefore an unregistered device may trigger locking, and removing one key may lock the session even when another key remains connected. NFC authenticators are not monitored. The monitoring service itself **does not cryptographically authenticate the key**: that happens through PAM when unlocking.

This project has **not undergone a security audit** and is not a replacement for full-disk encryption or endpoint protection.

## Repository layout

```text
fido2-guard/
├── README.md
├── fido2-guard.sh           # Terminal administration and setup menu
├── fido-removal-guard.py    # USB removal monitor; locks only
├── fido-hotplug.py         # Read-only event diagnostics
├── fido-kde-x11-retry.py   # Optional experimental KDE X11 retry
└── fido-tui.py             # Modern Textual TUI
```

**Version:** 2.9. **License:** No redistribution license has been explicitly granted until a LICENSE file is added.
