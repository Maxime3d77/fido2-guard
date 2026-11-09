#!/usr/bin/env python3
"""Interactive Textual front end for FIDO2 Guard.

Only returns a menu action to the existing Bash manager; does not change PAM,
USB device access, or the lock state. Requires Python >=3.9 and textual.
"""
import sys
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, OptionList, Static
from textual.widgets.option_list import Option

ACTIONS = [
    ("1", "Installer les dépendances", "ENVIRONNEMENT", "Installe les utilitaires nécessaires (apt / dnf / pacman)."),
    ("2", "Ajouter une clé FIDO2", "CLÉS DE SÉCURITÉ", "Enregistre une clé supplémentaire sans effacer les autres."),
    ("3", "Afficher les clés enregistrées", "CLÉS DE SÉCURITÉ", "Liste les identifiants de clés et leurs étiquettes."),
    ("4", "Révoquer une clé", "CLÉS DE SÉCURITÉ", "Retire une autorisation après confirmation."),
    ("5", "Importer mes anciennes clés", "CLÉS DE SÉCURITÉ", "Importe un fichier U2F existant si la base est vide."),
    ("6", "Préparer le test PAM FIDO2", "AUTHENTIFICATION", "Crée un profil PAM de test isolé."),
    ("7", "Installation intégrée / réparation", "AUTHENTIFICATION", "Installe ou répare PAM et le service ; à éviter pour une simple mise à jour du menu."),
    ("8", "Aide à la configuration PAM", "AUTHENTIFICATION", "Explique le parcours d'installation sécurisée."),
    ("9", "Restaurer PAM KDE", "AUTHENTIFICATION", "Restaure le profil PAM modifié par le gestionnaire."),
    ("10", "Statut du système et journaux", "SURVEILLANCE", "Affiche l'état du service et les journaux récents."),
    ("11", "Supprimer le service de retrait", "SURVEILLANCE", "Désinstalle uniquement le démon de retrait USB."),
    ("12", "Purge complète", "MAINTENANCE", "Supprime les paramètres du gestionnaire avec sauvegarde et confirmations."),
    ("13", "Diagnostic PAM KDE", "DIAGNOSTIC", "Analyse les profils PAM et la configuration de KDE."),
    ("14", "Activer le verrouillage au retrait", "SURVEILLANCE", "Verrouille la session si un périphérique FIDO2 USB connu est retiré."),
    ("15", "Désactiver le verrouillage au retrait", "SURVEILLANCE", "Conserve PAM et les clés, arrête uniquement le démon."),
    ("16", "Détection de la clé et état KDE", "DIAGNOSTIC", "Vérifie la présence USB et la règle FIDO2 sans déverrouiller KDE."),
]
BY_ID = {item[0]: item for item in ACTIONS}


class GuardUI(App):
    TITLE = "FIDO2 GUARD"
    SUB_TITLE = "Security key control center · v2.8"
    CSS = """
    Screen { background: #0b1320; color: #e4edf9; }
    Header { background: #101f34; color: #7fc4fc; }
    Footer { background: #101f34; }
    #hero { dock: top; height: 5; padding: 1 3; background: #10243a; color: #d7ebff; }
    #hero_title { text-style: bold; color: #80c8ff; height: 1; }
    #hero_status { color: #b2c6db; height: 1; }
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
        Binding("escape", "quit", "Quitter"),
        Binding("ctrl+q", "quit", "Quitter", show=False),
        Binding("slash", "focus_search", "Rechercher"),
        Binding("f5", "clear_search", "Effacer filtre"),
    ]

    def __init__(self, output: Path, user: str, distro: str, keys: str, service: str):
        super().__init__()
        self.output = output
        self.user = user
        self.distro = distro
        self.keys = keys
        self.service = service

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Vertical(id="hero"):
            yield Static("◆  FIDO2 GUARD   /   ADMINISTRATION", id="hero_title")
            yield Static(
                f"Compte  {self.user}    ·    Distribution  {self.distro}    ·    Clés  {self.keys}    ·    Retrait  {self.service}",
                id="hero_status",
            )
        with Horizontal(id="workspace"):
            with Vertical(id="left"):
                yield Input(placeholder="Filtrer les actions…  (touche /)", id="search")
                yield OptionList(*[Option(f"{int(n):>2}    {label}", id=n) for n, label, _, _ in ACTIONS], id="items")
            with Vertical(id="right"):
                yield Static("CHOISISSEZ UNE ACTION", id="detail_title")
                yield Static("NAVIGATION", id="detail_group")
                yield Static("↑ ↓  Déplacer la sélection\nEntrée  Exécuter\n/  Rechercher\nÉchap  Quitter", id="detail_text")
                yield Static("La présence USB ne déverrouille jamais la session sans authentification PAM.", id="notice")
        yield Static("↑↓ Navigation   •   Enter Sélection   •   / Recherche   •   Esc Quitter", id="help")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#items", OptionList).focus()
        self.update_detail()

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
            self.query_one("#detail_title", Static).update("Aucun résultat")
            self.query_one("#detail_group", Static).update("RECHERCHE")
            self.query_one("#detail_text", Static).update("Modifie les termes recherchés.")

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
