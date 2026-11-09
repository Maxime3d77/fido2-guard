#!/usr/bin/env bash
set -Eeuo pipefail
if (( EUID != 0 )); then echo 'Lancer avec sudo bash fido2-guard.sh'; exit 1; fi
SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BASE=/etc/thetis-auth
MAP=$BASE/u2f_keys
LABELS=$BASE/labels.tsv
GUARD=/usr/local/libexec/thetis-fido-guard.py
UNIT=/etc/systemd/system/thetis-guard.service
TEST_PAM=/etc/pam.d/thetis-v2-test
KDE_PAM=/etc/pam.d/kde
MARK='# THETIS-FIDO2-V2 managed; password fallback remains below'
META=$BASE/kde-created-by-manager
USER_MAP=""
PAM_TARGET_META=$BASE/kde-pam-target
OS_ID=unknown; OS_LIKE=''; PKG=unsupported
[[ -r /etc/os-release ]] && { . /etc/os-release; OS_ID=${ID:-unknown}; OS_LIKE=${ID_LIKE:-}; }
case " $OS_ID $OS_LIKE " in
  *' arch '*|*' manjaro '*|*' endeavouros '*|*' cachyos '*) PKG=pacman;;
  *' fedora '*|*' rhel '*|*' centos '*) PKG=dnf;;
  *' debian '*|*' ubuntu '*|*' linuxmint '*) PKG=apt;;
esac
if [[ -e /run/ostree-booted ]]; then PKG=immutable; fi
TARGET=${SUDO_USER:-}
[[ -n "$TARGET" && "$TARGET" != root ]] || TARGET=$(logname 2>/dev/null || true)
[[ -n "$TARGET" && "$TARGET" != root ]] || { echo 'Impossible de trouver le compte cible (utiliser sudo depuis le compte graphique).'; exit 1; }
id "$TARGET" >/dev/null
USER_HOME=$(getent passwd "$TARGET" | cut -d: -f6)
USER_MAP="$MAP"
mkdir -p "$BASE"
chown root:root "$BASE"
chmod 755 "$BASE"

pause(){ read -r -p 'Entrée pour continuer...' _ || :; }
backup(){
 local folder="$BASE/backups/$(date +%Y%m%d-%H%M%S)-$RANDOM"
 install -d -m 700 "$folder"
 for file in "$MAP" "$LABELS" "$TEST_PAM" "$KDE_PAM" "$UNIT"; do
   [[ ! -f "$file" ]] || cp -a "$file" "$folder/$(echo "$file" | tr / _)"
 done
 printf '%s\n' "$folder"
}
need(){ command -v "$1" >/dev/null || { echo "Outil absent : $1. Menu 1 pour les dépendances."; return 1; }; }
validate_map(){
 [[ -f "$MAP" ]] || return 0
 awk -F: '
   /^[[:space:]]*$/ {next}
   NF < 2 || $1 !~ /^[[:alnum:]_.@-]+$/ {bad=1; next}
   {for(i=2;i<=NF;i++) if($i=="")bad=1}
   seen[$1]++
   END {for (u in seen) if (seen[u] > 1) bad=1; exit bad?1:0}
 ' "$MAP" || { echo 'Autorisations ambiguës (doublons ou syntaxe inattendue) : aucune modification.'; return 1; }
}
check_map(){
 [[ -s "$MAP" ]] || { echo 'Aucune clé enregistrée.'; return 1; }
 validate_map || return 1
 local n
 n=$(awk -F: -v u="$TARGET" '$1==u && NF>1 {n++} END{print n+0}' "$MAP")
 [[ "$n" -eq 1 ]] || { echo "Aucune entrée unique pour $TARGET dans le fichier PAM U2F."; return 1; }
}
count(){
 if [[ -s "$MAP" ]]; then
   awk -F: -v u="$TARGET" '$1==u {print NF-1; found=1; exit} END{if(!found) print 0}' "$MAP"
 else echo 0; fi
}
extract_target(){ awk -F: -v u="$TARGET" '$1==u {print; exit}' "$MAP"; }
sync_user_authfile(){
  check_map || return 1
  chown root:root "$BASE" "$MAP"
  chmod 755 "$BASE"
  chmod 644 "$MAP"
  if ! runuser -u "$TARGET" -- test -r "$MAP"; then
    echo "PAM KDE ne peut pas lire $MAP : refus d'activer le verrouillage."; return 1
  fi
  echo "Autorisation publiée : $MAP (root:root 0644, répertoire 0755)."
}

install_deps(){
 case "$PKG" in
  apt) apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-u2f pamu2fcfg fido2-tools python3 python3-pyudev pamtester whiptail;;
  dnf) dnf install -y pam-u2f pamu2fcfg libfido2 python3 python3-pyudev pamtester newt;;
  pacman) pacman -Syu --needed pam-u2f libfido2 python python-pyudev libnewt;;
  *) echo "Distribution $OS_ID : installation automatique non prise en charge."; return 1;;
 esac
 echo 'Sur Arch, pamtester peut être indisponible dans les dépôts standard : l’installation est refusée si absent.'
}
list_keys(){
 echo "=== Clés autorisées pour $TARGET ==="
 if ! check_map; then return 0; fi
 local n; n=$(count); local i label
 for ((i=1;i<=n;i++)); do
   label=$(awk -F '\t' -v k="$i" '$1==k{$1="";sub(/^\t/,"");print;exit}' "$LABELS" 2>/dev/null || true)
   printf '%2d. %s\n' "$i" "${label:-Clé $i (importée)}"
 done
 echo 'Les clés publiques et handles ne sont pas affichés.'
}
atomic_write(){
 local source=$1 dest=$2 tmp
 tmp=$(mktemp "$BASE/.tmp.XXXXXX")
 install -m 644 -o root -g root "$source" "$tmp"
 mv -f "$tmp" "$dest"
}
add_key(){
 need pamu2fcfg || return 1
 echo 'Débranche les autres clés FIDO et branche uniquement la nouvelle.'
 local label out temp oldline fresh n
 read -r -p 'Nom de cette clé : ' label
 [[ -n "$label" && "$label" != *$'\t'* && "$label" != *$'\n'* ]] || { echo 'Nom invalide.'; return 1; }
 validate_map || return 1
 out=$(mktemp); temp=$(mktemp)
 chmod 600 "$out" "$temp"
 echo 'Touche la clé lorsque demandé. Le mode v2 exige la présence utilisateur.'
 if [[ $(count) -gt 0 ]]; then
   check_map || { rm -f "$out" "$temp"; return 1; }
   if ! runuser -u "$TARGET" -- pamu2fcfg -n > "$out"; then
     echo 'Enregistrement FIDO échoué.'; rm -f "$out" "$temp"; return 1
   fi
   [[ $(cat "$out") == :*,* ]] || { echo 'Format -n inattendu.'; rm -f "$out" "$temp"; return 1; }
   oldline=$(extract_target)
   fresh="${oldline}$(tr -d '\n' < "$out")"
 else
   if ! runuser -u "$TARGET" -- pamu2fcfg -u "$TARGET" > "$out"; then
     echo 'Enregistrement FIDO échoué.'; rm -f "$out" "$temp"; return 1
   fi
   [[ $(cat "$out") == "$TARGET":*,* ]] || { echo 'Format inattendu.'; rm -f "$out" "$temp"; return 1; }
   fresh=$(tr -d '\n' < "$out")
 fi
 if [[ -s "$MAP" ]]; then
   awk -F: -v u="$TARGET" -v new="$fresh" '
      BEGIN {done=0}
      /^[[:space:]]*$/ {next}
      $1==u {if(!done){print new; done=1}; next}
      {print}
      END {if(!done) print new}
   ' "$MAP" > "$temp"
 else
   printf '%s\n' "$fresh" > "$temp"
 fi
 echo "Sauvegarde : $(backup)"
 atomic_write "$temp" "$MAP"
 n=$(count)
 printf '%s\t%s\n' "$n" "$label" >> "$LABELS"
 chmod 600 "$LABELS"
 rm -f "$out" "$temp"
 sync_user_authfile || echo "AVERTISSEMENT : échec synchro KDE, verrouillage auto à laisser désactivé."
 echo "Clé #$n enregistrée pour $TARGET ; les autres comptes sont préservés."
 echo 'Tester avec toucher avant de verrouiller la session.'
}
revoke_key(){
 check_map || return 1
 list_keys
 local n idx newmap labeltmp targetline fresh
 n=$(count)
 read -r -p "Numéro à révoquer (1-$n) : " idx
 [[ "$idx" =~ ^[0-9]+$ ]] && ((idx>=1 && idx<=n)) || { echo 'Numéro invalide'; return 1; }
 read -r -p "Confirmer la révocation de la clé $idx (écrire REVOQUER) : " answer
 [[ $answer == REVOQUER ]] || return 0
 newmap=$(mktemp); labeltmp=$(mktemp)
 chmod 600 "$newmap" "$labeltmp"
 targetline=$(extract_target)
 fresh=$(printf '%s\n' "$targetline" | awk -F: -v n="$idx" 'BEGIN{OFS=":"} {out=$1;for(i=2;i<=NF;i++)if(i!=n+1)out=out OFS $i;print out}')
 awk -F: -v u="$TARGET" -v new="$fresh" -v n="$n" '
   /^[[:space:]]*$/ {next}
   $1==u {if(n>1)print new;next}
   {print}
 ' "$MAP" > "$newmap"
 echo "Sauvegarde : $(backup)"
 if [[ -s "$newmap" ]]; then atomic_write "$newmap" "$MAP"; else rm -f "$MAP"; fi
 if ((n==1)); then rm -f "$LABELS"; else
   if [[ -f "$LABELS" ]]; then
     awk -F '\t' -v n="$idx" 'BEGIN{OFS="\t"} $1!=n {if($1>n)$1=$1-1;print}' "$LABELS" > "$labeltmp"
     atomic_write "$labeltmp" "$LABELS"
   fi
 fi
 rm -f "$newmap" "$labeltmp"
 if ((n>1)); then sync_user_authfile || :; fi
 echo 'Révocation effective sur les nouvelles authentifications PAM.'
}
import_old(){
 local home src
 home=$(getent passwd "$TARGET" | cut -d: -f6)
 src="$home/.config/Yubico/u2f_keys"
 [[ ! -s "$MAP" ]] || { echo 'Une base existe déjà : aucun remplacement automatique.'; return 1; }
 [[ -s "$src" ]] || { echo "Aucun fichier utilisateur : $src"; return 1; }
 [[ $(head -n1 "$src" | cut -d: -f1) == "$TARGET" ]] || { echo 'Nom utilisateur différent'; return 1; }
 echo "Sauvegarde : $(backup)"
 atomic_write "$src" "$MAP"
 sync_user_authfile || :
 echo "Import terminé, $(count) clé(s). Tester avec toucher avant PAM KDE."
}
write_test_pam(){
 check_map || return 1
 sync_user_authfile || return 1
 printf 'auth required pam_u2f.so authfile=%s userpresence=1 cue\n' "$USER_MAP" > "$TEST_PAM"
 chmod 644 "$TEST_PAM"
 echo 'PAM isolé créé : /etc/pam.d/thetis-v2-test'
 echo 'Pour tester : sudo pamtester thetis-v2-test '"$TARGET"' authenticate (si pamtester installé).'
 echo 'Débranche toutes les autres clés puis touche la clé testée.'
}
install_guard(){
 need fido2-token || return 1
 need loginctl || return 1
 if ! /usr/bin/python3 -c 'import pyudev' >/dev/null 2>&1; then
   echo 'Dépendance python3-pyudev absente. Installer via le menu 01.'; return 1
 fi
 python3 -m py_compile "$SELF_DIR/fido-removal-guard.py" || return 1
 echo "Sauvegarde : $(backup)"
 systemctl disable --now thetis-guard.service 2>/dev/null || true
 install -o root -g root -m 700 "$SELF_DIR/fido-removal-guard.py" "$GUARD"
 cat > "$UNIT" <<EOF
[Unit]
Description=FIDO2 Guard v2.7 - optional lock on USB FIDO removal
After=systemd-logind.service
Requires=systemd-logind.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 $GUARD $TARGET
User=root
Group=root
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF
 chmod 644 "$UNIT"
 systemctl daemon-reload
 echo 'Surveillance installée mais DÉSACTIVÉE. Menu 14 pour l’activer.'
}
enable_guard(){
 echo 'ACTIVER LE VERROUILLAGE AUTOMATIQUE AU RETRAIT ?'
 echo 'PAM KDE et les clés restent inchangés. Retirer une clé FIDO USB reconnue verrouillera KDE.'
 echo 'Ne pas activer tant que les écrans noirs de KDE ne sont pas résolus.'
 local answer
 read -r -p 'Pour confirmer, saisir ACTIVER : ' answer
 [[ "$answer" == ACTIVER ]] || { echo 'Activation annulée.'; return 1; }
 install_guard || return 1
 systemctl enable --now thetis-guard.service
 systemctl is-active --quiet thetis-guard.service || { echo 'Service non actif.'; return 1; }
 echo 'Verrouillage au retrait ACTIVÉ. Réinsertion = aucune action.'
}
disable_guard(){
 systemctl disable --now thetis-guard.service 2>/dev/null || true
 echo 'Verrouillage au retrait DÉSACTIVÉ. Clés et PAM KDE CONSERVÉS.'
}
remove_guard(){
 systemctl disable --now thetis-guard.service 2>/dev/null || :
 rm -f "$UNIT" "$GUARD"
 systemctl daemon-reload
 echo 'Service supprimé. Autorisations et mot de passe conservés.'
}
pam_diagnostic(){
 echo '=== DIAGNOSTIC KDE / PAM ==='
 echo "Session utilisateur : $TARGET"
 echo 'Services candidats présents :'
 for f in /etc/pam.d/kde /etc/pam.d/kscreenlocker /etc/pam.d/kde-fingerprint /etc/pam.d/other; do
   [[ ! -f "$f" ]] || echo "  $f"
 done
 echo
 echo 'Événements PAM KDE des dernières 24 h (sans données de clé) :'
 journalctl --since '24 hours ago' --no-pager -o cat 2>/dev/null | \
   grep -Ei 'pam_.*\((kde|kscreenlocker|kde-fingerprint):auth\)|kscreenlocker.*pam' | tail -15 || :
 echo
 echo 'KScreenLocker utilise souvent le service kde, mais ce nom peut être modifié à la compilation.'
 echo 'Sans preuve du nom réel, aucune activation PAM automatique n’est sûre.'
}
install_kde_pam(){
 check_map || return 1
 need pamtester || return 1
 pam_diagnostic
 local service target existing template b tmp answer
 echo
 read -r -p 'Nom EXACT du service PAM du verrouilleur KDE vérifié (ex: kde), ou Entrée pour annuler : ' service
 [[ "$service" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo 'Annulé / service invalide.'; return 1; }
 case "$service" in kde|kscreenlocker) ;; *)
   echo 'Service personnalisé : validation manuelle requise. Aucune modification.'; return 1;; esac
 target="/etc/pam.d/$service"
 if [[ -f "$target" ]]; then
   echo "Service PAM existant : $target"
   if grep -Fq "$MARK" "$target"; then echo 'Intégration déjà active.'; return 0; fi
   if grep -Eq '^auth[[:space:]]|^@include[[:space:]]+common-auth' "$target"; then :; else
     echo 'Profil PAM sans règle auth reconnue : arrêt.'; return 1
   fi
 else
   if [[ "$service" != kde || "$PKG" != apt || ! -f /etc/pam.d/common-auth ]]; then
     echo 'Profil absent : création automatique limitée à KDE Debian/Ubuntu/Mint avec common-auth.'; return 1
   fi
   echo 'ATTENTION : /etc/pam.d/kde absent. Le créer n’aura un effet QUE si KDE utilise le service « kde ». '
   echo 'Sur ce système, le nouveau profil inclura common-auth pour préserver le mot de passe.'
   echo 'Ne poursuivre que si les journaux ou la configuration de KScreenLocker confirment ce nom.'
 fi
 if command -v getenforce >/dev/null && [[ $(getenforce 2>/dev/null) == Enforcing ]]; then
   echo 'SELinux Enforcing : intégration PAM automatique désactivée.'; return 1
 fi
 write_test_pam
 echo
 echo 'TEST OBLIGATOIRE : avec une SEULE clé insérée, lancer dans un autre terminal :'
 echo "  sudo pamtester thetis-v2-test '$TARGET' authenticate"
 echo 'Le toucher doit être demandé ET accepté. Contrôler aussi le mot de passe habituel.'
 echo 'Garder une session root / console de secours ouverte pendant le test.'
 read -r -p 'Confirmer test avec toucher ET accès de secours (saisir TEST_OK) : ' answer
 [[ "$answer" == TEST_OK ]] || { echo 'Annulé'; return 0; }
 read -r -p "Confirmer le service KDE réel « $service » (saisir PAM_KDE_CONFIRME) : " answer
 [[ "$answer" == PAM_KDE_CONFIRME ]] || { echo 'Annulé'; return 0; }
 b=$(backup); echo "Sauvegarde : $b"
 if [[ ! -f "$target" ]]; then
   printf 'auth include common-auth\naccount include common-account\npassword include common-password\nsession include common-session\n' > "$target"
   chmod 644 "$target"
   printf '%s\n' "$service" > "$META"
 fi
 tmp=$(mktemp /etc/pam.d/.thetis-pam-XXXXXX)
 { printf '%s\nauth sufficient pam_u2f.so authfile=%s userpresence=1 cue\n' "$MARK" "$USER_MAP"; cat "$target"; } > "$tmp"
 chmod --reference="$target" "$tmp"; chown --reference="$target" "$tmp"
 mv -f "$tmp" "$target"
 printf '%s\n' "$service" > "$PAM_TARGET_META"
 chmod 600 "$META" "$PAM_TARGET_META" 2>/dev/null || :
 echo "PAM activé dans $target. Le mot de passe existant est conservé comme alternative."
 echo 'Tester immédiatement les DEUX méthodes sur KDE. Si échec, menu restauration ou console de secours.'
}
rollback_kde_pam(){
 local target service tmp
 service=kde
 if [[ -f "$PAM_TARGET_META" ]]; then service=$(head -n1 "$PAM_TARGET_META"); fi
 [[ "$service" =~ ^[a-zA-Z0-9_-]+$ ]] || return 1
 target="/etc/pam.d/$service"
 [[ -f "$target" ]] || { echo 'Aucun PAM cible'; return 0; }
 grep -Fxq "$MARK" "$target" || { echo 'Aucun bloc PAM géré détecté'; return 0; }
 [[ $(grep -Fxc "$MARK" "$target") -eq 1 ]] || { echo 'Plusieurs blocs PAM : refus'; return 1; }
 local next
 next=$(grep -A1 -Fx "$MARK" "$target" | sed -n '2p')
 case "$next" in
 "auth sufficient pam_u2f.so authfile=$MAP userpresence=1 cue"|"auth sufficient pam_u2f.so authfile=$USER_MAP userpresence=1 cue") ;;
 *) echo 'Bloc PAM inattendu, refus'; return 1;;
 esac
 echo "Sauvegarde : $(backup)"
 tmp=$(mktemp /etc/pam.d/.fido-rollback-XXXXXX)
 awk -v m="$MARK" -v a="$next" '$0!=m && $0!=a{print}' "$target" > "$tmp"
 chmod --reference="$target" "$tmp"; chown --reference="$target" "$tmp"
 mv -f "$tmp" "$target"
 if [[ -f "$META" && $(cat "$META") == "$service" ]]; then
   if cmp -s "$target" <(printf 'auth include common-auth\naccount include common-account\npassword include common-password\nsession include common-session\n'); then
      rm -f "$target"; echo 'Profil KDE créé par l’outil retiré.'
   fi
 fi
 rm -f "$PAM_TARGET_META" "$META"
 echo 'PAM KDE restauré, mot de passe Linux conservé.'
}
status(){
 echo "OS: $OS_ID ($PKG) | utilisateur: $TARGET"
 echo "Clés: $(count)"
 systemctl --no-pager --full is-enabled thetis-guard.service 2>/dev/null || :
 systemctl --no-pager --full is-active thetis-guard.service 2>/dev/null || :
 local pam_target=/etc/pam.d/kde
 [[ -s "$PAM_TARGET_META" ]] && pam_target=/etc/pam.d/$(cat "$PAM_TARGET_META")
 [[ -f "$pam_target" ]] && grep -Fq "$MARK" "$pam_target" && echo "PAM KDE v2: actif ($pam_target)" || echo 'PAM KDE v2: non confirmé / inactif'
 journalctl -u thetis-guard.service -n 12 --no-pager 2>/dev/null || :
}
complete_purge(){
 echo
 echo '================ SUPPRESSION COMPLETE ================'
 echo "Compte : $TARGET"
 echo 'Cette opération supprimera :'
 echo ' - les services thetis-guard (v1 et v2) et leur activation systemd'
 echo ' - les démons installés dans /usr/local/libexec'
 echo ' - les fichiers FIDO2 /etc/thetis-auth (clés, étiquettes, sauvegardes)'
 echo ' - les PAM de test dédiés à Thetis/FIDO2 Guard'
 echo ' - les scripts de surveillance lancés pour le compte utilisateur'
 echo ' - la ligne FIDO2 ajoutée par la v2 dans PAM KDE, si elle est présente'
 echo 'Le PAM de connexion d’origine et ton mot de passe Linux sont conservés.'
 echo 'Les identifiants FIDO2 enregistrés ailleurs (sites web, autres PC) ne sont pas touchés.'
 echo 'Les clés physiques ne sont jamais réinitialisées.'
 echo 'Une copie de récupération sera conservée sous /root/ avant suppression.'
 echo
 read -r -p 'Pour confirmer, saisir exactement SUPPRIMER TOUT THETIS : ' confirmation
 [[ "$confirmation" == 'SUPPRIMER TOUT THETIS' ]] || { echo 'Annulé : aucune modification.'; return 0; }
 read -r -p "Confirmer la suppression des clés du compte $TARGET (oui/NON) : " confirm2
 [[ "$confirm2" == oui ]] || { echo 'Annulé : aucune modification.'; return 0; }
 local actual_kde_pam="$KDE_PAM"
 if [[ -f "$PAM_TARGET_META" ]]; then
   local service_name; service_name=$(head -n1 "$PAM_TARGET_META")
   [[ "$service_name" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo "Cible PAM non valide"; return 1; }
   actual_kde_pam="/etc/pam.d/$service_name"
 fi
 if [[ -f "$actual_kde_pam" ]] && grep -Fq 'THETIS-FIDO2' "$actual_kde_pam"; then
   if ! grep -Fxq "$MARK" "$actual_kde_pam"; then
     echo 'ARRÊT : marqueur PAM Thetis inconnu : vérifier manuellement /etc/pam.d/kde.'
     return 1
   fi
   if [[ $(grep -Fxc "$MARK" "$actual_kde_pam") -ne 1 ]] ||
      ! grep -A1 -Fx "$MARK" "$actual_kde_pam" | grep -Eq '^auth sufficient pam_u2f.so authfile=.* userpresence=1 cue$'; then
     echo 'ARRÊT : structure PAM inattendue. Aucune suppression.'
     return 1
   fi
 fi
 local recovery
 recovery="/root/thetis-recovery-$(date +%Y%m%d-%H%M%S)-$$"
 install -d -m 700 "$recovery"
 for f in "$actual_kde_pam" "$UNIT" "$GUARD" /usr/local/libexec/thetis-guard.py \
          "$TEST_PAM" /etc/pam.d/thetis-test /etc/pam.d/thetis-guard \
          /etc/systemd/system/thetis-lock.service; do
   if [[ -f "$f" ]]; then
     install -d -m 700 "$recovery/$(dirname "${f#/}")"
     cp -a "$f" "$recovery/${f#/}"
   fi
 done
 if [[ -d "$BASE" ]]; then cp -a "$BASE" "$recovery/thetis-auth"; fi
 echo "Sauvegarde de récupération : $recovery"
 rollback_kde_pam || { echo 'PAM non restauré : purge annulée.'; return 1; }
 systemctl disable --now thetis-guard.service 2>/dev/null || :
 systemctl disable --now thetis-lock.service 2>/dev/null || :
 rm -f -- "$UNIT" /etc/systemd/system/thetis-lock.service
 rm -f -- "$GUARD" /usr/local/libexec/thetis-guard.py
 rm -f -- "$TEST_PAM" /etc/pam.d/thetis-test /etc/pam.d/thetis-guard
 local uid home runtime
 uid=$(id -u "$TARGET")
 home=$(getent passwd "$TARGET" | cut -d: -f6)
 runtime="/run/user/$uid"
 if [[ -S "$runtime/bus" ]]; then
   runuser -u "$TARGET" -- env XDG_RUNTIME_DIR="$runtime" \
     DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" \
     systemctl --user disable --now thetis-lock.service 2>/dev/null || :
 fi
 rm -f -- "$home/.config/systemd/user/thetis-lock.service" \
           "$home/.local/bin/thetis-lock.py"
 if [[ -d "$BASE" ]]; then rm -rf -- "$BASE"; fi
 systemctl daemon-reload
 echo 'La copie utilisateur ~/.config/Yubico/u2f_keys est conservée par défaut.'
 if [[ -f "$home/.config/Yubico/u2f_keys" ]]; then
   echo 'ATTENTION : ce fichier peut aussi servir à d’autres usages PAM U2F.'
   read -r -p 'Supprimer AUSSI le fichier U2F utilisateur ? Saisir SUPPRIMER COPIE : ' answer_copy
   if [[ "$answer_copy" == 'SUPPRIMER COPIE' ]]; then
     install -d -m 700 "$recovery/user-copy"
     cp -a "$home/.config/Yubico/u2f_keys" "$recovery/user-copy/u2f_keys"
     rm -f -- "$home/.config/Yubico/u2f_keys"
     echo 'Copie utilisateur supprimée, avec sauvegarde.'
   else
     echo 'Copie utilisateur conservée.'
   fi
 fi
 echo 'SUPPRESSION TERMINÉE : service, configurations et clés système supprimés.'
 echo "Récupération possible depuis $recovery"
}
confirm_kde_service(){
 local journal service candidates
 journal=$(journalctl --since '14 days ago' --no-pager -o cat 2>/dev/null || true)
 service=''
 if grep -Eq 'pam_[[:alnum:]_]+\(kde:auth\)' <<< "$journal"; then service=kde; fi
 if grep -Eq 'pam_[[:alnum:]_]+\(kscreenlocker:auth\)' <<< "$journal"; then
   [[ -z "$service" ]] || { echo 'Plusieurs services KDE observés, vérification manuelle nécessaire.'; return 1; }
   service=kscreenlocker
 fi
 if [[ -s "$PAM_TARGET_META" ]]; then
   local configured
   configured=$(cat "$PAM_TARGET_META")
   if [[ "$configured" == kde || "$configured" == kscreenlocker ]]; then
     if [[ -n "$service" && "$service" != "$configured" ]]; then
       echo 'Désaccord entre le service PAM déjà configuré et les journaux.'
       return 1
     fi
     service="$configured"
   fi
 fi
 [[ -n "$service" ]] || { echo 'Impossible de déterminer le service PAM réel de KDE. Aucun verrouillage nouveau activé.'; pam_diagnostic; return 1; }
 printf '%s\n' "$service"
}
ensure_kde_pam_auto(){
 local service target tmp existing
 service=$(confirm_kde_service) || return 1
 target="/etc/pam.d/$service"
 echo "Service PAM KDE identifié : $service"
 if command -v getenforce >/dev/null && [[ $(getenforce 2>/dev/null) == Enforcing ]]; then
   echo 'SELinux Enforcing : modification PAM automatique non autorisée.'; return 1
 fi
 if [[ -f "$target" ]] && grep -Fxq "$MARK" "$target"; then
   local oldline newline
   oldline="auth sufficient pam_u2f.so authfile=$MAP userpresence=1 cue"
   newline="auth sufficient pam_u2f.so authfile=$USER_MAP userpresence=1 cue"
   if grep -Fxq "$newline" "$target"; then
     sync_user_authfile || return 1
     echo "PAM KDE déjà configuré et autorisations accessibles ($target)"
     return 0
   fi
   if ! grep -Fxq "$oldline" "$target"; then
      echo 'PAM géré mais contenu inattendu. Aucun remplacement.'; return 1
   fi
   sync_user_authfile || return 1
   echo "Sauvegarde migration PAM : $(backup)"
   tmp=$(mktemp /etc/pam.d/.fido-migrate-XXXXXX)
   sed "s|^auth sufficient pam_u2f.so authfile=$MAP userpresence=1 cue$|$newline|" "$target" > "$tmp"
   chmod --reference="$target" "$tmp"; chown --reference="$target" "$tmp"
   mv -f "$tmp" "$target"
   echo 'Configuration PAM migrée vers un fichier lisible par la session KDE.'
   return 0
 fi
 if [[ ! -f "$target" ]]; then
   if [[ "$PKG" != apt || ! -f /etc/pam.d/common-auth ]]; then
     echo "Profil $target absent; création automatique non sûre sur cette distribution."; return 1
   fi
   echo "KDE utilise $service selon les journaux, création du profil sur base common-auth."
 else
   if ! grep -Eq '^[[:space:]]*auth[[:space:]]|^@include[[:space:]]+common-auth' "$target"; then
     echo 'Profil PAM existant sans méthode auth connue. Abandon.'; return 1
   fi
 fi
 sync_user_authfile || return 1
 echo "Sauvegarde : $(backup)"
 if [[ ! -f "$target" ]]; then
   printf 'auth include common-auth\naccount include common-account\npassword include common-password\nsession include common-session\n' > "$target"
   chmod 644 "$target"
   printf '%s\n' "$service" > "$META"
   chmod 600 "$META"
 fi
 tmp=$(mktemp /etc/pam.d/.thetis-v27-XXXXXX)
 { printf '%s\nauth sufficient pam_u2f.so authfile=%s userpresence=1 cue\n' "$MARK" "$USER_MAP"; cat "$target"; } > "$tmp"
 chmod --reference="$target" "$tmp"
 chown --reference="$target" "$tmp"
 mv -f "$tmp" "$target"
 printf '%s\n' "$service" > "$PAM_TARGET_META"
 chmod 600 "$PAM_TARGET_META"
 return 0
}
guided_install(){
 local service answer count_keys i active_before=0 had_pam=0 created_now=0
 echo '=== INSTALLATION INTÉGRÉE FIDO2 GUARD v2.7 ==='
 echo '1. Dépendances  2. Clés et toucher  3. PAM KDE  4. Mot de passe  5. Verrouillage'
 echo 'Le service ne déverrouille JAMAIS une session. Le toucher FIDO se fait dans KDE.'
 echo 'En cas d’échec, le verrouillage automatique reste arrêté.'
 echo
 if [[ "$PKG" == immutable || "$PKG" == unsupported ]]; then
   echo "Distribution non prise en charge automatiquement : $OS_ID"; return 1
 fi
 if systemctl -q is-active thetis-guard.service; then active_before=1; fi
 systemctl disable --now thetis-guard.service 2>/dev/null || :
 if ! command -v pamu2fcfg >/dev/null || ! command -v fido2-token >/dev/null || ! command -v pamtester >/dev/null || ! command -v whiptail >/dev/null; then
   echo 'Installation des dépendances manquantes.'
   install_deps || return 1
 fi
 for tool in pamtester fido2-token loginctl timeout; do need "$tool" || return 1; done
 if ! check_map; then
   echo 'Aucune autorisation valide. Enregistre une clé dans le menu 02, puis relance l’installation.'
   return 1
 fi
 count_keys=$(count)
 echo "[$count_keys] clé(s) enregistrée(s)."
 write_test_pam || return 1
 echo
 echo 'Vérification de CHAQUE clé : il faut retirer les autres clés pendant chaque essai.'
 echo 'IMPORTANT YubiKey OTP : toucher la clé uniquement lorsque pamtester attend FIDO2,'
 echo 'pas lorsque le curseur est dans un champ de mot de passe.'
 for ((i=1;i<=count_keys;i++)); do
   echo
   echo "CLÉ $i/$count_keys : débranche toutes les clés, puis insère UNIQUEMENT la clé n°$i."
   read -r -p 'Appuie sur Entrée quand elle est prête : ' answer
   echo 'Lancement d’UNE seule vérification cryptographique.'
   echo 'Attends le message « Please touch the device » puis touche la clé FIDO2.'
   echo 'Si une YubiKey saisit un code OTP, ce n’est PAS une preuve FIDO2.'
   if ! timeout 75s pamtester thetis-v2-test "$TARGET" authenticate; then
      echo 'ÉCHEC PAM U2F : vérifie la clé isolée, les autorisations et l’origine PAM.'
      echo 'Aucun nouveau verrouillage ne sera activé.'
      return 1
   fi
   echo "Clé $i : authentification PAM U2F réussie (présence requise par la règle)."
 done
 service=$(confirm_kde_service) || return 1
 echo "Service de verrouillage KDE confirmé par les journaux : $service"
 if [[ -f "$PAM_TARGET_META" ]] && [[ -f "/etc/pam.d/$(cat "$PAM_TARGET_META")" ]] && grep -Fq "$MARK" "/etc/pam.d/$(cat "$PAM_TARGET_META")"; then had_pam=1; fi
 echo 'Configuration de PAM KDE avec conservation de la pile de mot de passe.'
 if ! ensure_kde_pam_auto; then echo 'Échec de configuration PAM. Aucun service activé.'; return 1; fi
 if ((had_pam==0)); then created_now=1; fi
 echo
 echo "TEST DU SERVICE PAM KDE '$service' : garde uniquement une clé et touche-la."
 read -r -p 'Clé prête ? Entrée pour tester : ' answer
 if ! timeout 45s pamtester "$service" "$TARGET" authenticate; then
   echo 'Échec du test PAM KDE.'
   if ((created_now)); then rollback_kde_pam || :; fi
   return 1
 fi
 echo
 echo 'TEST DE SECOURS : débranche TOUTES les clés FIDO, puis saisis ton mot de passe Linux.'
 read -r -p 'Clés retirées ? Entrée pour tester : ' answer
 if ! timeout 65s pamtester "$service" "$TARGET" authenticate; then
   echo 'Mot de passe non validé : arrêt de l’installation.'
   if ((created_now)); then rollback_kde_pam || :; fi
   return 1
 fi
 echo 'Méthodes PAM confirmées : FIDO2 et mot de passe.'
 echo 'Installation du service de verrouillage au retrait (désactivé par défaut).'
 if ! install_guard; then
   echo 'Installation du composant de surveillance impossible. PAM reste restaurable (menu 09).'
   return 1
 fi
 echo
 echo 'INSTALLATION FIDO2/PAM TERMINÉE.'
 echo 'Teste d’abord le déverrouillage réel dans KDE par toucher ou mot de passe.'
 echo 'Si tu veux ensuite le verrouillage au retrait, utilise le MENU 14.'
 echo 'Le menu 15 le désactive sans modifier PAM ni tes clés.'
}
show_header(){
 clear 2>/dev/null || :
 local svc=DÉSACTIVÉ pam=INACTIF
 systemctl -q is-active thetis-guard.service && svc=ACTIF
 [[ -f "$PAM_TARGET_META" ]] && pam=FICHIER_MODIFIÉ
 printf '\033[1;36m╔══════════════════════════════════════════════════════════════════╗\n'
 printf '║                   FIDO2 GUARD  v2.7                            ║\n'
 printf '║           Gestion sécurisée des clés Linux                     ║\n'
 printf '╚══════════════════════════════════════════════════════════════════╝\033[0m\n'
 printf '  Système : %-18s  Paquets : %-10s\n' "$OS_ID" "$PKG"
 printf '  Compte  : %-18s  Clés    : %-10s\n' "$TARGET" "$(count)"
 printf '  Service : %-18s  PAM KDE : %s\n\n' "$svc" "$pam"
}
menu_choice(){
 if command -v whiptail >/dev/null && [[ -t 0 && -t 1 ]]; then
   whiptail --title 'FIDO2 GUARD v2.7 • MENU PRINCIPAL' --backtitle "$OS_ID / $TARGET / $(count) clés" \
     --menu 'Sélectionner une opération :' 25 88 16 \
     1 'Dépendances / apt / dnf / pacman' \
     2 'Ajouter une clé FIDO2' \
     3 'Lister les clés enregistrées' \
     4 'Révoquer une clé (confirmation)' \
     5 'Importer des clés existantes' \
     6 'Tester PAM avec toucher' \
     7 'INSTALLATION INTÉGRÉE (FIDO2 + PAM ; retrait désactivé)' \
     8 'Assistance PAM : utiliser le parcours 07' \
     9 'Restaurer PAM KDE' \
     10 'Statut du service / journaux' \
     11 'Supprimer seulement le service' \
     12 'Purge totale (double confirmation)' \
     13 'Diagnostic PAM KDE' \
     14 'ACTIVER le verrouillage automatique au retrait' \
     15 'DÉSACTIVER le verrouillage au retrait (garder FIDO2)' \
     0 'Quitter' 3>&1 1>&2 2>&3 || echo 0
 else
   cat >&2 <<'EOF'
  [01] Dépendances                  [08] Aide PAM KDE
  [02] Ajouter une clé             [09] Restaurer PAM KDE
  [03] Lister les clés            [10] Statut et journaux
  [04] Révoquer une clé           [11] Supprimer le service
  [05] Importer clés anciennes    [12] PURGE complète
  [06] Test FIDO2 avec toucher    [13] Diagnostic PAM KDE
  [07] INSTALLATION INTÉGRÉE        [14] Activer verrouillage au retrait
  [15] Désactiver verrouillage au retrait  [00] Quitter
EOF
   read -r -p 'Choix : ' choice </dev/tty || choice=0
   echo "$choice"
 fi
}
while true; do
 show_header
 choice=$(menu_choice)
 [[ "$choice" == 0 ]] && break
 if ! case "$choice" in
 1) install_deps;; 2) add_key;; 3) list_keys;; 4) revoke_key;; 5) import_old;;
 6) write_test_pam;; 7) guided_install;; 8) echo 'Pour configurer PAM avec les tests et la méthode de secours, utilise l’option 07.';; 9) rollback_kde_pam;;
 10) status;; 11) remove_guard;; 12) complete_purge;; 13) pam_diagnostic;;
 14) enable_guard;; 15) disable_guard;;
 *) echo 'Choix invalide';;
 esac; then echo 'Opération non terminée / vérifier les messages.'; fi
 pause
done
