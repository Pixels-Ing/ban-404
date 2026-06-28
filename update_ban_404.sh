#!/bin/bash
# update_ban_404.sh — met à jour ban_404.sh ET update_ban_404.sh depuis le dépôt Git.
# Télécharge -> valide (shebang + syntaxe) -> bascule atomique. Jamais "curl | bash".
# L'updater se met aussi à jour lui-même (self-update) : plus besoin de repasser sur
# les serveurs pour propager une évolution de l'updater. Il ajoute aussi BAN404_LANG
# à la conf si elle est absente (langue héritée du shell/système, sinon en).
set -u

UPDATER_VERSION="1.2.10"
CONF_FILE="/etc/ban_404.conf"
TARGET="/usr/local/sbin/ban_404.sh"
SELF="/usr/local/sbin/update_ban_404.sh"
COMPLETION_PATH="/usr/share/bash-completion/completions/ban_404.sh"  # complétion Bash (interactif)
LOG="/var/log/ban_404.log"
UPDATE_STAMP_FILE="/var/lib/ban_404/last_update"   # repère « l'updater a tourné » (lu par le moteur)

# --- i18n : messages multilingues (en, fr, de, es, it). Voir ban_404.sh pour le mécanisme. ---
declare -A T_EN T_FR T_DE T_ES T_IT

T_EN[version.line]="update_ban_404.sh version %s"
T_FR[version.line]="update_ban_404.sh version %s"
T_DE[version.line]="update_ban_404.sh version %s"
T_ES[version.line]="update_ban_404.sh version %s"
T_IT[version.line]="update_ban_404.sh version %s"

T_EN[version.author]="Author: Francis Spiesser - Pixels Ingénierie"
T_FR[version.author]="Auteur : Francis Spiesser - Pixels Ingénierie"
T_DE[version.author]="Autor: Francis Spiesser - Pixels Ingénierie"
T_ES[version.author]="Autor: Francis Spiesser - Pixels Ingénierie"
T_IT[version.author]="Autore: Francis Spiesser - Pixels Ingénierie"

T_EN[help.usage]="Usage: %s [OPTIONS]"
T_FR[help.usage]="Usage : %s [OPTIONS]"
T_DE[help.usage]="Aufruf: %s [OPTIONEN]"
T_ES[help.usage]="Uso: %s [OPCIONES]"
T_IT[help.usage]="Uso: %s [OPZIONI]"

T_EN[help.options_header]="Available options:"
T_FR[help.options_header]="Options disponibles :"
T_DE[help.options_header]="Verfügbare Optionen:"
T_ES[help.options_header]="Opciones disponibles:"
T_IT[help.options_header]="Opzioni disponibili:"

T_EN[help.version]="  --version        Show the version and exit."
T_FR[help.version]="  --version        Afficher la version et quitter."
T_DE[help.version]="  --version        Version anzeigen und beenden."
T_ES[help.version]="  --version        Mostrar la versión y salir."
T_IT[help.version]="  --version        Mostrare la versione e uscire."

T_EN[help.force]="  --force, -f      Redeploy even if files are unchanged."
T_FR[help.force]="  --force, -f      Redéployer même si les fichiers sont identiques."
T_DE[help.force]="  --force, -f      Neu ausrollen, auch wenn die Dateien unverändert sind."
T_ES[help.force]="  --force, -f      Redesplegar aunque los archivos no hayan cambiado."
T_IT[help.force]="  --force, -f      Ridistribuire anche se i file non sono cambiati."

T_EN[help.help]="  --help, -h       Show this help message."
T_FR[help.help]="  --help, -h       Afficher ce message d'aide."
T_DE[help.help]="  --help, -h       Diese Hilfemeldung anzeigen."
T_ES[help.help]="  --help, -h       Mostrar este mensaje de ayuda."
T_IT[help.help]="  --help, -h       Mostrare questo messaggio di aiuto."

T_EN[upd.forced]="Force mode enabled (--force): redeploying even if unchanged."
T_FR[upd.forced]="Mode forcé activé (--force) : redéploiement même si identique."
T_DE[upd.forced]="Force-Modus aktiv (--force): Neuausrollung auch ohne Änderung."
T_ES[upd.forced]="Modo forzado activado (--force): redespliegue aunque sin cambios."
T_IT[upd.forced]="Modalità forzata attiva (--force): ridistribuzione anche se invariato."

T_EN[upd.self_reexec]="Updater self-updated: relaunching the new version in the same run."
T_FR[upd.self_reexec]="Updater auto-mis à jour : relance de la nouvelle version dans le même passage."
T_DE[upd.self_reexec]="Updater selbst aktualisiert: Neustart der neuen Version im selben Lauf."
T_ES[upd.self_reexec]="Updater autoactualizado: relanzando la nueva versión en la misma ejecución."
T_IT[upd.self_reexec]="Updater autoaggiornato: riavvio della nuova versione nella stessa esecuzione."

T_EN[err.unknown_opt]="Unknown option: %s. Use --help."
T_FR[err.unknown_opt]="Option inconnue : %s. Utilisez --help."
T_DE[err.unknown_opt]="Unbekannte Option: %s. Verwenden Sie --help."
T_ES[err.unknown_opt]="Opción desconocida: %s. Use --help."
T_IT[err.unknown_opt]="Opzione sconosciuta: %s. Usare --help."

T_EN[upd.repo_undef]="REPO_RAW not set in %s — update skipped."
T_FR[upd.repo_undef]="REPO_RAW non défini dans %s — MAJ ignorée."
T_DE[upd.repo_undef]="REPO_RAW nicht in %s gesetzt — Update übersprungen."
T_ES[upd.repo_undef]="REPO_RAW no definido en %s — actualización omitida."
T_IT[upd.repo_undef]="REPO_RAW non definito in %s — aggiornamento ignorato."

T_EN[upd.lang_added]="BAN404_LANG added to %s (=%s)."
T_FR[upd.lang_added]="BAN404_LANG ajouté à %s (=%s)."
T_DE[upd.lang_added]="BAN404_LANG zu %s hinzugefügt (=%s)."
T_ES[upd.lang_added]="BAN404_LANG añadido a %s (=%s)."
T_IT[upd.lang_added]="BAN404_LANG aggiunto a %s (=%s)."

T_EN[upd.optvars_added]="Optional settings (commented) added to %s."
T_FR[upd.optvars_added]="Réglages optionnels (commentés) ajoutés à %s."
T_DE[upd.optvars_added]="Optionale Einstellungen (auskommentiert) zu %s hinzugefügt."
T_ES[upd.optvars_added]="Ajustes opcionales (comentados) añadidos a %s."
T_IT[upd.optvars_added]="Impostazioni opzionali (commentate) aggiunte a %s."

T_EN[upd.conf_synced]="Config %s reconciled (multilingual comments / settings)."
T_FR[upd.conf_synced]="Config %s réconciliée (commentaires multilingues / réglages)."
T_DE[upd.conf_synced]="Konfiguration %s abgeglichen (mehrsprachige Kommentare / Einstellungen)."
T_ES[upd.conf_synced]="Config %s reconciliada (comentarios multilingües / ajustes)."
T_IT[upd.conf_synced]="Config %s riconciliata (commenti multilingue / impostazioni)."

T_EN[upd.dl_fail]="%s: download failed (%s)"
T_FR[upd.dl_fail]="%s : téléchargement KO (%s)"
T_DE[upd.dl_fail]="%s: Download fehlgeschlagen (%s)"
T_ES[upd.dl_fail]="%s: descarga fallida (%s)"
T_IT[upd.dl_fail]="%s: download non riuscito (%s)"

T_EN[upd.empty]="%s: empty file — aborting"
T_FR[upd.empty]="%s : fichier vide — abandon"
T_DE[upd.empty]="%s: leere Datei — Abbruch"
T_ES[upd.empty]="%s: archivo vacío — cancelando"
T_IT[upd.empty]="%s: file vuoto — annullamento"

T_EN[upd.shebang]="%s: unexpected shebang — aborting"
T_FR[upd.shebang]="%s : shebang inattendu — abandon"
T_DE[upd.shebang]="%s: unerwarteter Shebang — Abbruch"
T_ES[upd.shebang]="%s: shebang inesperado — cancelando"
T_IT[upd.shebang]="%s: shebang imprevisto — annullamento"

T_EN[upd.syntax]="%s: invalid syntax — aborting (nothing replaced)"
T_FR[upd.syntax]="%s : syntaxe invalide — abandon (rien remplacé)"
T_DE[upd.syntax]="%s: ungültige Syntax — Abbruch (nichts ersetzt)"
T_ES[upd.syntax]="%s: sintaxis no válida — cancelando (no se reemplazó nada)"
T_IT[upd.syntax]="%s: sintassi non valida — annullamento (nulla sostituito)"

T_EN[upd.mktemp_fail]="%s: target mktemp failed"
T_FR[upd.mktemp_fail]="%s : mktemp cible KO"
T_DE[upd.mktemp_fail]="%s: mktemp für Ziel fehlgeschlagen"
T_ES[upd.mktemp_fail]="%s: mktemp de destino fallido"
T_IT[upd.mktemp_fail]="%s: mktemp destinazione non riuscito"

T_EN[upd.swap_fail]="%s: switch failed"
T_FR[upd.swap_fail]="%s : bascule KO"
T_DE[upd.swap_fail]="%s: Umschaltung fehlgeschlagen"
T_ES[upd.swap_fail]="%s: cambio fallido"
T_IT[upd.swap_fail]="%s: commutazione non riuscita"

T_EN[upd.prep_fail]="%s: preparation failed"
T_FR[upd.prep_fail]="%s : préparation KO"
T_DE[upd.prep_fail]="%s: Vorbereitung fehlgeschlagen"
T_ES[upd.prep_fail]="%s: preparación fallida"
T_IT[upd.prep_fail]="%s: preparazione non riuscita"

T_EN[upd.updated_ver]="%s updated (version %s)."
T_FR[upd.updated_ver]="%s mis à jour (version %s)."
T_DE[upd.updated_ver]="%s aktualisiert (Version %s)."
T_ES[upd.updated_ver]="%s actualizado (versión %s)."
T_IT[upd.updated_ver]="%s aggiornato (versione %s)."

T_EN[upd.updated]="%s updated."
T_FR[upd.updated]="%s mis à jour."
T_DE[upd.updated]="%s aktualisiert."
T_ES[upd.updated]="%s actualizado."
T_IT[upd.updated]="%s aggiornato."

T_EN[upd.repo_migrated]="REPO_RAW migrated to %s (PixelsIng -> Pixels-Ing)."
T_FR[upd.repo_migrated]="REPO_RAW migré vers %s (PixelsIng -> Pixels-Ing)."
T_DE[upd.repo_migrated]="REPO_RAW migriert zu %s (PixelsIng -> Pixels-Ing)."
T_ES[upd.repo_migrated]="REPO_RAW migrado a %s (PixelsIng -> Pixels-Ing)."
T_IT[upd.repo_migrated]="REPO_RAW migrato a %s (PixelsIng -> Pixels-Ing)."

# Détection de la langue : locale du shell (ou /etc/default/locale en repli pour cron).
detect_lang() {
    local l="${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}"
    if [ -z "$l" ] && [ -r /etc/default/locale ]; then
        l=$(. /etc/default/locale 2>/dev/null; printf '%s' "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}")
    fi
    l="${l%%.*}"; l="${l%%_*}"; l="${l,,}"
    case "$l" in en|fr|de|es|it) printf '%s' "$l" ;; *) printf '%s' en ;; esac
}

log(){ printf '%s [update] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG" 2>/dev/null; }

[ -f "$CONF_FILE" ] && . "$CONF_FILE"

# Résolution de la langue : conf > locale du shell > en. Puis validation.
: "${BAN404_LANG:=$(detect_lang)}"
BAN404_LANG="${BAN404_LANG,,}"
case "$BAN404_LANG" in en|fr|de|es|it) ;; *) BAN404_LANG=en ;; esac

# t <cle> [args...] : renvoie la traduction (\n du format interprétés) + saut de ligne final.
t() {
    local key="$1"; shift
    local ref="T_${BAN404_LANG^^}[$key]"
    local fmt="${!ref-}"
    [ -z "$fmt" ] && fmt="${T_EN[$key]-}"
    [ -z "$fmt" ] && fmt="$key"
    # '--' : empêche printf d'interpréter un format commençant par '-' comme une option.
    # shellcheck disable=SC2059
    printf -- "$fmt\n" "$@"
}

show_help() {
    t version.line "$UPDATER_VERSION"
    t version.author
    t help.usage "$0"
    echo ""
    t help.options_header
    t help.force
    t help.version
    t help.help
    exit 0
}

FORCE=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force|-f) FORCE=true; shift ;;
        --version) t version.line "$UPDATER_VERSION"; t version.author; exit 0 ;;
        --help|-h) show_help ;;
        *) t err.unknown_opt "$1"; exit 1 ;;
    esac
done

: "${REPO_RAW:=}"
[ -z "$REPO_RAW" ] && { log "$(t upd.repo_undef "$CONF_FILE")"; exit 0; }

# Trace d'exécution lue par le moteur (« l'updater a tourné »). Touchée même si un download échoue
# ensuite : prouve que cron.daily s'est bien déclenché, pour que le moteur ne double pas la MAJ
# (filet self_heal_update_trigger côté ban_404.sh, déclenché si ce repère vieillit > ~36 h).
mkdir -p "$(dirname "$UPDATE_STAMP_FILE")" 2>/dev/null && : > "$UPDATE_STAMP_FILE" 2>/dev/null

# --- Migration conf : transfert du dépôt PixelsIng -> Pixels-Ing (réécrit REPO_RAW) ---
# One-shot : retirable une fois le parc migré (le case ne re-matche pas après coup).
case "$REPO_RAW" in
    */PixelsIng/*)
        _new=$(printf '%s' "$REPO_RAW" | sed 's#/PixelsIng/#/Pixels-Ing/#')
        if [ -f "$CONF_FILE" ] && grep -q '^REPO_RAW=' "$CONF_FILE"; then
            _tmp=$(mktemp) || _tmp=""
            if [ -n "$_tmp" ] && sed "s#^REPO_RAW=.*#REPO_RAW=\"$_new\"#" "$CONF_FILE" > "$_tmp" && cat "$_tmp" > "$CONF_FILE"; then
                log "$(t upd.repo_migrated "$_new")"
            fi
            [ -n "$_tmp" ] && rm -f "$_tmp"
        fi
        REPO_RAW="$_new"
        ;;
esac

# >>> RECONCILE_BLOCK_BEGIN (testable par extraction entre les marqueurs) ---------------------
# Migration conf : RÉCONCILIATION canonique multilingue (5 langues).
# Principe (validé) : on relève les variables ACTIVES (lignes non commentées, valeurs
# PRÉSERVÉES), puis on régénère TOUTE la structure commentée (en-tête de fichier, blocs
# explicatifs, en-têtes de section, valeurs commentées par défaut) en en (défaut), fr, de, es, it.
# NON destructif pour le comportement : seules les lignes de COMMENTAIRE changent ; les valeurs
# actives sont reportées telles quelles ; les variables actives inconnues sont conservées.
# Idempotent (sortie déterministe).
C_FHDR=(
"# /etc/ban_404.conf — LOCAL per-server configuration (NOT versioned)."
"# /etc/ban_404.conf — configuration LOCALE par serveur (NON versionnée)."
"# /etc/ban_404.conf — LOKALE Konfiguration pro Server (NICHT versioniert)."
"# /etc/ban_404.conf — configuración LOCAL por servidor (NO versionada)."
"# /etc/ban_404.conf — configurazione LOCALE per server (NON versionata).")
C_REPO=(
"# Repo raw URL (no trailing slash), used by the self-updater."
"# URL raw du dépôt (sans slash final), utilisée par le self-updater."
"# Raw-URL des Repos (ohne abschließenden Schrägstrich), vom Self-Updater verwendet."
"# URL raw del repositorio (sin barra final), usada por el self-updater."
"# URL raw del repository (senza slash finale), usata dal self-updater.")
C_WLIP=(
"# IPs to NEVER ban (exact match, separated by | )."
"# IP à ne JAMAIS bannir (correspondance exacte, séparées par | )."
"# Niemals zu sperrende IPs (exakte Übereinstimmung, durch | getrennt)."
"# IP que NUNCA bloquear (coincidencia exacta, separadas por | )."
"# IP da non bloccare MAI (corrispondenza esatta, separati da | ).")
C_LANG=(
"# Messages language: en (default) | fr | de | es | it"
"# Langue des messages : en (défaut) | fr | de | es | it"
"# Sprache der Meldungen: en (Standard) | fr | de | es | it"
"# Idioma de los mensajes: en (por defecto) | fr | de | es | it"
"# Lingua dei messaggi: en (predefinito) | fr | de | es | it")
C_H_opt=(
"# --- Optional settings (uncomment to override, see help for details) ---"
"# --- Réglages optionnels (décommenter pour surcharger, voir l'aide pour les détails) ---"
"# --- Optionale Einstellungen (zum Überschreiben auskommentieren, Details siehe Hilfe) ---"
"# --- Ajustes opcionales (descomentar para sobrescribir, ver la ayuda para más detalles) ---"
"# --- Impostazioni opzionali (decommentare per sovrascrivere, vedere l'aiuto per i dettagli) ---")
C_H_cidr=(
"# --- CIDR whitelist / subnets to NEVER ban (separated by | ) ---"
"# --- Whitelist CIDR / sous-réseaux à ne JAMAIS bannir (séparés par | ) ---"
"# --- CIDR-Whitelist / niemals zu sperrende Subnetze (durch | getrennt) ---"
"# --- Lista blanca CIDR / subredes que NUNCA bloquear (separadas por | ) ---"
"# --- Whitelist CIDR / sottoreti da non bloccare MAI (separate da | ) ---")
C_H_vhosts=(
"# --- Vhosts to EXCLUDE from analysis (folder names under /var/www, separated by | ) ---"
"# --- Vhosts à EXCLURE de l'analyse (noms de dossier sous /var/www, séparés par | ) ---"
"# --- Von der Analyse auszuschließende Vhosts (Ordnernamen unter /var/www, durch | getrennt) ---"
"# --- Vhosts a EXCLUIR del análisis (nombres de carpeta en /var/www, separados por | ) ---"
"# --- Vhost da ESCLUDERE dall'analisi (nomi di cartella sotto /var/www, separati da | ) ---")
C_H_notif=(
"# --- Notifications (empty => disabled; messages in the BAN404_LANG language) ---"
"# --- Notifications (vides => désactivées ; messages dans la langue BAN404_LANG) ---"
"# --- Benachrichtigungen (leer => deaktiviert; Meldungen in der Sprache BAN404_LANG) ---"
"# --- Notificaciones (vacías => desactivadas; mensajes en el idioma BAN404_LANG) ---"
"# --- Notifiche (vuote => disattivate; messaggi nella lingua BAN404_LANG) ---")
C_H_motifs=(
"# --- Detection patterns (awk regex) — ADVANCED: override only if you know what you are doing ---"
"# --- Motifs de détection (regex awk) — AVANCÉ : ne surcharger qu'en connaissance de cause ---"
"# --- Erkennungsmuster (awk-Regex) — FORTGESCHRITTEN: nur mit Sachkenntnis überschreiben ---"
"# --- Patrones de detección (regex awk) — AVANZADO: sobrescribir solo con conocimiento ---"
"# --- Pattern di rilevamento (regex awk) — AVANZATO: sovrascrivere solo con cognizione di causa ---")
C_OTHER=(
"# --- Other active settings preserved as-is ---"
"# --- Autres réglages actifs conservés tels quels ---"
"# --- Sonstige aktive Einstellungen unverändert beibehalten ---"
"# --- Otros ajustes activos conservados tal cual ---"
"# --- Altre impostazioni attive conservate così come sono ---")
C_SEC=(opt cidr vhosts notif motifs)
C_opt_v=( $'WINDOW\t#WINDOW=7200' $'BAN_TIMEOUT\t#BAN_TIMEOUT=172800' $'TAIL_LINES\t#TAIL_LINES=50000' $'BAN_THRESHOLD\t#BAN_THRESHOLD=10' $'HONEYPOT_SCORE\t#HONEYPOT_SCORE=100' $'HONEYPOT_BAN_TIMEOUT\t#HONEYPOT_BAN_TIMEOUT=604800' $'RESOLVE_PTR\t#RESOLVE_PTR=false' $'PTR_TIMEOUT\t#PTR_TIMEOUT=2' )
C_cidr_v=( $'WHITELIST_CIDR\t#WHITELIST_CIDR="10.0.0.0/8|192.168.0.0/16"' )
C_vhosts_v=( $'EXCLUDE_VHOSTS\t#EXCLUDE_VHOSTS="staging.exemple.com|interne.exemple.com"' )
C_notif_v=( $'SERVER_NICKNAME\t#SERVER_NICKNAME=""' $'WEBHOOK_URL\t#WEBHOOK_URL=""' $'NOTIFY_EMAIL\t#NOTIFY_EMAIL=""' $'NOTIFY_FROM\t#NOTIFY_FROM=""' $'NOTIFY_MIN_BANS\t#NOTIFY_MIN_BANS=1' $'NOTIFY_BANS\t#NOTIFY_BANS=false' $'DAILY_SUMMARY\t#DAILY_SUMMARY=false' )
C_motifs_v=( $'HONEYPOT_PATTERN\t#HONEYPOT_PATTERN='\''\.env|wp-config\.php|phpmyadmin|config\.json|setup\.php|actuator|xmlrpc\.php'\''' $'NOISE_PATTERN\t#NOISE_PATTERN='\''\.(jpg|jpeg|png|gif|webp|ico|css|js|svg|woff2?|map)$|apple-touch-icon|favicon|browserconfig\.xml|mstile|autodiscover\.xml|sitemap\.xml|robots\.txt|ads\.txt|\.well-known/(security\.txt|pki-validation)'\''' )
C_KNOWN=" REPO_RAW WHITELIST_IP BAN404_LANG WINDOW BAN_TIMEOUT TAIL_LINES BAN_THRESHOLD HONEYPOT_SCORE HONEYPOT_BAN_TIMEOUT WHITELIST_CIDR EXCLUDE_VHOSTS SERVER_NICKNAME WEBHOOK_URL NOTIFY_EMAIL NOTIFY_FROM NOTIFY_MIN_BANS NOTIFY_BANS DAILY_SUMMARY RESOLVE_PTR PTR_TIMEOUT HONEYPOT_PATTERN NOISE_PATTERN "

reconcile_conf() {  # $1 = chemin de la conf
    local f="$1" line t var sec entry def tmp pairs
    declare -A ACTIVE
    # 1) Relève des variables ACTIVES (lignes non commentées, non vides ; valeur préservée).
    while IFS= read -r line || [ -n "$line" ]; do
        t="${line#"${line%%[![:space:]]*}"}"
        case "$t" in ''|'#'*) continue ;; esac
        if [[ "$t" =~ ^([A-Za-z_][A-Za-z0-9_]*)= ]]; then ACTIVE["${BASH_REMATCH[1]}"]="$t"; fi
    done < "$f"
    # 2) Réécriture canonique.
    tmp=$(mktemp) || return 1
    {
        printf '%s\n' "${C_FHDR[@]}"
        printf '\n'; printf '%s\n' "${C_REPO[@]}"
        if [ -n "${ACTIVE[REPO_RAW]+x}" ]; then printf '%s\n' "${ACTIVE[REPO_RAW]}"; else printf '%s\n' '#REPO_RAW=""'; fi
        printf '\n'; printf '%s\n' "${C_WLIP[@]}"
        if [ -n "${ACTIVE[WHITELIST_IP]+x}" ]; then printf '%s\n' "${ACTIVE[WHITELIST_IP]}"; else printf '%s\n' '#WHITELIST_IP="127.0.0.1"'; fi
        printf '\n'; printf '%s\n' "${C_LANG[@]}"
        if [ -n "${ACTIVE[BAN404_LANG]+x}" ]; then printf '%s\n' "${ACTIVE[BAN404_LANG]}"; else printf '#BAN404_LANG="%s"\n' "$(detect_lang)"; fi
        for sec in "${C_SEC[@]}"; do
            printf '\n'; eval "printf '%s\n' \"\${C_H_${sec}[@]}\""
            eval "pairs=(\"\${C_${sec}_v[@]}\")"
            for entry in "${pairs[@]}"; do
                var="${entry%%$'\t'*}"; def="${entry#*$'\t'}"
                if [ -n "${ACTIVE[$var]+x}" ]; then printf '%s\n' "${ACTIVE[$var]}"; else printf '%s\n' "$def"; fi
            done
        done
        # Variables actives NON reconnues : conservées (ordre trié = déterministe).
        local other=0 k
        for k in $(printf '%s\n' "${!ACTIVE[@]}" | LC_ALL=C sort); do
            case "$C_KNOWN" in *" $k "*) continue ;; esac
            [ "$other" = 0 ] && { printf '\n'; printf '%s\n' "${C_OTHER[@]}"; other=1; }
            printf '%s\n' "${ACTIVE[$k]}"
        done
    } > "$tmp"
    cat "$tmp" > "$f"
    rm -f "$tmp"
}

if [ -f "$CONF_FILE" ]; then
    _cb=$(cksum < "$CONF_FILE" 2>/dev/null)
    reconcile_conf "$CONF_FILE"
    _ca=$(cksum < "$CONF_FILE" 2>/dev/null)
    [ "$_cb" != "$_ca" ] && log "$(t upd.conf_synced "$CONF_FILE")"
fi
# >>> RECONCILE_BLOCK_END ---------------------------------------------------------------------

# Télécharge $1 dans un fichier temporaire dont le chemin est émis sur stdout.
# Retourne != 0 (et n'émet rien) en cas d'échec.
download(){
    local url="$1" tmp
    tmp=$(mktemp /tmp/ban_404.XXXXXX) || return 1
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --max-time 30 "$url" -o "$tmp" || { rm -f "$tmp"; return 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 30 -O "$tmp" "$url" || { rm -f "$tmp"; return 1; }
    else
        rm -f "$tmp"; return 1
    fi
    printf '%s' "$tmp"
}

# update_file <nom-dans-dépôt> <chemin-cible> <label>
#   Télécharge, valide (non vide + shebang + bash -n), et bascule atomiquement si
#   le contenu diffère. Code retour : 0 = bascule effectuée, 1 = déjà à jour,
#   2 = échec (rien remplacé).
update_file(){
    local name="$1" target="$2" label="$3" url tmp dir new ver
    url="$REPO_RAW/$name"

    tmp=$(download "$url") || { log "$(t upd.dl_fail "$label" "$url")"; return 2; }

    # Validations avant toute bascule
    [ -s "$tmp" ] || { log "$(t upd.empty "$label")"; rm -f "$tmp"; return 2; }
    head -n1 "$tmp" | grep -q '^#!/bin/bash' || { log "$(t upd.shebang "$label")"; rm -f "$tmp"; return 2; }
    bash -n "$tmp" 2>/dev/null || { log "$(t upd.syntax "$label")"; rm -f "$tmp"; return 2; }

    # Déjà à jour ? (--force court-circuite cette vérification)
    if [ "$FORCE" != true ] && [ -f "$target" ] && cmp -s "$tmp" "$target"; then rm -f "$tmp"; return 1; fi

    # Bascule atomique (copie dans le même répertoire que la cible puis mv), avec sauvegarde
    dir=$(dirname "$target")
    new=$(mktemp "$dir/.ban_404.XXXXXX") || { log "$(t upd.mktemp_fail "$label")"; rm -f "$tmp"; return 2; }
    if cp "$tmp" "$new" && chmod 755 "$new"; then
        [ -f "$target" ] && cp -a "$target" "${target}.bak" 2>/dev/null || true
        if mv -f "$new" "$target"; then
            rm -f "$tmp"
            ver=$(grep -m1 -E '^(BAN404_VERSION|UPDATER_VERSION)=' "$target" | cut -d'"' -f2)
            if [ -n "$ver" ]; then log "$(t upd.updated_ver "$label" "$ver")"; else log "$(t upd.updated "$label")"; fi
            return 0
        fi
        rm -f "$new" "$tmp"; log "$(t upd.swap_fail "$label")"; return 2
    fi
    rm -f "$new" "$tmp"; log "$(t upd.prep_fail "$label")"; return 2
}

# Trace explicite quand on force (redéploiement même si identique).
[ "$FORCE" = true ] && log "$(t upd.forced)"

# 1) Le moteur de détection/ban.
update_file "ban_404.sh" "$TARGET" "ban_404.sh"

# 1bis) Le fichier de complétion Bash (interactif uniquement, aucun impact sur le cron). Déposé
#    SEULEMENT si bash-completion est présent (sinon rien ne le sourcerait) ; auto-correcteur, car
#    re-testé à chaque passage si le paquet est posé plus tard. mkdir car la bascule de update_file
#    fait un mktemp dans le répertoire de la cible, qui doit donc exister. Réutilise les clés upd.*.
if [ -d /usr/share/bash-completion ]; then
    mkdir -p "$(dirname "$COMPLETION_PATH")" 2>/dev/null
    update_file "ban_404.completion.bash" "$COMPLETION_PATH" "completion"
fi

# 2) L'updater lui-même, EN DERNIER. La bascule par 'mv' crée un nouvel inode : le process en
#    cours garde l'ancien inode ouvert et termine sans surprise.
update_file "update_ban_404.sh" "$SELF" "update_ban_404.sh"; _rc_self=$?

# Auto-relance immédiate après une VRAIE bascule de l'updater : la nouvelle version reprend la main
# DANS LE MÊME passage (réconciliation conf + migrations à jour → plus de décalage d'un cycle, p.ex.
# une nouvelle variable de conf apparaît dès cette exécution). Pas de boucle : au tour suivant
# l'updater est déjà à jour (rc != 0) ; le garde BAN404_SELF_REEXEC neutralise aussi le cas --force.
# La nouvelle version est déjà validée (shebang + bash -n) avant la bascule : exec ne lance jamais
# un script cassé, et remplace le process courant (pas de second process concurrent).
if [ "$_rc_self" -eq 0 ] && [ "${BAN404_SELF_REEXEC:-0}" != 1 ]; then
    log "$(t upd.self_reexec)"
    export BAN404_SELF_REEXEC=1
    exec "$SELF"
fi

exit 0
