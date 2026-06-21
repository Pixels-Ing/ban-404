#!/bin/bash
# update_ban_404.sh — met à jour ban_404.sh ET update_ban_404.sh depuis le dépôt Git.
# Télécharge -> valide (shebang + syntaxe) -> bascule atomique. Jamais "curl | bash".
# L'updater se met aussi à jour lui-même (self-update) : plus besoin de repasser sur
# les serveurs pour propager une évolution de l'updater. Il ajoute aussi BAN404_LANG
# à la conf si elle est absente (langue héritée du shell/système, sinon en).
set -u

UPDATER_VERSION="1.2.3"
CONF_FILE="/etc/ban_404.conf"
TARGET="/usr/local/sbin/ban_404.sh"
SELF="/usr/local/sbin/update_ban_404.sh"
LOG="/var/log/ban_404.log"

# --- i18n : messages multilingues (en, fr, de, es, it). Voir ban_404.sh pour le mécanisme. ---
declare -A T_EN T_FR T_DE T_ES T_IT

T_EN[version.line]="update_ban_404.sh version %s"
T_FR[version.line]="update_ban_404.sh version %s"
T_DE[version.line]="update_ban_404.sh version %s"
T_ES[version.line]="update_ban_404.sh version %s"
T_IT[version.line]="update_ban_404.sh version %s"

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
        --version) t version.line "$UPDATER_VERSION"; exit 0 ;;
        --help|-h) show_help ;;
        *) t err.unknown_opt "$1"; exit 1 ;;
    esac
done

: "${REPO_RAW:=}"
[ -z "$REPO_RAW" ] && { log "$(t upd.repo_undef "$CONF_FILE")"; exit 0; }

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

# --- Migration conf : ajoute BAN404_LANG (commenté, découvrable) s'il manque ---
# Idempotent : ne re-ajoute pas si une ligne active OU commentée existe déjà.
if [ -f "$CONF_FILE" ] && ! grep -qE '^[[:space:]]*#?[[:space:]]*BAN404_LANG=' "$CONF_FILE"; then
    _dl=$(detect_lang)
    {
        printf '\n'
        printf '%s\n' "# Messages language: en (default) | fr | de | es | it"
        printf '%s\n' "# Langue des messages : en (défaut) | fr | de | es | it"
        printf '%s\n' "# Sprache der Meldungen: en (Standard) | fr | de | es | it"
        printf '%s\n' "# Idioma de los mensajes: en (por defecto) | fr | de | es | it"
        printf '%s\n' "# Lingua dei messaggi: en (predefinito) | fr | de | es | it"
        printf '#BAN404_LANG="%s"\n' "$_dl"
    } >> "$CONF_FILE" && log "$(t upd.lang_added "$CONF_FILE" "$_dl")"
fi

# --- Migration conf : ajoute les réglages OPTIONNELS manquants (commentés, découvrables) ---
# NON destructif et idempotent : on n'ajoute QUE les variables totalement absentes
# (ni active, ni commentée) ; un réglage déjà présent (même commenté) est laissé tel quel.
if [ -f "$CONF_FILE" ]; then
    _opt_added=0
    # "nom  ligne-commentée-complète" ; le nom de variable ne contient pas d'espace.
    _OPTVARS=(
        'WINDOW #WINDOW=7200'
        'BAN_TIMEOUT #BAN_TIMEOUT=172800'
        'TAIL_LINES #TAIL_LINES=50000'
        'BAN_THRESHOLD #BAN_THRESHOLD=10'
        'HONEYPOT_SCORE #HONEYPOT_SCORE=100'
        'WHITELIST_CIDR #WHITELIST_CIDR="10.0.0.0/8|192.168.0.0/16"'
        'EXCLUDE_VHOSTS #EXCLUDE_VHOSTS="staging.exemple.com|interne.exemple.com"'
        'WEBHOOK_URL #WEBHOOK_URL=""'
        'NOTIFY_EMAIL #NOTIFY_EMAIL=""'
        'NOTIFY_FROM #NOTIFY_FROM=""'
        'NOTIFY_MIN_BANS #NOTIFY_MIN_BANS=1'
        'NOTIFY_BANS #NOTIFY_BANS=false'
        'DAILY_SUMMARY #DAILY_SUMMARY=false'
    )
    for _e in "${_OPTVARS[@]}"; do
        _name="${_e%% *}"; _line="${_e#* }"
        grep -qE "^[[:space:]]*#?[[:space:]]*${_name}=" "$CONF_FILE" && continue
        if [ "$_opt_added" -eq 0 ]; then
            grep -qE 'Optional settings|R[ée]glages optionnels' "$CONF_FILE" || {
                printf '\n'
                printf '%s\n' "# --- Optional settings (uncomment to override, see help for details) ---"
                printf '%s\n' "# --- Réglages optionnels (décommenter pour surcharger, voir l'aide pour les détails) ---"
                printf '%s\n' "# --- Optionale Einstellungen (zum Überschreiben auskommentieren, Details siehe Hilfe) ---"
                printf '%s\n' "# --- Ajustes opcionales (descomentar para sobrescribir, ver la ayuda para más detalles) ---"
                printf '%s\n' "# --- Impostazioni opzionali (decommentare per sovrascrivere, vedere l'aiuto per i dettagli) ---"
            } >> "$CONF_FILE"
            _opt_added=1
        fi
        printf '%s\n' "$_line" >> "$CONF_FILE"
    done
    [ "$_opt_added" -eq 1 ] && log "$(t upd.optvars_added "$CONF_FILE")"
fi

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

# 2) L'updater lui-même, EN DERNIER. La bascule par 'mv' crée un nouvel inode :
#    le process en cours garde l'ancien inode ouvert et termine sans surprise ;
#    le prochain passage cron utilisera la nouvelle version.
update_file "update_ban_404.sh" "$SELF" "update_ban_404.sh"

exit 0
