#!/bin/bash
# update_ban_404.sh — met a jour ban_404.sh ET update_ban_404.sh depuis le depot Git.
# Telecharge -> valide (shebang + syntaxe) -> bascule atomique. Jamais "curl | bash".
# L'updater se met aussi a jour lui-meme (self-update) : plus besoin de repasser sur
# les serveurs pour propager une evolution de l'updater.
set -u

CONF_FILE="/etc/ban_404.conf"
TARGET="/usr/local/sbin/ban_404.sh"
SELF="/usr/local/sbin/update_ban_404.sh"
LOG="/var/log/ban_404.log"

log(){ printf '%s [update] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG" 2>/dev/null; }

[ -f "$CONF_FILE" ] && . "$CONF_FILE"
: "${REPO_RAW:=}"
[ -z "$REPO_RAW" ] && { log "REPO_RAW non defini dans $CONF_FILE — MAJ ignoree."; exit 0; }

# Telecharge $1 dans un fichier temporaire dont le chemin est emis sur stdout.
# Retourne != 0 (et n'emet rien) en cas d'echec.
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

# update_file <nom-dans-depot> <chemin-cible> <label>
#   Telecharge, valide (non vide + shebang + bash -n), et bascule atomiquement si
#   le contenu differe. Code retour : 0 = bascule effectuee, 1 = deja a jour,
#   2 = echec (rien remplace).
update_file(){
    local name="$1" target="$2" label="$3" url tmp dir new ver
    url="$REPO_RAW/$name"

    tmp=$(download "$url") || { log "$label : telechargement KO ($url)"; return 2; }

    # Validations avant toute bascule
    [ -s "$tmp" ] || { log "$label : fichier vide — abandon"; rm -f "$tmp"; return 2; }
    head -n1 "$tmp" | grep -q '^#!/bin/bash' || { log "$label : shebang inattendu — abandon"; rm -f "$tmp"; return 2; }
    bash -n "$tmp" 2>/dev/null || { log "$label : syntaxe invalide — abandon (rien remplace)"; rm -f "$tmp"; return 2; }

    # Deja a jour ?
    if [ -f "$target" ] && cmp -s "$tmp" "$target"; then rm -f "$tmp"; return 1; fi

    # Bascule atomique (copie dans le meme repertoire que la cible puis mv), avec sauvegarde
    dir=$(dirname "$target")
    new=$(mktemp "$dir/.ban_404.XXXXXX") || { log "$label : mktemp cible KO"; rm -f "$tmp"; return 2; }
    if cp "$tmp" "$new" && chmod 755 "$new"; then
        [ -f "$target" ] && cp -a "$target" "${target}.bak" 2>/dev/null || true
        if mv -f "$new" "$target"; then
            rm -f "$tmp"
            ver=$(grep -m1 '^BAN404_VERSION=' "$target" | cut -d'"' -f2)
            log "$label mis a jour${ver:+ (version $ver)}."
            return 0
        fi
        rm -f "$new" "$tmp"; log "$label : bascule KO"; return 2
    fi
    rm -f "$new" "$tmp"; log "$label : preparation KO"; return 2
}

# 1) Le moteur de detection/ban.
update_file "ban_404.sh" "$TARGET" "ban_404.sh"

# 2) L'updater lui-meme, EN DERNIER. La bascule par 'mv' cree un nouvel inode :
#    le process en cours garde l'ancien inode ouvert et termine sans surprise ;
#    le prochain passage cron utilisera la nouvelle version.
update_file "update_ban_404.sh" "$SELF" "update_ban_404.sh"

exit 0
