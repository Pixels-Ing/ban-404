#!/bin/bash
# ============================================================================
#  install_ban_404.sh — Installation "cle en main" du ban automatique sur
#  flood de 404 (ipset + iptables, persistance au reboot, execution horaire).
#  Idempotent. Migre l'ancien chemin /etc/iptables/ipset et decommissionne
#  tout ancien script de ban 404 (quel que soit son nom).
#
#  Le moteur ban_404.sh n'est PAS embarque ici : il est recupere depuis le
#  depot par le self-updater (source unique de verite). Seul l'updater est
#  embarque (heredoc UPD_EOF) — amorce incontournable, puis il se met a jour
#  lui-meme. L'installation requiert donc un acces reseau a REPO_RAW.
# ============================================================================
set -u

SCRIPT_PATH="/usr/local/sbin/ban_404.sh"
CRON_PATH="/etc/cron.hourly/ban_404"        # SANS extension : run-parts ignore les noms contenant '.'
CRON_BASE="ban_404"
LOG_PATH="/var/log/ban_404.log"
LOGROTATE_PATH="/etc/logrotate.d/ban_404"
UPDATER_PATH="/usr/local/sbin/update_ban_404.sh"
CONF_PATH="/etc/ban_404.conf"
UPDATE_CRON="/etc/cron.daily/ban_404_update"

# >>> A EDITER UNE FOIS avant distribution : URL "raw" de ton depot (sans slash final) <<<
REPO_RAW="https://raw.githubusercontent.com/PixelsIng/ban-404/main"

die(){ echo "ERREUR: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "a lancer en root (sudo)."

echo "==> Installation des paquets requis..."
export DEBIAN_FRONTEND=noninteractive
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
apt-get update || echo "   (apt-get update en erreur — on poursuit avec le cache local)"
# curl : requis pour la recuperation initiale du moteur via l'updater (l'install depend du reseau).
install_pkgs(){ apt-get install -y ipset iptables-persistent ipset-persistent cron curl; }
if ! install_pkgs; then
    echo "   echec — tentative d'activation du depot 'universe' (requis pour ipset-persistent sur 22.04)..."
    command -v add-apt-repository >/dev/null 2>&1 && { add-apt-repository -y universe && apt-get update || true; }
    install_pkgs || die "echec installation paquets (le depot 'universe' est-il active ?)."
fi

systemctl enable --now netfilter-persistent >/dev/null 2>&1 || true
mkdir -p /etc/iptables

echo "==> Migration eventuelle de l'ancien chemin de persistance ipset..."
if [ -L /etc/iptables/ipsets ]; then
    link_target=$(readlink -f /etc/iptables/ipsets 2>/dev/null || true)
    echo "   /etc/iptables/ipsets est un lien -> ${link_target:-<casse>}"
    rm -f /etc/iptables/ipsets
    if [ -n "${link_target:-}" ] && [ -f "$link_target" ]; then
        cp -a "$link_target" /etc/iptables/ipsets
        echo "   contenu materialise dans un vrai fichier /etc/iptables/ipsets"
    fi
fi
if [ -f /etc/iptables/ipset ]; then
    rm -f /etc/iptables/ipset
    echo "   ancien /etc/iptables/ipset supprime"
fi

echo "==> Decommissionnement de tout ancien script de ban 404..."
# Un nom evoque-t-il un ancien ban-404 ? (ban+404 dans un sens ou l'autre, insensible casse)
is_legacy_name(){ printf '%s' "$1" | grep -qiE '(ban[_-]?404|404[_-]?ban|autoban404|auto_ban_404)'; }

shopt -s nullglob
for f in /etc/cron.hourly/* /etc/cron.daily/*; do
    base=$(basename "$f")
    [ "$base" = "$CRON_BASE" ] && continue                 # notre nouvelle tache : ne pas toucher
    if [ -L "$f" ]; then
        tgt=$(readlink -f "$f" 2>/dev/null || true)
        if is_legacy_name "$base" || { [ -n "${tgt:-}" ] && is_legacy_name "$(basename "$tgt")"; }; then
            [ -n "${tgt:-}" ] && [ -f "$tgt" ] && [ "$tgt" != "$SCRIPT_PATH" ] && { rm -f "$tgt"; echo "   ancien script supprime : $tgt"; }
            rm -f "$f"; echo "   ancien cron (lien) supprime : $f"
        fi
    elif [ -f "$f" ]; then
        ref=$(grep -oE '/[^[:space:]"'\'']*\.sh' "$f" 2>/dev/null | head -n1 || true)
        if is_legacy_name "$base" || { [ -n "${ref:-}" ] && is_legacy_name "$(basename "$ref")"; }; then
            [ -n "${ref:-}" ] && [ -f "$ref" ] && [ "$ref" != "$SCRIPT_PATH" ] && { rm -f "$ref"; echo "   ancien script supprime : $ref"; }
            rm -f "$f"; echo "   ancien cron supprime : $f"
        fi
    fi
done
shopt -u nullglob

# Copies orphelines dans les emplacements habituels (sauf nos propres scripts, reecrits ensuite)
for d in /root /usr/local/bin /usr/local/sbin; do
    [ -d "$d" ] || continue
    find "$d" -maxdepth 1 -type f -regextype posix-extended \
        -iregex '.*(ban[_-]?404|404[_-]?ban|auto_ban_404).*\.sh' 2>/dev/null | while read -r s; do
        [ "$s" = "$SCRIPT_PATH" ] && continue
        [ "$s" = "$UPDATER_PATH" ] && continue
        rm -f "$s"; echo "   ancien script supprime : $s"
    done
done

# References dans crontab partage : signalees, pas auto-editees
hits=$(grep -rliE '(ban[_-]?404|404[_-]?ban|auto_ban_404)' /etc/cron.d /etc/crontab /var/spool/cron 2>/dev/null | grep -v "$CRON_BASE" || true)
[ -n "${hits:-}" ] && echo "   /!\\ References a verifier/retirer manuellement : $hits"

# Ancienne chaine iptables eventuelle
if iptables -nL AUTOBAN404 >/dev/null 2>&1; then
    iptables -D INPUT -j AUTOBAN404 2>/dev/null || true
    iptables -F AUTOBAN404 2>/dev/null || true
    iptables -X AUTOBAN404 2>/dev/null || true
    echo "   chaine AUTOBAN404 demontee"
fi
[ -d /var/lib/auto-ban-404 ] && { rm -rf /var/lib/auto-ban-404; echo "   /var/lib/auto-ban-404 supprime"; }

# La config locale doit exister AVANT l'updater (qui y lit REPO_RAW).
echo "==> Configuration locale : $CONF_PATH"
if [ ! -f "$CONF_PATH" ]; then
    cat > "$CONF_PATH" <<EOF
# /etc/ban_404.conf — configuration LOCALE par serveur (NON versionnee).
REPO_RAW="$REPO_RAW"
WHITELIST_IP="127.0.0.1"
#WINDOW=7200
#BAN_TIMEOUT=172800
#TAIL_LINES=50000
EOF
    chmod 600 "$CONF_PATH"
    echo "   cree (pense a adapter WHITELIST_IP sur ce serveur)"
else
    echo "   existant conserve (non ecrase)"
fi

# Seule copie embarquee restante : l'updater (amorce). A garder synchronise avec
# update_ban_404.sh du depot — voir la doc interne. Le self-update fait converger toute
# divergence des le premier passage cron.
echo "==> Self-updater : $UPDATER_PATH (+ $UPDATE_CRON)"
cat > "$UPDATER_PATH" <<'UPD_EOF'
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
UPD_EOF
chmod 755 "$UPDATER_PATH"
cat > "$UPDATE_CRON" <<EOF
#!/bin/sh
exec $UPDATER_PATH
EOF
chmod 755 "$UPDATE_CRON"

# Recuperation initiale du moteur : on delegue a l'updater (source unique de verite).
echo "==> Recuperation initiale du moteur via l'updater : $SCRIPT_PATH"
"$UPDATER_PATH" || true
[ -s "$SCRIPT_PATH" ] || die "impossible de recuperer $SCRIPT_PATH depuis $REPO_RAW. Verifie l'acces reseau et REPO_RAW dans $CONF_PATH (voir $LOG_PATH ; rien d'installe pour le moteur)."

echo "==> Tache horaire : $CRON_PATH"
cat > "$CRON_PATH" <<EOF
#!/bin/sh
# Horodate chaque ligne de sortie du script avant de l'ecrire dans le log.
$SCRIPT_PATH 2>&1 | while IFS= read -r line; do
    printf '%s %s\n' "\$(date '+%Y-%m-%d %H:%M:%S')" "\$line"
done >> $LOG_PATH
EOF
chmod 755 "$CRON_PATH"

echo "==> Rotation du log : $LOGROTATE_PATH"
cat > "$LOGROTATE_PATH" <<EOF
$LOG_PATH {
    weekly
    rotate 8
    compress
    missingok
    notifempty
}
EOF

echo "==> Activation immediate (creation de l'ipset + regle DROP, puis persistance)..."
modprobe ip_set 2>/dev/null || true
# Recharger d'eventuels bans deja persistes (migration / reinstall) AVANT de re-sauvegarder
[ -s /etc/iptables/ipsets ] && ipset restore -exist < /etc/iptables/ipsets 2>/dev/null || true
"$SCRIPT_PATH" || true
netfilter-persistent save >/dev/null 2>&1 || true

cat <<EOF

------------------------------------------------------------
 Installation terminee.
   Script             : $SCRIPT_PATH  (recupere depuis REPO_RAW)
   Cron (horaire)     : $CRON_PATH   -> log dans $LOG_PATH
   Self-updater       : $UPDATER_PATH (cron.daily) — met a jour le moteur ET lui-meme
   Persistance reboot : /etc/iptables/ipsets + /etc/iptables/rules.v4
   Aucune dependance externe au runtime (FCrDNS via getent / libc)

 Tester sans rien modifier :
   $SCRIPT_PATH --dry-run --verbose
------------------------------------------------------------
EOF
