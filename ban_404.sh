#!/bin/bash

BAN404_VERSION="1.1.0"

# Configuration (valeurs par defaut ; surchargees par /etc/ban_404.conf)
BASE_DIR="/var/www"
IPSET_NAME="ban_404_list"
IPSET_SAVE_FILE="/etc/iptables/ipsets"   # chemin canonique du plugin ipset-persistent
BAN_TIMEOUT=172800   # 48 heures
WINDOW=7200          # Fenetre glissante en secondes (2h). Cron horaire => recouvrement, pas de trou aux bornes.
TAIL_LINES=50000     # On n'analyse que les N dernieres lignes de chaque log (borne le cout sur gros sites).
                     # A augmenter si un site depasse TAIL_LINES requetes dans la fenetre WINDOW.
LOCK_FILE="/run/ban_404_list.lock"

# Whitelist des IPs a ne JAMAIS bannir (separees par | ) -- correspondance EXACTE
WHITELIST_IP="127.0.0.1"

# --- Surcharge par la config locale, NON versionnee (whitelist par serveur, REPO_RAW, etc.) ---
CONF_FILE="/etc/ban_404.conf"
[ -f "$CONF_FILE" ] && . "$CONF_FILE"

# Initialisation des options
DRY_RUN=false
SHOW_BLOCKED=false
VERBOSE=false

show_help() {
    echo "ban_404.sh version $BAN404_VERSION"
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options disponibles :"
    echo "  --dry-run        Simuler les actions (mode lecture seule)."
    echo "  --show-blocked   Afficher aussi les IPs deja dans l'ipset."
    echo "  --verbose        Afficher le detail de la recherche des logs."
    echo "  --version        Afficher la version et quitter."
    echo "  --help, -h       Afficher ce message d'aide."
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --show-blocked) SHOW_BLOCKED=true; shift ;;
        --verbose) VERBOSE=true; shift ;;
        --version) echo "ban_404.sh version $BAN404_VERSION"; exit 0 ;;
        --help|-h) show_help ;;
        *) echo "Option inconnue : $1. Utilisez --help."; exit 1 ;;
    esac
done

# --- Verrou anti-chevauchement (cron). Inutile en simulation (lecture seule). ---
if [ "$DRY_RUN" = false ]; then
    exec 9>"$LOCK_FILE" || { echo "Impossible d'ouvrir le verrou $LOCK_FILE"; exit 1; }
    if ! flock -n 9; then
        echo "Une autre instance tourne deja (verrou $LOCK_FILE). Abandon."
        exit 1
    fi
fi

if [ "$VERBOSE" = true ]; then
    if [ "$DRY_RUN" = true ]; then
        echo -e "========================================="
        echo -e "   /!\\  MODE SIMULATION (DRY-RUN) ACTIF /!\\"
        echo -e "========================================="
    fi
    if [ "$SHOW_BLOCKED" = false ]; then
        echo -e "   FILTRE : IPs deja bloquees masquees\n"
    else
        echo -e "   AFFICHAGE : Toutes les IPs incluses\n"
    fi
    echo "=[ Recherche des fichiers de logs... ]="
fi

# FCrDNS sans dependance externe (getent, via la libc/nsswitch) :
#   1) PTR de l'IP  2) hostname = sous-domaine d'un crawler connu
#   3) ce hostname doit RE-RESOUDRE vers l'IP d'origine (anti-spoofing du PTR)
is_legit_crawler() {
    local ip="$1" rdns
    rdns=$(getent hosts "$ip" 2>/dev/null | awk '{print $2}' | head -n1 | tr 'A-Z' 'a-z')
    [ -z "$rdns" ] && return 1

    case "$rdns" in
        *.googlebot.com|*.google.com|*.search.msn.com|*.bing.com|\
        *.yandex.com|*.yandex.net|*.yandex.ru|\
        *.apple.com|*.applebot.apple.com|*.baidu.com) ;;
        *) return 1 ;;
    esac

    # Forward-confirmed : l'IP d'origine doit figurer parmi les adresses du hostname
    getent ahosts "$rdns" 2>/dev/null | awk '{print $1}' | grep -qxF "$ip" || return 1

    echo "$rdns"
    return 0
}

if [ "$DRY_RUN" = false ]; then
    ipset list "$IPSET_NAME" &>/dev/null
    if [ $? -ne 0 ]; then
        ipset create "$IPSET_NAME" hash:ip timeout $BAN_TIMEOUT
    fi
    /sbin/iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP &>/dev/null
    if [ $? -ne 0 ]; then
        /sbin/iptables -I INPUT -m set --match-set "$IPSET_NAME" src -j DROP
        mkdir -p /etc/iptables
        /sbin/iptables-save > /etc/iptables/rules.v4
    fi
fi

# 1. Recherche des fichiers de logs
FILES_FOUND=()
for log_dir in ${BASE_DIR}/*/log/; do
    [ -d "$log_dir" ] || continue
    if [ -f "${log_dir}access.log" ]; then
        FILES_FOUND+=("${log_dir}access.log")
    else
        latest=$(ls -1t "${log_dir}"*access.log 2>/dev/null | head -n 1)
        [ -n "$latest" ] && FILES_FOUND+=("$latest")
    fi
done

# 2. Filtrage des fichiers lisibles
VALID_FILES=()
for file in "${FILES_FOUND[@]}"; do
    if [ -r "$file" ] && [ -s "$file" ]; then
        [ "$VERBOSE" = true ] && echo "-> OK (lisible) : $file"
        VALID_FILES+=("$file")
    else
        [ "$VERBOSE" = true ] && echo "-> Ignore : $file"
    fi
done

if [ ${#VALID_FILES[@]} -eq 0 ]; then
    echo "=> Aucun fichier de log valide trouve. Fin."
    exit 0
fi

# Borne basse de la fenetre, au format AAAAMMJJHHMMSS (comparable directement, sans mktime)
CUTOFF=$(date -d "@$(( $(date +%s) - WINDOW ))" '+%Y%m%d%H%M%S')
[ "$VERBOSE" = true ] && echo -e "\n=[ Analyse des ${TAIL_LINES} dernieres lignes/log depuis $CUTOFF ]="

# 3. Extraction et tri via awk
#    - tail -q : seulement les dernieres lignes de CHAQUE log (borne le cout)
#    - whitelist en correspondance EXACTE (split sur |)
#    - fenetre temporelle (on ignore les 404 trop vieux)
#    - insensibilite a la casse via tolower() (le flag /i n'existe pas en awk)
#    - filtre anti-bruit + honeypots (+100)
ips_data=$(tail -n "$TAIL_LINES" -q "${VALID_FILES[@]}" | awk -v wl="$WHITELIST_IP" -v cutoff="$CUTOFF" '
BEGIN {
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", M, " ")
    for (i=1;i<=12;i++) mon[M[i]]=i
    n=split(wl, Wl, "|"); for (i=1;i<=n;i++) white[Wl[i]]=1
}
$9 == 404 && !($1 in white) {

    # --- Fenetre temporelle : $4 = [jj/Mon/aaaa:hh:mm:ss ---
    split(substr($4,2), d, /[\/:]/)
    ts = sprintf("%04d%02d%02d%02d%02d%02d", d[3], mon[d[2]], d[1], d[4], d[5], d[6])
    if (ts < cutoff) next

    p = tolower($7)

    # --- A. Bruit de fond (faux positifs) ---
    if (p ~ /\.(jpg|jpeg|png|gif|webp|ico|css|js|svg|woff2?|map)$/) next
    if (p ~ /(apple-touch-icon|favicon|browserconfig\.xml|mstile)/) next
    if (p ~ /(autodiscover\.xml|sitemap\.xml|robots\.txt|ads\.txt)/) next
    if (p ~ /\.well-known\/(security\.txt|pki-validation)/) next

    # --- B. Honeypots : +100 (ban quasi immediat) ---
    if (p ~ /(\.env|wp-config\.php|phpmyadmin|config\.json|setup\.php|actuator|xmlrpc\.php)/) {
        count[$1] += 100
    } else {
        count[$1]++
    }
}
END {
    for (ip in count) if (count[ip] > 10) print count[ip], ip
}' | sort -rn)

if [ -z "$ips_data" ]; then
    [ "$VERBOSE" = true ] && echo "Aucune IP suspecte trouvee."
    exit 0
fi

changes_made=false
rules_simulated=0
[ "$VERBOSE" = true ] && echo -e "\n=[ Traitement des IP ]="

# 4. Boucle de traitement
while read -r count ip; do
    [ -z "$ip" ] && continue

    crawler_domain=$(is_legit_crawler "$ip")
    if [ $? -eq 0 ]; then
        if [ "$DRY_RUN" = false ] && ipset test "$IPSET_NAME" "$ip" &>/dev/null; then
            echo "[-] Deblocage de l'IP (crawler legitime) : $ip ($crawler_domain | $count 404)"
            ipset del "$IPSET_NAME" "$ip"
            changes_made=true
        elif [ "$DRY_RUN" = true ] && ipset test "$IPSET_NAME" "$ip" &>/dev/null; then
            echo "[SIMULATION] [-] L'IP $ip aurait ete DEBANNIE (vrai robot : $crawler_domain)."
            rules_simulated=$((rules_simulated + 1))
        else
            [ "$SHOW_BLOCKED" = true ] && echo "[SKIP] Robot legitime non bloque : $ip"
        fi
        continue
    fi

    if ipset test "$IPSET_NAME" "$ip" &>/dev/null; then
        [ "$SHOW_BLOCKED" = true ] && echo "[...] L'IP $ip est deja dans l'ipset ($count erreurs 404)."
    else
        if [ "$DRY_RUN" = true ]; then
            if [ "$count" -ge 100 ]; then
                echo "[SIMULATION] [+] L'IP $ip aurait ete bannie IMMEDIATEMENT (Honeypot detecte : $count)."
            else
                echo "[SIMULATION] [+] L'IP $ip aurait ete ajoutee a l'ipset ($count erreurs 404)."
            fi
            rules_simulated=$((rules_simulated + 1))
        else
            if [ "$count" -ge 100 ]; then
                echo "[+] Blocage IMMEDIAT (Honeypot) de l'IP : $ip"
            else
                echo "[+] Blocage (ipset) de l'IP : $ip ($count erreurs 404)"
            fi
            ipset -exist add "$IPSET_NAME" "$ip"
            changes_made=true
        fi
    fi
done <<< "$ips_data"

# 5. Sauvegarde
[ "$VERBOSE" = true ] && echo -e "\n=[ Resultat ]="
if [ "$DRY_RUN" = true ]; then
    echo "=> Mode simulation termine. $rules_simulated action(s) virtuelle(s) generee(s)."
else
    if [ "$changes_made" = true ]; then
        [ "$VERBOSE" = true ] && echo "=> Changements appliques. Sauvegarde de la configuration ipset..."
        mkdir -p "$(dirname "$IPSET_SAVE_FILE")"
        ipset save > "$IPSET_SAVE_FILE"
    else
        [ "$VERBOSE" = true ] && echo "=> Aucune modification requise dans l'ipset."
    fi
fi
