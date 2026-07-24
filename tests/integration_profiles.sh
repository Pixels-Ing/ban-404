#!/bin/bash
# Test d'intégration ban-404 — PROFILS de layout de logs (Phase 2 de l'universalisation).
# Vérifie que la DÉCOUVERTE trouve les logs sur d'autres panels (cpanel/directadmin/nginx/generic)
# et que l'auto-détection choisit le bon profil. Le PARSEUR (combiné) est commun et déjà couvert
# pour ISPConfig par integration.sh. Tout en --dry-run => aucune écriture pare-feu, pas besoin
# d'ipset/iptables. Exécuté par .github/workflows/check.yml (root, pour créer /var/log/...).
#
# Usage : sudo bash tests/integration_profiles.sh [chemin_du_moteur]   (défaut : ./ban_404.sh)
set -u

ENGINE="${1:-./ban_404.sh}"
IP=203.0.113.88        # TEST-NET-3 (RFC 5737)
TS=$(LC_ALL=C date -u '+%d/%b/%Y:%H:%M:%S +0000')

fail() { echo "ÉCHEC : $*" >&2; exit 1; }
ok()   { echo "  OK  $*"; }
[ -f "$ENGINE" ] || fail "moteur introuvable : $ENGINE (lancer depuis la racine du dépôt)"

flood() {  # $1 = fichier de log à créer avec un flood 404 récent
    local f="$1" i; mkdir -p "$(dirname "$f")"; : > "$f"
    for i in $(seq 1 15); do
        printf '%s - - [%s] "GET /nope-%d HTTP/1.1" 404 200 "-" "bot/1.0"\n' "$IP" "$TS" "$i" >> "$f"
    done
}
run_detect() {  # $1 = valeur LOG_PROFILE ; $2 = ligne(s) de conf supplémentaires
    cat > /etc/ban_404.conf <<EOF
WHITELIST_IP=127.0.0.1
NOTIFY_BANS=false
DAILY_SUMMARY=false
HEALTH_CHECKS=false
LOG_PROFILE=$1
$2
EOF
    bash "$ENGINE" --dry-run 2>&1
}

echo "== cpanel (/var/log/apache2/domlogs/<domaine>) =="
flood /var/log/apache2/domlogs/site.example
run_detect cpanel "" | grep -q "$IP" || { run_detect cpanel "" | head; fail "cpanel : flood non détecté"; }
ok "cpanel : découverte + détection du flood 404"

echo "== directadmin (/var/log/httpd/domains/<domaine>.log) =="
flood /var/log/httpd/domains/site.example.log
: > /var/log/httpd/domains/site.example.error.log   # doit être IGNORÉ (pas un access log)
run_detect directadmin "" | grep -q "$IP" || fail "directadmin : flood non détecté"
ok "directadmin : découverte + détection (error.log ignoré)"

echo "== nginx (/var/log/nginx/*access*.log) =="
flood /var/log/nginx/site.example.access.log
: > /var/log/nginx/site.example.error.log   # doit être IGNORÉ
run_detect nginx "" | grep -q "$IP" || fail "nginx : flood non détecté"
ok "nginx : découverte + détection (error log ignoré)"

echo "== generic (BASE_DIR/*/*access*.log) =="
flood /tmp/b404generic/site1/access.log
run_detect generic "BASE_DIR=/tmp/b404generic" | grep -q "$IP" || fail "generic : flood non détecté"
ok "generic : découverte + détection sous BASE_DIR"

echo "== auto : détection de profil (domlogs présent => cpanel) =="
# ISPConfig (/var/www/*/log/) et plesk (/var/www/vhosts/*/logs/) absents sur le runner => auto doit
# tomber sur cpanel (le flood cpanel ci-dessus est toujours là).
run_detect auto "" | grep -q "$IP" || fail "auto : flood non détecté (auto-détection de profil)"
ok "auto : profil auto-détecté + flood détecté"

echo "== diag rapporte le profil actif =="
DOUT=$(run_detect cpanel ""; bash "$ENGINE" diag 2>&1)
printf '%s\n' "$DOUT" | grep -qiE 'profil|profile' || { printf '%s\n' "$DOUT" | grep -i log; fail "diag ne rapporte pas le profil de log"; }
ok "diag rapporte le profil de découverte des logs"

echo "== PROFILS OK =="
