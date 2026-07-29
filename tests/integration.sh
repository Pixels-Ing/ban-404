#!/bin/bash
# Test d'intégration ban-404 (CI) — chemin de RÉFÉRENCE : Apache/ISPConfig + ipset/iptables.
# But : verrouiller le comportement actuel (découverte de logs, détection de flood 404, ban/unban réel)
# pour détecter toute RÉGRESSION avant que l'universalisation ne touche au moteur. Exécuté par
# .github/workflows/check.yml sur le runner Ubuntu, en root (sudo) car le test 2 crée un ipset réel.
#
# Usage : sudo bash tests/integration.sh [chemin_du_moteur]   (défaut : ./ban_404.sh)
set -u

ENGINE="${1:-./ban_404.sh}"
FIX=/tmp/b404fix
IP=203.0.113.66        # TEST-NET-3 (RFC 5737) — jamais une vraie IP
LEGIT=198.51.100.10    # TEST-NET-2 — trafic 200 légitime, ne doit PAS être banni

fail() { echo "ÉCHEC : $*" >&2; exit 1; }
ok()   { echo "  OK  $*"; }

[ -f "$ENGINE" ] || fail "moteur introuvable : $ENGINE (lancer depuis la racine du dépôt)"

# ---------------------------------------------------------------------------
# Fixture : arborescence ISPConfig (/var/www/<vhost>/log/access.log) + flood 404
# avec des horodatages RÉCENTS (dans la fenêtre WINDOW de 2 h). LC_ALL=C => mois en
# anglais (Jul), attendu par la table de mois du awk.
# ---------------------------------------------------------------------------
rm -rf "$FIX"; mkdir -p "$FIX/www/site1.example/log"
LOG="$FIX/www/site1.example/log/access.log"
TS=$(LC_ALL=C date -u '+%d/%b/%Y:%H:%M:%S +0000')
: > "$LOG"
for i in $(seq 1 15); do
    printf '%s - - [%s] "GET /nonexistent-%d HTTP/1.1" 404 200 "-" "bot/1.0"\n' "$IP" "$TS" "$i" >> "$LOG"
done
# trafic légitime (200) : ne doit rien déclencher
printf '%s - - [%s] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n' "$LEGIT" "$TS" >> "$LOG"

# Conf minimale pointant sur la fixture. touch last_update => neutralise le filet updater
# (self_heal_update_trigger) qui tenterait de lancer l'updater vers un REPO_RAW inexistant.
mkdir -p /var/lib/ban_404 && touch /var/lib/ban_404/last_update
cat > /etc/ban_404.conf <<EOF
BASE_DIR=$FIX/www
WHITELIST_IP=127.0.0.1
NOTIFY_BANS=false
DAILY_SUMMARY=false
HEALTH_CHECKS=false
EOF

# ---------------------------------------------------------------------------
echo "== Test 1 : découverte + détection du flood 404 (dry-run, aucune écriture pare-feu) =="
OUT=$(bash "$ENGINE" --dry-run 2>&1 || true)
printf '%s\n' "$OUT" | grep -q "$IP"    || { printf '%s\n' "$OUT"; fail "flood 404 non détecté (IP $IP absente de la sortie dry-run)"; }
ok "flood 404 détecté de bout en bout (découverte + parsing + scoring) — IP $IP"

# ---------------------------------------------------------------------------
echo "== Test 2 : ban / unban réel (ipset + iptables) =="
[ "$(id -u)" -eq 0 ] || fail "test 2 nécessite root — lancer via sudo"
modprobe ip_set 2>/dev/null || true

bash "$ENGINE" >/dev/null 2>&1 || true
ipset test ban_404_list "$IP" 2>/dev/null || fail "IP $IP non présente dans l'ipset ban_404_list après un run réel"
ok "IP bannie dans l'ipset ban_404_list"

iptables -C INPUT -m set --match-set ban_404_list src -j DROP 2>/dev/null \
    || fail "règle DROP INPUT (match-set ban_404_list) absente"
ok "règle DROP INPUT présente"

bash "$ENGINE" unban "$IP" >/dev/null 2>&1 || fail "la sous-commande 'unban' a échoué"
ipset test ban_404_list "$IP" 2>/dev/null && fail "IP $IP toujours bannie après unban"
ok "IP débannie proprement"

# ---------------------------------------------------------------------------
echo "== Test 3 : diag s'exécute et rapporte plateforme + backend pare-feu =="
# 'iptables+ipset' est un jeton littéral présent dans toutes les langues => assertion robuste.
DOUT=$(bash "$ENGINE" diag 2>&1 || true)
printf '%s\n' "$DOUT" | grep -q 'iptables+ipset' || { printf '%s\n' "$DOUT"; fail "diag ne rapporte pas le backend pare-feu"; }
ok "diag rapporte le backend pare-feu (iptables+ipset)"

# ---------------------------------------------------------------------------
echo "== Test 4 : compteurs 24 h à cheval sur une rotation logrotate =="
# Régression du 26 juil. 2026 : logrotate ouvre un fichier neuf, et les compteurs ne lisaient que
# le log courant => le résumé du matin de rotation annonçait une poignée de bans pour des milliers
# de bans réels (contradiction visible avec le delta ipset). Le flux doit rattraper le .1.gz.
TLOG="$FIX/ban_404.log"
OLD=$(date -d '10 hours ago' '+%Y-%m-%d %H:%M:%S'); NEW=$(date -d '1 hour ago' '+%Y-%m-%d %H:%M:%S')
: > "$TLOG.1"
for i in 1 2 3; do printf '%s [+] Block (ipset) of IP: 203.0.113.%d (30 404 errors)\n' "$OLD" "$i" >> "$TLOG.1"; done
gzip -f "$TLOG.1"                                  # => $TLOG.1.gz, comme logrotate avec compress
: > "$TLOG"
for i in 4 5; do printf '%s [+] Block (ipset) of IP: 203.0.113.%d (30 404 errors)\n' "$NEW" "$i" >> "$TLOG"; done
printf 'LOG_FILE=%s\nBAN404_LANG=en\n' "$TLOG" >> /etc/ban_404.conf
SOUT=$(bash "$ENGINE" stats --no-health 2>&1 || true)
printf '%s\n' "$SOUT" | grep -q 'New bans: 5' \
    || { printf '%s\n' "$SOUT" | head -30; fail "compteur 24 h amputé par la rotation (attendu « New bans: 5 », rotaté .1.gz non lu)"; }
ok "compteurs 24 h : log courant + rotaté .1.gz agrégés (5 bans)"

# Log courant VIDE : la rotation tombe à minuit et le résumé part à 06:25 — un serveur sans
# événement dans cette tranche ne doit PAS afficher 0 en ignorant le rotaté de la journée.
: > "$TLOG"
SOUT=$(bash "$ENGINE" stats --no-health 2>&1 || true)
printf '%s\n' "$SOUT" | grep -q 'New bans: 3' \
    || { printf '%s\n' "$SOUT" | head -30; fail "log courant vide : rotaté ignoré (attendu « New bans: 3 »)"; }
ok "compteurs 24 h : log courant vide => le rotaté fait foi (3 bans)"

# ---------------------------------------------------------------------------
echo "== Test 5 : bannissement gradué (récidive) et clamp du timeout ipset =="
# Pas besoin de voyager dans le temps : on SÈME le fichier d'état, puis on observe le timeout
# réellement posé dans l'ipset. OFFENDERS_FILE reste au chemin par défaut (test en root).
OFF=/var/lib/ban_404/offenders
HPIP=203.0.113.77       # TEST-NET-3 — déclenche le circuit honeypot

# timeout résiduel d'une IP dans le set (« <ip> timeout <secs> »), vide si absente
ipset_timeout() { ipset list ban_404_list 2>/dev/null | awk -v ip="$1" '$1==ip {for(i=1;i<=NF;i++) if($i=="timeout"){print $(i+1); exit}}'; }

# 5a. Non-régression : IP inconnue => BAN_TIMEOUT (172800), inchangé depuis 2.2.3.
rm -f "$OFF"
bash "$ENGINE" >/dev/null 2>&1 || true
TO=$(ipset_timeout "$IP")
[ -n "$TO" ] && [ "$TO" -gt 172000 ] && [ "$TO" -le 172800 ] \
    || fail "1er ban : timeout attendu ~172800 (BAN_TIMEOUT), obtenu « ${TO:-absent} »"
ok "1er ban d'une IP inconnue : timeout $TO s (BAN_TIMEOUT, non-régression)"

grep -qE "^$IP 1 [0-9]+$" "$OFF" 2>/dev/null \
    || { cat "$OFF" 2>/dev/null; fail "fichier d'état : ligne « $IP 1 <epoch> » attendue"; }
ok "mémoire des récidives alimentée ($IP, 1 ban)"

# 5b. Deux bans mémorisés => niveau 2 => 3e palier de BAN_ESCALATION (1209600 = 14 j).
bash "$ENGINE" unban "$IP" >/dev/null 2>&1 || fail "unban a échoué (préparation 5b)"
printf '%s 2 %s\n' "$IP" "$(date +%s)" > "$OFF"
bash "$ENGINE" >/dev/null 2>&1 || true
TO=$(ipset_timeout "$IP")
[ -n "$TO" ] && [ "$TO" -gt 1209000 ] && [ "$TO" -le 1209600 ] \
    || fail "récidiviste (2 bans) : timeout attendu ~1209600 (14 j), obtenu « ${TO:-absent} »"
ok "récidiviste : ban allongé à $TO s (14 j)"

grep -qE "^$IP 3 [0-9]+$" "$OFF" 2>/dev/null \
    || { cat "$OFF"; fail "le compteur de récidive doit passer à 3"; }
ok "compteur de récidive incrémenté (3 bans)"

# 5c. Déban manuel = verdict d'innocence : l'entrée disparaît du fichier d'état.
bash "$ENGINE" unban "$IP" >/dev/null 2>&1 || fail "la sous-commande 'unban' a échoué"
grep -q "^$IP " "$OFF" 2>/dev/null && { cat "$OFF"; fail "unban doit purger l'entrée de $IP"; }
ok "unban remet le compteur de récidive à zéro"

# 5d. Clamp ipset : un HONEYPOT_BAN_TIMEOUT > 2147483 s faisait échouer l'ajout EN SILENCE
# (aucune IP bannie). Le timeout doit être borné, pas refusé.
printf '%s - - [%s] "GET /.env HTTP/1.1" 404 200 "-" "bot/1.0"\n' "$HPIP" "$TS" >> "$LOG"
printf 'HONEYPOT_BAN_TIMEOUT=2592000\n' >> /etc/ban_404.conf     # 30 j : au-delà de la limite ipset
rm -f "$OFF"
bash "$ENGINE" >/dev/null 2>&1 || true
TO=$(ipset_timeout "$HPIP")
[ -n "$TO" ] && [ "$TO" -gt 2147000 ] && [ "$TO" -le 2147483 ] \
    || fail "clamp ipset : timeout attendu ~2147483, obtenu « ${TO:-absent — ban refusé en silence} »"
ok "timeout > 24 j borné à $TO s (l'IP est bien bannie)"

# ---------------------------------------------------------------------------
echo "== Test 6 : le score POST-flood reflète l'INTENSITÉ (100 forfaitaires + 1/POST) =="
# Avant 2.3.1 le forfait était seul : 3000 POST scoraient comme 21, donc même palier d'escalade et
# dernière place au Top honeypot du résumé. Le statut est volontairement 200 : xmlrpc/wp-login
# répondent 200 même quand l'authentification échoue, le compteur ne doit pas filtrer là-dessus.
PFIP=203.0.113.88
for i in $(seq 1 25); do
    printf '%s - - [%s] "POST /wp-login.php HTTP/1.1" 200 512 "-" "bot/1.0"\n' "$PFIP" "$TS" >> "$LOG"
done
rm -f "$OFF"
bash "$ENGINE" >/dev/null 2>&1 || true
grep -q "$PFIP (score 125)" "$TLOG" \
    || { grep -a "$PFIP" "$TLOG" | tail -3; fail "score attendu 125 (100 + 25 POST) pour $PFIP"; }
ok "25 POST en 200 => score 125 (forfait + volume), et non 100"

echo "== INTÉGRATION OK =="
