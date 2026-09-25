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

# ---------------------------------------------------------------------------
echo "== Test 7 : un crawler légitime n'est jamais banni par le circuit honeypot =="
# Régression du 31 juil. 2026 : le circuit honeypot/sécurité sautait le FCrDNS, au motif qu'un vrai
# crawler n'atteint jamais ces motifs. Faux — PrestaShop empile lui-même le paramètre resultsPerPage
# dans ses liens de facettes et Googlebot suit ces URL : 7 IP Googlebot et 1 Bingbot bannies 7 j sur
# le parc, sans aucun moyen d'en sortir. Le FCrDNS est ici servi par /etc/hosts (PTR ET
# re-résolution), donc sans réseau ni dépendance au DNS du runner.
CRIP=203.0.113.99
printf '%s crawl-test.googlebot.com\n' "$CRIP" >> /etc/hosts
printf '%s - - [%s] "GET /.env HTTP/1.1" 404 200 "-" "bot/1.0"\n' "$CRIP" "$TS" >> "$LOG"

# 7a. Hors des plages connues : le pré-filtre n'engage aucun DNS, l'IP est bannie (coût maîtrisé —
# c'est ce qui évite de repayer les ~30 min de lookups d'un run de rattrapage sous botnet).
rm -f "$OFF"
bash "$ENGINE" >/dev/null 2>&1 || true
[ -n "$(ipset_timeout "$CRIP")" ] \
    || fail "hors plage crawler : aucun lookup ne doit être payé, l'IP devait être bannie"
ok "hors plage connue : pas de lookup, ban honeypot normal"

# 7b. Plage déclarée : le FCrDNS est payé malgré hpflag=1, le crawler est reconnu et épargné.
bash "$ENGINE" unban "$CRIP" >/dev/null 2>&1 || fail "unban a échoué (préparation 7b)"
printf 'CRAWLER_HINT_PREFIXES="203.0.113."\n' >> /etc/ban_404.conf
bash "$ENGINE" >/dev/null 2>&1 || true
[ -z "$(ipset_timeout "$CRIP")" ] \
    || fail "crawler légitime (FCrDNS confirmé) : l'IP n'aurait jamais dû être bannie"
ok "crawler légitime épargné sur le circuit honeypot"

# 7c. Balayage à froid : une IP droppée n'émet plus de requêtes, donc ne revient JAMAIS dans les
# candidats — seul enforce_crawler_unban peut la libérer. Et l'acquittement vaut amnistie.
COLDIP=203.0.113.150
printf '%s crawl-cold.googlebot.com\n' "$COLDIP" >> /etc/hosts
ipset add ban_404_list "$COLDIP" timeout 604800 2>/dev/null
printf '%s 2 %s\n' "$COLDIP" "$(date +%s)" >> "$OFF"
[ -n "$(ipset_timeout "$COLDIP")" ] || fail "préparation 7c : $COLDIP devait être dans le set"
bash "$ENGINE" >/dev/null 2>&1 || true
[ -z "$(ipset_timeout "$COLDIP")" ] \
    || fail "balayage à froid : $COLDIP (crawler absent des logs) devait être libéré"
ok "balayage à froid : crawler banni à tort libéré sans réapparaître dans les logs"

grep -q "^$COLDIP " "$OFF" 2>/dev/null && { cat "$OFF"; fail "l'acquittement FCrDNS doit purger la mémoire des récidives"; }
ok "déban crawler = amnistie (compteur de récidive purgé)"


# ---------------------------------------------------------------------------
echo "== Test 8 : un asset manquant martelé sur UNE seule URL ne bannit plus (DISTINCT_PATH_MIN) =="
# Incident du 20 août 2026 : l'IP publique d'un client bannie 48 h pour 11 x LE MÊME 404 en 56 s —
# un fichier de langue absent du déploiement, réclamé par 25 templates. Un scanner balaie des
# chemins VARIÉS ; un navigateur bloqué sur un asset mort martèle UNE URL. Ce test verrouille les
# trois versants : l'épargne, la non-régression du scanner, et la primauté du circuit honeypot.
MISS=198.51.100.77    # navigateur légitime coincé sur un asset absent (1 seul chemin)
SCAN=198.51.100.88    # scanner : autant de hits, chemins tous différents
DUO=198.51.100.99     # 2 chemins distincts : doit rester banni (comportement historique)
for i in $(seq 1 12); do
    printf '%s - - [%s] "GET /assets/i18n/fr.json HTTP/1.1" 404 200 "-" "Mozilla/5.0"\n' "$MISS" "$TS" >> "$LOG"
    printf '%s - - [%s] "GET /probe-%d/index.php HTTP/1.1" 404 200 "-" "bot/1.0"\n' "$SCAN" "$TS" "$i" >> "$LOG"
done
for i in $(seq 1 6); do
    printf '%s - - [%s] "GET /wp-json/batch/v1 HTTP/1.1" 404 200 "-" "python-requests/2.34"\n' "$DUO" "$TS" >> "$LOG"
    printf '%s - - [%s] "GET / HTTP/1.1" 404 200 "-" "python-requests/2.34"\n' "$DUO" "$TS" >> "$LOG"
done
OUT=$(bash "$ENGINE" --dry-run 2>&1 || true)
printf '%s\n' "$OUT" | grep -q "$MISS" && { printf '%s\n' "$OUT"; fail "faux positif : $MISS (12 x la même URL) ne doit plus être candidat"; }
ok "asset manquant : 12 x le même 404 sur UN chemin ne bannit plus"
printf '%s\n' "$OUT" | grep -q "$SCAN" || { printf '%s\n' "$OUT"; fail "régression : $SCAN (12 chemins distincts) devait rester détecté"; }
ok "non-régression : scanner à chemins variés toujours détecté"
printf '%s\n' "$OUT" | grep -q "$DUO" || { printf '%s\n' "$OUT"; fail "régression : $DUO (2 chemins distincts) devait rester détecté"; }
ok "non-régression : 2 chemins distincts suffisent toujours (cas mesuré sur le parc)"

# 8d. Le circuit honeypot prime : une URL unique + un chemin-piège = ban malgré la diversité nulle.
HPIP=198.51.100.111
for i in $(seq 1 12); do
    printf '%s - - [%s] "GET /assets/i18n/fr.json HTTP/1.1" 404 200 "-" "Mozilla/5.0"\n' "$HPIP" "$TS" >> "$LOG"
done
printf '%s - - [%s] "GET /.env HTTP/1.1" 404 200 "-" "Mozilla/5.0"\n' "$HPIP" "$TS" >> "$LOG"
OUT=$(bash "$ENGINE" --dry-run 2>&1 || true)
printf '%s\n' "$OUT" | grep -q "$HPIP" || { printf '%s\n' "$OUT"; fail "le circuit honeypot doit bannir quelle que soit la diversité des chemins"; }
ok "honeypot : ban maintenu malgré une diversité de chemins nulle"

# 8e. Réversibilité : DISTINCT_PATH_MIN=1 restaure exactement le comportement d'avant 2.3.6.
printf 'DISTINCT_PATH_MIN=1\n' >> /etc/ban_404.conf
OUT=$(bash "$ENGINE" --dry-run 2>&1 || true)
printf '%s\n' "$OUT" | grep -q "$MISS" \
    || { printf '%s\n' "$OUT"; fail "DISTINCT_PATH_MIN=1 doit rendre le comportement historique"; }
ok "DISTINCT_PATH_MIN=1 restaure le comportement historique"
sed -i '/^DISTINCT_PATH_MIN=1$/d' /etc/ban_404.conf

echo "== INTÉGRATION OK =="

# ---------------------------------------------------------------------------
echo "== Test 9 : une IPv6 candidate ne peut pas être bannie — et n'est plus comptée comme telle =="
# Les deux backends ne savent stocker que de l'IPv4 (ipset créé « family inet » par défaut, set
# nftables en ipv4_addr). Jusqu'en 2.3.6 le code d'erreur de l'ajout était IGNORÉ : la ligne [+]
# partait au journal, la mémoire de récidive était alimentée, mais l'IP n'était JAMAIS bloquée —
# et comme `ipset test` la disait libre, elle était « re-bannie » à chaque passage. Sur le parc,
# deux IPv6 avaient ainsi accumulé 25 et 26 bans fictifs (constaté le 13 sept. 2026).
V6=2001:db8::66          # RFC 3849 (documentation) — jamais une vraie IP
LOGF="$TLOG"          # journal redirigé vers la fixture par le test 4
rm -f "$OFF"
: > "$LOGF"
for i in $(seq 1 15); do
    printf '%s - - [%s] "GET /v6-probe-%d/index.php HTTP/1.1" 404 200 "-" "bot/1.0"\n' "$V6" "$TS" "$i" >> "$LOG"
done

# 9a. Le parsing n'est pas en cause : le run DIT qu'il a vu une candidate qu'il ne sait pas bannir
# (le récapitulatif sort aussi en dry-run, t_log imprimant toujours sur stdout). Et l'IPv6 ne doit
# plus être annoncée comme bannissable, en simulation comme en réel.
OUT=$(bash "$ENGINE" --dry-run 2>&1 || true)
printf '%s\n' "$OUT" | grep -q 'IPv6' \
    || { printf '%s\n' "$OUT"; fail "le dry-run doit signaler la candidate IPv6 écartée (15 x 404, chemins variés)"; }
ok "candidate IPv6 vue et signalée (la détection n'est pas masquée)"
printf '%s\n' "$OUT" | grep -qF "$V6" \
    && { printf '%s\n' "$OUT"; fail "l'IPv6 ne doit plus être annoncée comme bannissable en simulation"; }
ok "simulation : aucun ban annoncé pour l'IPv6"

# 9b. Run réel : aucun [+] ne doit être journalisé pour elle (on ne journalise pas un ban fictif).
bash "$ENGINE" >/dev/null 2>&1 || true
grep -F "$V6" "$LOGF" 2>/dev/null | grep -q '\[+\]' \
    && { grep -F "$V6" "$LOGF"; fail "aucune ligne [+] ne doit être journalisée pour une IP non bannissable"; }
ok "aucun ban fictif journalisé pour l'IPv6"

# 9c. La mémoire de récidive ne doit PAS être alimentée (sinon le compteur enfle sans fin).
grep -q "^$V6 " "$OFF" 2>/dev/null \
    && { cat "$OFF"; fail "la mémoire de récidive ne doit pas enregistrer un ban qui n'a pas eu lieu"; }
ok "mémoire de récidive épargnée (pas de récidiviste fantôme)"

# 9d. Le run doit le DIRE : une ligne [i] récapitulative, une seule, quel que soit le nombre d'IPv6.
grep -q 'IPv6' "$LOGF" 2>/dev/null \
    || { cat "$LOGF"; fail "le run doit signaler au journal les candidates ignorées faute de support IPv6"; }
ok "run tracé au journal (candidates IPv6 ignorées, une seule ligne)"

# 9e. Non-régression : l'IPv4 du même run est toujours bannie normalement.
ipset test ban_404_list "$IP" >/dev/null 2>&1 \
    || fail "régression : l'IPv4 $IP doit rester bannie dans le même run"
ok "non-régression : l'IPv4 du même run est bannie normalement"

# 9f. Amnistie d'une IP ABSENTE du set : jusqu'en 2.3.7, « unban » sortait avant escalation_forget
# dès que l'IP n'était pas bannie — donc une entrée de récidive dont le ban avait expiré (cas
# NORMAL : l'épreuve dure ESCALATION_MEMORY après la libération) était INEFFAÇABLE. C'est ce qui
# empêchait de nettoyer les deux IPv6 fantômes du parc.
GHOST=203.0.113.201      # jamais bannie, mais inscrite dans la mémoire de récidive
printf '%s 7 %s\n' "$GHOST" "$(date +%s)" >> "$OFF"
ipset test ban_404_list "$GHOST" >/dev/null 2>&1 \
    && fail "préparation 9f : $GHOST ne doit pas être dans le set"
bash "$ENGINE" unban "$GHOST" >/dev/null 2>&1 || true
grep -q "^$GHOST " "$OFF" 2>/dev/null \
    && { cat "$OFF"; fail "unban doit effacer la mémoire de récidive même si l'IP n'est plus dans le set"; }
ok "amnistie d'une IP hors du set : entrée de récidive effacée"

# 9g. Une IP absente du set ET de la mémoire : unban reste un no-op silencieux (pas de faux [i]).
: > "$LOGF"
bash "$ENGINE" unban 203.0.113.202 >/dev/null 2>&1 || true
grep -q 'unban\|récidiv\|Repeat-offence' "$LOGF" 2>/dev/null \
    && { cat "$LOGF"; fail "unban sur une IP inconnue ne doit rien journaliser"; }
ok "unban sur une IP totalement inconnue : aucun effet de bord"

# ---------------------------------------------------------------------------
echo "== Test 10 : signature resultsPerPage hors du défaut + ligne « bans au score plancher » =="
# 2.3.9. (a) La signature du paramètre resultsPerPage DUPLIQUÉ ne doit plus bannir par défaut :
# PrestaShop fabrique lui-même ces URL (mesuré le 13 sept. 2026 : 100 % des bans d'un serveur, pour
# des IP à UNE requête qui ne reviennent jamais — zéro requête empêchée — et zéro déclenchement sur
# l'autre). (b) Le %3f encodé, lui, RESTE : aucun client légitime ne le produit.
PS=198.51.100.150      # suit un lien de facettes PrestaShop (URL légitime du site)
PSATK=198.51.100.151   # « ? » encodé dans la valeur du paramètre : vraie signature d'attaque
for i in $(seq 1 4); do
    printf '%s - - [%s] "GET /c/12-bagues?order=product.name.desc&resultsPerPage=72&resultsPerPage=24 HTTP/1.1" 200 5120 "-" "Mozilla/5.0"\n' "$PS" "$TS" >> "$LOG"
    printf '%s - - [%s] "GET /c/12-bagues?resultsPerPage=24%%3Fx HTTP/1.1" 200 5120 "-" "Mozilla/5.0"\n' "$PSATK" "$TS" >> "$LOG"
done
OUT=$(bash "$ENGINE" --dry-run 2>&1 || true)
printf '%s\n' "$OUT" | grep -qF "$PS" \
    && { printf '%s\n' "$OUT"; fail "resultsPerPage dupliqué ne doit plus bannir par défaut (URL générée par PrestaShop)"; }
ok "resultsPerPage dupliqué : hors du défaut, plus de ban"
printf '%s\n' "$OUT" | grep -qF "$PSATK" \
    || { printf '%s\n' "$OUT"; fail "régression : le « ? » encodé (%3f) doit rester une signature de ban"; }
ok "non-régression : la variante %3f encodée bannit toujours"

# 10c. Réversibilité : la conf locale doit pouvoir réarmer la signature (opt-in documenté).
printf 'SECURITY_PATTERN="${SECURITY_PATTERN}|resultsperpage.*resultsperpage"\n' >> /etc/ban_404.conf
OUT=$(bash "$ENGINE" --dry-run 2>&1 || true)
printf '%s\n' "$OUT" | grep -qF "$PS" \
    || { printf '%s\n' "$OUT"; fail "l'append en conf locale doit réarmer la signature"; }
ok "réarmement par conf locale opérationnel (append sur SECURITY_PATTERN)"
sed -i '/resultsperpage\.\*resultsperpage/d' /etc/ban_404.conf

# 10d. Ligne « bans au score plancher » : muette en dessous du seuil, visible au-dessus.
# On purge AUSSI les rotatés du test 4 : stats_log_stream les remonte tant que la fenêtre 24 h
# n'est pas couverte, et leurs 3 bans hors plancher fausseraient le dénominateur (« 40 of 43 »).
rm -f "$TLOG".1 "$TLOG".1.gz
: > "$TLOG"
NOW=$(date '+%Y-%m-%d %H:%M:%S')
for i in $(seq 1 5); do
    printf '%s [+] IMMEDIATE block (honeypot) of IP: 203.0.113.%d (score 100)\n' "$NOW" "$i" >> "$TLOG"
done
SOUT=$(bash "$ENGINE" stats --no-health 2>&1 || true)
printf '%s\n' "$SOUT" | grep -q 'single flagged request' \
    && { printf '%s\n' "$SOUT" | head -20; fail "5 bans au plancher : sous le seuil, la ligne doit rester muette"; }
ok "ligne muette sous le seuil (design d'alerte, pas de bruit sur un serveur sain)"

for i in $(seq 6 40); do
    printf '%s [+] IMMEDIATE block (honeypot) of IP: 203.0.113.%d (score 100)\n' "$NOW" "$i" >> "$TLOG"
done
SOUT=$(bash "$ENGINE" stats --no-health 2>&1 || true)
printf '%s\n' "$SOUT" | grep -q 'single flagged request: 40 of 40 (100 %)' \
    || { printf '%s\n' "$SOUT" |  sed -n '/Statistics/,$p' | head -12; fail "40 bans au plancher sur 40 : la ligne doit annoncer « 40 of 40 (100 %) »"; }
ok "ligne affichée au-dessus du seuil : 40 sur 40 (100 %)"

# 10e. Des bans à score ÉLEVÉ ne déclenchent pas la ligne (cas du scraper réellement intensif).
rm -f "$TLOG".1 "$TLOG".1.gz
: > "$TLOG"
for i in $(seq 1 40); do
    printf '%s [+] IMMEDIATE block (honeypot) of IP: 203.0.113.%d (score 1800)\n' "$NOW" "$i" >> "$TLOG"
done
SOUT=$(bash "$ENGINE" stats --no-health 2>&1 || true)
printf '%s\n' "$SOUT" | grep -q 'single flagged request' \
    && { printf '%s\n' "$SOUT" | head -20; fail "des bans à score 1800 ne sont PAS au plancher : la ligne ne doit pas sortir"; }
ok "non-régression : un scan intensif (score 1800) ne déclenche pas la ligne"

# ---------------------------------------------------------------------------
echo "== Test 11 : la porte de cadence s'ouvre quand le relevé horaire est dû =="
# 2.3.11. Un run complet hors échéance (sentinelle, cadence resserrée) relance l'horloge last_run
# sans relever les métriques (garde SAMPLE_MIN_INTERVAL) : le relevé suivant glissait d'un
# intervalle entier (jusqu'à ~110 min entre deux points). La porte doit désormais laisser passer
# un tick dès que le relevé est dû. Log vidé => la sentinelle ne peut pas ouvrir la porte à sa place.
# Entrée/sortie hors terminal : la porte ne s'applique jamais aux runs interactifs.
: > "$LOG"
STAMP=/var/lib/ban_404/last_run; METRICS=/var/lib/ban_404/metrics
printf 'CRON_STEP=auto\n' >> /etc/ban_404.conf
printf '60 0\n' > /var/lib/ban_404/cadence
gate_run() { bash "$ENGINE" </dev/null >/dev/null 2>&1 || true; }

# 11a. Relevé récent, dernier run il y a 10 min (intervalle 60) : tick porté, rien n'est écrit.
touch -d '-10 minutes' "$STAMP"; before=$(stat -c %Y "$STAMP")
printf '%s - - - - -\n' "$(date +%s)" > "$METRICS"
gate_run
[ "$(stat -c %Y "$STAMP")" = "$before" ] || fail "11a : relevé récent, le tick aurait dû être porté (last_run modifié)"
ok "tick porté quand aucun relevé n'est dû"

# 11b. Même situation, mais relevé vieux de 2 h : la porte s'ouvre, run complet + nouveau relevé.
old=$(( $(date +%s) - 7200 ))
printf '%s - - - - -\n' "$old" > "$METRICS"; touch -d "@$old" "$METRICS"
t0=$(date +%s)
gate_run
[ "$(stat -c %Y "$STAMP")" -ge "$t0" ] || fail "11b : relevé dû, la porte aurait dû laisser passer un run complet"
[ "$(wc -l < "$METRICS")" -eq 2 ] || { cat "$METRICS"; fail "11b : le run forcé doit poser un relevé (sinon chaque tick rouvrirait la porte)"; }
ok "relevé dû : run complet forcé, relevé posé"

# 11c. Fichier de métriques absent : pas de forçage (le prochain run normal le créera).
rm -f "$METRICS"
touch -d '-10 minutes' "$STAMP"; before=$(stat -c %Y "$STAMP")
gate_run
[ "$(stat -c %Y "$STAMP")" = "$before" ] || fail "11c : sans fichier de métriques, la porte ne doit pas s'ouvrir à chaque tick"
ok "fichier de métriques absent : pas de run forcé"

sed -i '/^CRON_STEP=auto$/d' /etc/ban_404.conf
rm -f /etc/cron.d/ban_404_step /var/lib/ban_404/cadence

# ---------------------------------------------------------------------------
echo "== Test 12 : alertes de ban routées (destinataire dédié, canal), liste bornée, enveloppe SPF =="
# 2.3.12. Les alertes de ban partaient sur TOUS les canaux, vers le seul NOTIFY_EMAIL : impossible
# d'alerter le client d'un serveur sans l'abonner au résumé technique, ni sans inonder le webhook
# partagé. Les outils d'envoi (mail, sendmail, curl) sont remplacés par des doublures qui consignent
# leurs arguments (et le message reçu sur l'entrée standard).
STUB=/tmp/b404stub; rm -rf "$STUB"; mkdir -p "$STUB"
cat > "$STUB/stub" <<'EOS'
#!/bin/bash
n=${0##*/}
{ printf 'ARGS:'; printf ' %s' "$@"; printf '\n'; [ "$n" = curl ] || cat; } >> "/tmp/b404stub/$n.log"
exit 0
EOS
chmod +x "$STUB/stub"
for c in mail sendmail curl; do ln -s "$STUB/stub" "$STUB/$c"; done
stub_run() { PATH="$STUB:$PATH" bash "$ENGINE" "$@" </dev/null >/dev/null 2>&1 || true; }

cat >> /etc/ban_404.conf <<'EOC'
# test12-debut
NOTIFY_BANS=true
NOTIFY_EMAIL=resume@example.test
NOTIFY_FROM="Ban 404 <no-reply@example.test>"
NOTIFY_BANS_EMAIL=alertes@example.test
NOTIFY_BANS_CHANNELS=email
WEBHOOK_URL=http://127.0.0.1:9/hook
NOTIFY_BANS_LIST_MAX=3
DAILY_SUMMARY=true
# test12-fin
EOC

# Cinq sondes honeypot (score 100 chacune) + un flood de 120 × 404 PURS, sans aucun chemin-piège.
VOLIP=198.51.100.210
: > "$LOG"; rm -f "$OFF"
for i in 201 202 203 204 205; do
    printf '198.51.100.%s - - [%s] "GET /.env HTTP/1.1" 404 200 "-" "bot/1.0"\n' "$i" "$TS" >> "$LOG"
done
for i in $(seq 1 120); do
    printf '%s - - [%s] "GET /absent-%d HTTP/1.1" 404 200 "-" "bot/1.0"\n' "$VOLIP" "$TS" "$i" >> "$LOG"
done
stub_run

# 12a. Routage : l'alerte va au destinataire dédié, par e-mail seul.
grep -q 'alertes@example.test' "$STUB/mail.log" 2>/dev/null \
    || { cat "$STUB/mail.log" 2>/dev/null; fail "12a : l'alerte doit partir vers NOTIFY_BANS_EMAIL"; }
grep -q 'resume@example.test' "$STUB/mail.log" 2>/dev/null \
    && fail "12a : l'alerte ne doit PAS partir vers le destinataire du résumé"
grep -q '127.0.0.1:9/hook' "$STUB/curl.log" 2>/dev/null \
    && fail "12a : NOTIFY_BANS_CHANNELS=email, le webhook ne doit pas être appelé"
ok "alerte vers NOTIFY_BANS_EMAIL, par e-mail seul (ni résumé, ni webhook)"

# 12b. Liste bornée : 6 bans, 3 détaillés (plus hauts scores d'abord) + une ligne « et 3 autres ».
[ "$(grep -c '^  198\.51\.100\.2[0-9][0-9] —' "$STUB/mail.log")" -eq 3 ] \
    || { cat "$STUB/mail.log"; fail "12b : 3 IP détaillées attendues (NOTIFY_BANS_LIST_MAX=3)"; }
grep -q '3 more IP(s) (full list: ban_404.sh list)' "$STUB/mail.log" \
    || { cat "$STUB/mail.log"; fail "12b : ligne « … and 3 more » attendue"; }
grep -q '^6 new IP(s) banned on ' "$STUB/mail.log" \
    || { cat "$STUB/mail.log"; fail "12b : le mail doit garder sa phrase d'en-tête (le sujet y est affiché à part)"; }
ok "liste bornée à NOTIFY_BANS_LIST_MAX, surplus résumé en une ligne"

# 12c. Un flood de 404 PURS, même au-delà de HONEYPOT_SCORE, n'est plus annoncé « honeypot »…
grep -q "$VOLIP — score 120 (404 flood)" "$STUB/mail.log" \
    || { cat "$STUB/mail.log"; fail "12c : $VOLIP doit être annoncé comme un flood 404 dans l'alerte"; }
grep -a "$VOLIP" "$TLOG" | grep -q honeypot \
    && { grep -a "$VOLIP" "$TLOG"; fail "12c : $VOLIP journalisé « honeypot » alors qu'il n'a touché aucun piège"; }
# … mais sa durée ne bouge pas : même circuit long que les sondes honeypot du même run.
TO_V=$(ipset_timeout "$VOLIP"); TO_H=$(ipset_timeout 198.51.100.201)
[ -n "$TO_V" ] && [ -n "$TO_H" ] && [ $((TO_H - TO_V)) -le 5 ] && [ $((TO_V - TO_H)) -le 5 ] \
    || fail "12c : durée du flood massif attendue identique au circuit honeypot ($TO_H), obtenue « ${TO_V:-absent} »"
ok "flood 404 massif : libellé « 404 flood », durée inchangée ($TO_V s)"

# 12d. Résumé : toujours vers NOTIFY_EMAIL, et enveloppe = adresse de NOTIFY_FROM (sendmail -f).
stub_run summary
grep -q '^ARGS: -t -f no-reply@example.test$' "$STUB/sendmail.log" 2>/dev/null \
    || { cat "$STUB/sendmail.log" 2>/dev/null | head -5; fail "12d : sendmail -t doit recevoir -f <adresse de NOTIFY_FROM>"; }
grep -q '^To: resume@example.test$' "$STUB/sendmail.log" \
    || fail "12d : le résumé doit partir vers NOTIFY_EMAIL"
ok "résumé vers NOTIFY_EMAIL, enveloppe alignée sur NOTIFY_FROM"

# 12e. check-notification teste AUSSI le destinataire des alertes.
rm -f "$STUB/mail.log"
stub_run check-notification email
grep -q 'resume@example.test' "$STUB/mail.log" && grep -q 'alertes@example.test' "$STUB/mail.log" \
    || { cat "$STUB/mail.log" 2>/dev/null; fail "12e : les deux destinataires doivent recevoir un test"; }
ok "check-notification teste les deux destinataires"

# 12f. Canal webhook : le sujet ouvre déjà le message, la phrase d'en-tête du corps n'y est plus
# répétée (elle l'était mot pour mot) ; le mail, lui, la garde pour introduire la liste.
sed -i 's/^NOTIFY_BANS_CHANNELS=email$/NOTIFY_BANS_CHANNELS=webhook/' /etc/ban_404.conf
printf '198.51.100.220 - - [%s] "GET /.env HTTP/1.1" 404 200 "-" "bot/1.0"\n' "$TS" >> "$LOG"
rm -f "$STUB/curl.log" "$STUB/mail.log"
stub_run
grep -q '127.0.0.1:9/hook' "$STUB/curl.log" 2>/dev/null && grep -q '198.51.100.220' "$STUB/curl.log" \
    || { cat "$STUB/curl.log" 2>/dev/null; fail "12f : NOTIFY_BANS_CHANNELS=webhook, l'alerte doit partir sur le webhook"; }
grep -q 'banned on' "$STUB/curl.log" \
    && { cat "$STUB/curl.log"; fail "12f : le message webhook ne doit plus répéter le sujet en en-tête de corps"; }
[ -e "$STUB/mail.log" ] && fail "12f : NOTIFY_BANS_CHANNELS=webhook, aucun e-mail ne doit partir"
ok "webhook : sujet en tête, sans phrase d'en-tête redondante ; aucun e-mail"

sed -i '/^# test12-debut$/,/^# test12-fin$/d' /etc/ban_404.conf
rm -rf "$STUB" /etc/cron.daily/1_ban_404_summary   # DAILY_SUMMARY=true a fait poser le cron de résumé

echo "== Test 13 : le diag dit si le domaine de NOTIFY_FROM autorise ce serveur en SPF =="
# 2.3.14. Depuis 2.3.12, NOTIFY_FROM est aussi l'expéditeur d'ENVELOPPE : c'est lui que vérifie le
# SPF du destinataire. Un domaine sans SPF (nom d'hôte de l'hébergeur par défaut) fait classer les
# résumés en spam SANS aucun signe côté serveur — le MTA reçoit un « 250 OK ». Tout un parc a
# basculé ainsi en une nuit. On double `dig` pour rendre le contrôle déterministe (aucun DNS réel).
SPFD=/tmp/b404spf; rm -rf "$SPFD"; mkdir -p "$SPFD"
cat > "$SPFD/dig" <<'EOS'
#!/bin/bash
cat /tmp/b404spf/answer 2>/dev/null
exit 0
EOS
chmod +x "$SPFD/dig"
MYIP=$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1)
[ -n "$MYIP" ] || MYIP=127.0.0.1

cat >> /etc/ban_404.conf <<'EOC'
# test13-debut
NOTIFY_EMAIL=resume@example.test
NOTIFY_FROM="no-reply@spftest.example"
# test13-fin
EOC
# Le tag [ OK ]/[WARN] n'est jamais traduit : on l'utilise comme verdict, quelle que soit la langue.
spf_verdict() { printf '%s\n' "$1" > "$SPFD/answer"
    PATH="$SPFD:$PATH" bash "$ENGINE" diag 2>/dev/null | grep -m1 'spftest\.example' | sed -E 's/^\[([^]]*)\].*/\1/' | tr -d ' '; }

v=$(spf_verdict "\"v=spf1 ip4:$MYIP ~all\"")
[ "$v" = "OK" ] || fail "13a : une IP listée en ip4 doit donner [ OK ] (obtenu : ${v:-<aucune ligne>})"
ok "SPF listant ce serveur : [ OK ]"

v=$(spf_verdict "\"v=spf1 ip4:203.0.113.1 -all\"")
[ "$v" = "WARN" ] || fail "13b : un SPF strict sans notre IP doit donner [WARN] (obtenu : ${v:-<aucune ligne>})"
ok "SPF strict qui n'autorise pas ce serveur : [WARN]"

v=$(spf_verdict "")
[ "$v" = "WARN" ] || fail "13c : un domaine SANS SPF doit donner [WARN] (obtenu : ${v:-<aucune ligne>})"
ok "domaine sans SPF (le cas fondateur) : [WARN]"

# Un SPF qui délègue (include/a/mx) n'est PAS évaluable sans résolution récursive : le contrôle doit
# le dire sans accuser — aucun faux positif, c'est la condition pour qu'il reste crédible.
v=$(spf_verdict "\"v=spf1 mx a include:_spf.google.com ~all\"")
[ "$v" = "OK" ] || fail "13d : un SPF qui délègue ne doit PAS produire de [WARN] (obtenu : ${v:-<aucune ligne>})"
ok "SPF délégué (include/a/mx) : signalé non vérifiable, sans faux positif"

sed -i '/^# test13-debut$/,/^# test13-fin$/d' /etc/ban_404.conf
rm -rf "$SPFD"

# ---------------------------------------------------------------------------
echo "== Test 14 : après minuit, le log de la VEILLE est lu tant que la fenêtre y déborde =="
# 2.3.15. ISPConfig bascule access.log sur le nouveau AAAAMMJJ-access.log à 00:00 : un run de 00:30
# ne voyait que 30 min de trafic. On simule « juste après minuit » en élargissant WINDOW jusqu'à la
# veille, plutôt qu'en truquant l'horloge. Le flood est dans le fichier de la VEILLE uniquement.
D14="$FIX/www/site14.example/log"; mkdir -p "$D14"
TODAY14=$(date +%Y%m%d); YDAY14=$(date -d yesterday +%Y%m%d)
IP14=198.51.100.140
TS14=$(LC_ALL=C date -u '+%d/%b/%Y:%H:%M:%S +0000')
: > "$D14/$TODAY14-access.log"; ln -sfn "$TODAY14-access.log" "$D14/access.log"
: > "$D14/$YDAY14-access.log"
for i in $(seq 1 7); do   # 7 × 404 : sous le seuil (10), mais 14 si le fichier était lu deux fois
    printf '%s - - [%s] "GET /probe14-%d HTTP/1.1" 404 200 "-" "bot/1.0"\n' "$IP14" "$TS14" "$i" >> "$D14/$YDAY14-access.log"
done
for i in $(seq 8 12); do
    printf '%s - - [%s] "GET /probe14-%d HTTP/1.1" 404 200 "-" "bot/1.0"\n' "$IP14" "$TS14" "$i" >> "$D14/$YDAY14-access.log"
done
SINCE_MIDNIGHT=$(( $(date +%s) - $(date -d 'today 00:00' +%s) ))

# 14a. Fenêtre courte, entièrement dans la journée : la veille n'est PAS lue.
printf 'WINDOW=60\n' >> /etc/ban_404.conf
OUT=$(bash "$ENGINE" --dry-run --verbose 2>&1 || true)
if [ "$SINCE_MIDNIGHT" -gt 120 ]; then
    printf '%s\n' "$OUT" | grep -q "$YDAY14-access.log" && { printf '%s\n' "$OUT"; fail "14a : fenêtre dans la journée, le log de la veille ne doit pas être lu"; }
    ok "fenêtre dans la journée : log de la veille ignoré"
fi
sed -i '/^WINDOW=60$/d' /etc/ban_404.conf

# 14b. Fenêtre qui déborde sur la veille : le fichier daté de la veille est lu, le flood détecté.
printf 'WINDOW=%s\n' "$(( SINCE_MIDNIGHT + 3600 ))" >> /etc/ban_404.conf
OUT=$(bash "$ENGINE" --dry-run 2>&1 || true)
printf '%s\n' "$OUT" | grep -q "$IP14" || { printf '%s\n' "$OUT"; fail "14b : le flood du log de la veille aurait dû être détecté"; }
ok "fenêtre à cheval sur minuit : log de la veille lu, flood détecté"

# 14c. access.log pointe encore sur la veille (bascule en retard) : un seul passage, pas de double
# comptage. On ne garde que 7 lignes : lues deux fois, elles franchiraient le seuil.
sed -i '8,$d' "$D14/$YDAY14-access.log"
ln -sfn "$YDAY14-access.log" "$D14/access.log"
OUT=$(bash "$ENGINE" --dry-run 2>&1 || true)
printf '%s\n' "$OUT" | grep -q "$IP14" && { printf '%s\n' "$OUT"; fail "14c : access.log -> veille, le fichier a été lu deux fois (score doublé)"; }
ok "access.log pointant sur la veille : fichier lu une seule fois"

sed -i '/^WINDOW=/d' /etc/ban_404.conf
rm -rf "$FIX/www/site14.example"
