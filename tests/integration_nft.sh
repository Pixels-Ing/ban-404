#!/bin/bash
# Test d'intégration ban-404 — backend nftables + BASCULE de backend (iptables -> nftables).
# Complète tests/integration.sh (chemin de référence iptables) : ici on exerce le backend nft opt-in
# et la migration one-shot. Exécuté par .github/workflows/check.yml sur le runner Ubuntu, en root
# (sudo) : les tests créent une vraie table nft / un vrai ipset.
#
# Usage : sudo bash tests/integration_nft.sh [chemin_du_moteur]   (défaut : ./ban_404.sh)
set -u

ENGINE="${1:-./ban_404.sh}"
FIX=/tmp/b404fix_nft
IP=203.0.113.77        # TEST-NET-3 (RFC 5737) — jamais une vraie IP
SET=ban_404_list

fail() { echo "ÉCHEC : $*" >&2; exit 1; }
ok()   { echo "  OK  $*"; }

[ -f "$ENGINE" ] || fail "moteur introuvable : $ENGINE (lancer depuis la racine du dépôt)"
[ "$(id -u)" -eq 0 ] || fail "ce test nécessite root — lancer via sudo"
command -v nft >/dev/null 2>&1 || fail "nft absent (installer le paquet nftables)"

cleanup_fw() {
    ipset destroy "$SET" 2>/dev/null || true
    iptables -D INPUT -m set --match-set "$SET" src -j DROP 2>/dev/null || true
    nft delete table inet ban_404 2>/dev/null || true
}

# Fixture commune : arborescence ISPConfig + flood 404 récent (dans la fenêtre WINDOW de 2 h).
build_fixture() {
    rm -rf "$FIX"; mkdir -p "$FIX/www/site1.example/log"
    local log ts i
    log="$FIX/www/site1.example/log/access.log"
    ts=$(LC_ALL=C date -u '+%d/%b/%Y:%H:%M:%S +0000')
    : > "$log"
    for i in $(seq 1 15); do
        printf '%s - - [%s] "GET /nonexistent-%d HTTP/1.1" 404 200 "-" "bot/1.0"\n' "$IP" "$ts" "$i" >> "$log"
    done
}
write_conf() {  # $1 = valeur de FW_BACKEND
    cat > /etc/ban_404.conf <<EOF
BASE_DIR=$FIX/www
WHITELIST_IP=127.0.0.1
NOTIFY_BANS=false
DAILY_SUMMARY=false
HEALTH_CHECKS=false
FW_BACKEND=$1
EOF
}
nft_has()  { nft list set inet ban_404 "$SET" 2>/dev/null | grep -qwF -- "$IP"; }
nft_rule() { nft list chain inet ban_404 input 2>/dev/null | grep -q "@$SET drop"; }

modprobe ip_set 2>/dev/null || true
modprobe nf_tables 2>/dev/null || true
mkdir -p /var/lib/ban_404 && touch /var/lib/ban_404/last_update   # neutralise le filet updater

# ===========================================================================
echo "== Test A : backend nftables « from scratch » =="
cleanup_fw
build_fixture
write_conf nftables

OUT=$(bash "$ENGINE" --dry-run 2>&1 || true)
printf '%s\n' "$OUT" | grep -q "$IP" || { printf '%s\n' "$OUT"; fail "A1 : flood 404 non détecté en dry-run (backend nft)"; }
ok "A1 flood 404 détecté (dry-run, backend nftables)"

bash "$ENGINE" >/dev/null 2>&1 || true
nft_has  || { nft list ruleset 2>/dev/null | sed -n '1,40p'; fail "A2 : IP $IP absente du set nft ban_404_list après un run réel"; }
ok "A2 IP bannie dans le set nft inet ban_404 $SET"
nft_rule || fail "A3 : règle « ip saddr @$SET drop » absente de la chaîne nft input"
ok "A3 règle DROP nft présente"

# 'list' doit énumérer l'IP bannie AVEC un timeout NUMÉRIQUE (pas « ? ») : exerce nft_list_members_raw
# + nft_dur_to_secs, dont les bugs (collision awk « exp » fatale sous gawk ; strip glob « %%[0-9]*ms »
# qui effaçait la durée ; « m » de « ms » compté en minutes) donnaient soit une liste vide soit « ? ».
LLINE=$(bash "$ENGINE" list 2>&1 | grep -F "$IP")
printf '%s\n' "$LLINE" | grep -qE 'timeout[^0-9]*[0-9]+' || { bash "$ENGINE" list 2>&1 | head; fail "A3bis : 'list' n'affiche pas l'IP $IP avec un timeout numérique (nft_list_members_raw/dur)"; }
ok "A3bis 'list' énumère l'IP bannie + timeout numérique sous nft"

bash "$ENGINE" unban "$IP" >/dev/null 2>&1 || fail "A4 : la sous-commande unban a échoué (backend nft)"
nft_has && fail "A4 : IP $IP toujours dans le set nft après unban"
ok "A4 IP débannie proprement (backend nft)"

DOUT=$(bash "$ENGINE" diag 2>&1 || true)
printf '%s\n' "$DOUT" | grep -q 'nftables' || { printf '%s\n' "$DOUT"; fail "A5 : diag ne rapporte pas le backend nftables"; }
ok "A5 diag rapporte le backend nftables"

# ===========================================================================
echo "== Test B : bascule migratoire iptables -> nftables (bans transférés, sans trou) =="
cleanup_fw
build_fixture
write_conf iptables        # départ sur le backend historique
bash "$ENGINE" >/dev/null 2>&1 || true
ipset test "$SET" "$IP" 2>/dev/null || fail "B1 : IP $IP non bannie dans l'ipset (départ iptables)"
iptables -C INPUT -m set --match-set "$SET" src -j DROP 2>/dev/null || fail "B1 : règle iptables absente au départ"
ok "B1 IP bannie côté iptables+ipset (état de départ)"

write_conf nftables        # l'admin bascule
bash "$ENGINE" >/dev/null 2>&1 || true
nft_has  || fail "B2 : IP $IP non transférée vers le set nft lors de la bascule"
nft_rule || fail "B2 : règle DROP nft absente après la bascule"
ok "B2 ban transféré vers nft + règle nft en place"
ipset list "$SET" &>/dev/null && fail "B3 : l'ipset ban_404_list existe encore après la bascule (aurait dû être retiré)"
ok "B3 ipset retiré (uniquement nos artefacts, jamais de flush)"
iptables -C INPUT -m set --match-set "$SET" src -j DROP 2>/dev/null && fail "B3 : la règle iptables ban-404 subsiste après la bascule"
ok "B3 règle iptables ban-404 retirée"

echo "== Test B (suite) : bascule INVERSE nftables -> iptables (réversibilité + nettoyage) =="
write_conf iptables
bash "$ENGINE" >/dev/null 2>&1 || true
ipset test "$SET" "$IP" 2>/dev/null || fail "B4 : IP $IP non re-transférée vers l'ipset au retour iptables"
iptables -C INPUT -m set --match-set "$SET" src -j DROP 2>/dev/null || fail "B4 : règle iptables absente au retour"
ok "B4 ban re-transféré vers ipset + règle iptables restaurée"
nft list table inet ban_404 &>/dev/null && fail "B5 : table nft ban_404 subsiste après retour iptables"
ok "B5 table nft ban_404 retirée (retour propre)"

cleanup_fw
echo "== INTÉGRATION NFT OK =="
