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
SUMMARY_CRON="/etc/cron.daily/ban_404_summary"

# >>> A EDITER UNE FOIS avant distribution : URL "raw" de ton depot (sans slash final) <<<
REPO_RAW="https://raw.githubusercontent.com/PixelsIng/ban-404/main"

# --- i18n : messages multilingues (en, fr, de, es, it). Voir ban_404.sh pour le mecanisme. ---
declare -A T_EN T_FR T_DE T_ES T_IT

T_EN[inst.error_prefix]="ERROR: "
T_FR[inst.error_prefix]="ERREUR : "
T_DE[inst.error_prefix]="FEHLER: "
T_ES[inst.error_prefix]="ERROR: "
T_IT[inst.error_prefix]="ERRORE: "

T_EN[inst.need_root]="must be run as root (sudo)."
T_FR[inst.need_root]="à lancer en root (sudo)."
T_DE[inst.need_root]="muss als root (sudo) ausgeführt werden."
T_ES[inst.need_root]="debe ejecutarse como root (sudo)."
T_IT[inst.need_root]="da eseguire come root (sudo)."

T_EN[inst.pkg_install]="==> Installing required packages..."
T_FR[inst.pkg_install]="==> Installation des paquets requis..."
T_DE[inst.pkg_install]="==> Erforderliche Pakete werden installiert..."
T_ES[inst.pkg_install]="==> Instalando los paquetes necesarios..."
T_IT[inst.pkg_install]="==> Installazione dei pacchetti richiesti..."

T_EN[inst.apt_update_warn]="   (apt-get update failed — continuing with the local cache)"
T_FR[inst.apt_update_warn]="   (apt-get update en erreur — on poursuit avec le cache local)"
T_DE[inst.apt_update_warn]="   (apt-get update fehlgeschlagen — Fortsetzung mit dem lokalen Cache)"
T_ES[inst.apt_update_warn]="   (apt-get update con error — se continúa con la caché local)"
T_IT[inst.apt_update_warn]="   (apt-get update non riuscito — si prosegue con la cache locale)"

T_EN[inst.universe_try]="   failed — trying to enable the 'universe' repo (required for ipset-persistent on 22.04)..."
T_FR[inst.universe_try]="   echec — tentative d'activation du depot 'universe' (requis pour ipset-persistent sur 22.04)..."
T_DE[inst.universe_try]="   fehlgeschlagen — Versuch, das Repo 'universe' zu aktivieren (erforderlich für ipset-persistent auf 22.04)..."
T_ES[inst.universe_try]="   fallo — intentando activar el repositorio 'universe' (necesario para ipset-persistent en 22.04)..."
T_IT[inst.universe_try]="   errore — tentativo di attivare il repository 'universe' (richiesto per ipset-persistent su 22.04)..."

T_EN[inst.pkg_fail]="package installation failed (is the 'universe' repo enabled?)."
T_FR[inst.pkg_fail]="echec installation paquets (le depot 'universe' est-il active ?)."
T_DE[inst.pkg_fail]="Paketinstallation fehlgeschlagen (ist das Repo 'universe' aktiviert?)."
T_ES[inst.pkg_fail]="fallo en la instalación de paquetes (¿está activado el repositorio 'universe'?)."
T_IT[inst.pkg_fail]="installazione dei pacchetti non riuscita (il repository 'universe' è attivo?)."

T_EN[inst.migrate_ipset]="==> Possible migration of the old ipset persistence path..."
T_FR[inst.migrate_ipset]="==> Migration eventuelle de l'ancien chemin de persistance ipset..."
T_DE[inst.migrate_ipset]="==> Mögliche Migration des alten ipset-Persistenzpfads..."
T_ES[inst.migrate_ipset]="==> Posible migración de la antigua ruta de persistencia de ipset..."
T_IT[inst.migrate_ipset]="==> Possibile migrazione del vecchio percorso di persistenza ipset..."

T_EN[inst.ipsets_link]="   /etc/iptables/ipsets is a symlink -> %s"
T_FR[inst.ipsets_link]="   /etc/iptables/ipsets est un lien -> %s"
T_DE[inst.ipsets_link]="   /etc/iptables/ipsets ist ein Symlink -> %s"
T_ES[inst.ipsets_link]="   /etc/iptables/ipsets es un enlace -> %s"
T_IT[inst.ipsets_link]="   /etc/iptables/ipsets è un collegamento -> %s"

T_EN[inst.ipsets_materialized]="   content materialized into a real file /etc/iptables/ipsets"
T_FR[inst.ipsets_materialized]="   contenu materialise dans un vrai fichier /etc/iptables/ipsets"
T_DE[inst.ipsets_materialized]="   Inhalt in eine echte Datei /etc/iptables/ipsets überführt"
T_ES[inst.ipsets_materialized]="   contenido materializado en un archivo real /etc/iptables/ipsets"
T_IT[inst.ipsets_materialized]="   contenuto materializzato in un vero file /etc/iptables/ipsets"

T_EN[inst.old_ipset_removed]="   old /etc/iptables/ipset removed"
T_FR[inst.old_ipset_removed]="   ancien /etc/iptables/ipset supprime"
T_DE[inst.old_ipset_removed]="   altes /etc/iptables/ipset entfernt"
T_ES[inst.old_ipset_removed]="   antiguo /etc/iptables/ipset eliminado"
T_IT[inst.old_ipset_removed]="   vecchio /etc/iptables/ipset rimosso"

T_EN[inst.decom]="==> Decommissioning any old ban 404 script..."
T_FR[inst.decom]="==> Decommissionnement de tout ancien script de ban 404..."
T_DE[inst.decom]="==> Außerbetriebnahme aller alten Ban-404-Skripte..."
T_ES[inst.decom]="==> Retirada de cualquier antiguo script de ban 404..."
T_IT[inst.decom]="==> Dismissione di ogni vecchio script di ban 404..."

T_EN[inst.old_script_removed]="   old script removed: %s"
T_FR[inst.old_script_removed]="   ancien script supprime : %s"
T_DE[inst.old_script_removed]="   altes Skript entfernt: %s"
T_ES[inst.old_script_removed]="   antiguo script eliminado: %s"
T_IT[inst.old_script_removed]="   vecchio script rimosso: %s"

T_EN[inst.old_cron_link_removed]="   old cron (symlink) removed: %s"
T_FR[inst.old_cron_link_removed]="   ancien cron (lien) supprime : %s"
T_DE[inst.old_cron_link_removed]="   alter Cron (Symlink) entfernt: %s"
T_ES[inst.old_cron_link_removed]="   antiguo cron (enlace) eliminado: %s"
T_IT[inst.old_cron_link_removed]="   vecchio cron (collegamento) rimosso: %s"

T_EN[inst.old_cron_removed]="   old cron removed: %s"
T_FR[inst.old_cron_removed]="   ancien cron supprime : %s"
T_DE[inst.old_cron_removed]="   alter Cron entfernt: %s"
T_ES[inst.old_cron_removed]="   antiguo cron eliminado: %s"
T_IT[inst.old_cron_removed]="   vecchio cron rimosso: %s"

T_EN[inst.refs_manual]="References to check/remove manually: %s"
T_FR[inst.refs_manual]="Références à vérifier/retirer manuellement : %s"
T_DE[inst.refs_manual]="Referenzen, die manuell zu prüfen/entfernen sind: %s"
T_ES[inst.refs_manual]="Referencias a verificar/eliminar manualmente: %s"
T_IT[inst.refs_manual]="Riferimenti da verificare/rimuovere manualmente: %s"

T_EN[inst.chain_removed]="   AUTOBAN404 chain dismantled"
T_FR[inst.chain_removed]="   chaine AUTOBAN404 demontee"
T_DE[inst.chain_removed]="   Kette AUTOBAN404 abgebaut"
T_ES[inst.chain_removed]="   cadena AUTOBAN404 desmontada"
T_IT[inst.chain_removed]="   catena AUTOBAN404 smontata"

T_EN[inst.varlib_removed]="   /var/lib/auto-ban-404 removed"
T_FR[inst.varlib_removed]="   /var/lib/auto-ban-404 supprime"
T_DE[inst.varlib_removed]="   /var/lib/auto-ban-404 entfernt"
T_ES[inst.varlib_removed]="   /var/lib/auto-ban-404 eliminado"
T_IT[inst.varlib_removed]="   /var/lib/auto-ban-404 rimosso"

T_EN[inst.conf_local]="==> Local configuration: %s"
T_FR[inst.conf_local]="==> Configuration locale : %s"
T_DE[inst.conf_local]="==> Lokale Konfiguration: %s"
T_ES[inst.conf_local]="==> Configuración local: %s"
T_IT[inst.conf_local]="==> Configurazione locale: %s"

T_EN[inst.conf_created]="   created (remember to adjust WHITELIST_IP on this server)"
T_FR[inst.conf_created]="   cree (pense a adapter WHITELIST_IP sur ce serveur)"
T_DE[inst.conf_created]="   erstellt (denken Sie daran, WHITELIST_IP auf diesem Server anzupassen)"
T_ES[inst.conf_created]="   creado (recuerde adaptar WHITELIST_IP en este servidor)"
T_IT[inst.conf_created]="   creato (ricordarsi di adattare WHITELIST_IP su questo server)"

T_EN[inst.conf_kept]="   existing one kept (not overwritten)"
T_FR[inst.conf_kept]="   existant conserve (non ecrase)"
T_DE[inst.conf_kept]="   vorhandene beibehalten (nicht überschrieben)"
T_ES[inst.conf_kept]="   se conserva el existente (no sobrescrito)"
T_IT[inst.conf_kept]="   esistente conservato (non sovrascritto)"

T_EN[inst.selfupdater]="==> Self-updater: %s (+ %s)"
T_FR[inst.selfupdater]="==> Self-updater : %s (+ %s)"
T_DE[inst.selfupdater]="==> Self-Updater: %s (+ %s)"
T_ES[inst.selfupdater]="==> Auto-actualizador: %s (+ %s)"
T_IT[inst.selfupdater]="==> Self-updater: %s (+ %s)"

T_EN[inst.summary_cron]="==> Daily summary cron: %s (opt-in via DAILY_SUMMARY)"
T_FR[inst.summary_cron]="==> Cron de résumé quotidien : %s (opt-in via DAILY_SUMMARY)"
T_DE[inst.summary_cron]="==> Cron für tägliche Zusammenfassung: %s (opt-in über DAILY_SUMMARY)"
T_ES[inst.summary_cron]="==> Cron de resumen diario: %s (opt-in vía DAILY_SUMMARY)"
T_IT[inst.summary_cron]="==> Cron del riepilogo giornaliero: %s (opt-in tramite DAILY_SUMMARY)"

T_EN[inst.fetch_engine]="==> Initial fetch of the engine via the updater: %s"
T_FR[inst.fetch_engine]="==> Recuperation initiale du moteur via l'updater : %s"
T_DE[inst.fetch_engine]="==> Erstes Abrufen der Engine über den Updater: %s"
T_ES[inst.fetch_engine]="==> Recuperación inicial del motor mediante el actualizador: %s"
T_IT[inst.fetch_engine]="==> Recupero iniziale del motore tramite l'updater: %s"

T_EN[inst.fetch_fail]="cannot fetch %s from %s. Check network access and REPO_RAW in %s (see %s; nothing installed for the engine)."
T_FR[inst.fetch_fail]="impossible de recuperer %s depuis %s. Verifie l'acces reseau et REPO_RAW dans %s (voir %s ; rien d'installe pour le moteur)."
T_DE[inst.fetch_fail]="%s kann nicht von %s abgerufen werden. Prüfen Sie den Netzwerkzugang und REPO_RAW in %s (siehe %s; nichts für die Engine installiert)."
T_ES[inst.fetch_fail]="no se puede recuperar %s desde %s. Verifique el acceso de red y REPO_RAW en %s (consulte %s; no se instaló nada para el motor)."
T_IT[inst.fetch_fail]="impossibile recuperare %s da %s. Verificare l'accesso di rete e REPO_RAW in %s (vedere %s; nulla installato per il motore)."

T_EN[inst.cron_hourly]="==> Hourly task: %s"
T_FR[inst.cron_hourly]="==> Tache horaire : %s"
T_DE[inst.cron_hourly]="==> Stündliche Aufgabe: %s"
T_ES[inst.cron_hourly]="==> Tarea horaria: %s"
T_IT[inst.cron_hourly]="==> Attività oraria: %s"

T_EN[inst.logrotate]="==> Log rotation: %s"
T_FR[inst.logrotate]="==> Rotation du log : %s"
T_DE[inst.logrotate]="==> Log-Rotation: %s"
T_ES[inst.logrotate]="==> Rotación del registro: %s"
T_IT[inst.logrotate]="==> Rotazione del log: %s"

T_EN[inst.activate]="==> Immediate activation (creating the ipset + DROP rule, then persistence)..."
T_FR[inst.activate]="==> Activation immediate (creation de l'ipset + regle DROP, puis persistance)..."
T_DE[inst.activate]="==> Sofortige Aktivierung (Erstellung des ipset + DROP-Regel, dann Persistenz)..."
T_ES[inst.activate]="==> Activación inmediata (creación del ipset + regla DROP, luego persistencia)..."
T_IT[inst.activate]="==> Attivazione immediata (creazione dell'ipset + regola DROP, poi persistenza)..."

T_EN[inst.done_header]=" Installation complete."
T_FR[inst.done_header]=" Installation terminee."
T_DE[inst.done_header]=" Installation abgeschlossen."
T_ES[inst.done_header]=" Instalación completada."
T_IT[inst.done_header]=" Installazione completata."

T_EN[inst.done_script]="   Script              : %s  (fetched from REPO_RAW)"
T_FR[inst.done_script]="   Script              : %s  (recupere depuis REPO_RAW)"
T_DE[inst.done_script]="   Skript              : %s  (von REPO_RAW abgerufen)"
T_ES[inst.done_script]="   Script              : %s  (recuperado desde REPO_RAW)"
T_IT[inst.done_script]="   Script              : %s  (recuperato da REPO_RAW)"

T_EN[inst.done_cron]="   Cron (hourly)       : %s   -> logs to %s"
T_FR[inst.done_cron]="   Cron (horaire)      : %s   -> log dans %s"
T_DE[inst.done_cron]="   Cron (stündlich)    : %s   -> Log in %s"
T_ES[inst.done_cron]="   Cron (cada hora)    : %s   -> registro en %s"
T_IT[inst.done_cron]="   Cron (orario)       : %s   -> log in %s"

T_EN[inst.done_updater]="   Self-updater        : %s (cron.daily) — updates the engine AND itself"
T_FR[inst.done_updater]="   Self-updater        : %s (cron.daily) — met a jour le moteur ET lui-meme"
T_DE[inst.done_updater]="   Self-Updater        : %s (cron.daily) — aktualisiert die Engine UND sich selbst"
T_ES[inst.done_updater]="   Auto-actualizador   : %s (cron.daily) — actualiza el motor Y a sí mismo"
T_IT[inst.done_updater]="   Self-updater        : %s (cron.daily) — aggiorna il motore E sé stesso"

T_EN[inst.done_persist]="   Reboot persistence  : /etc/iptables/ipsets + /etc/iptables/rules.v4"
T_FR[inst.done_persist]="   Persistance reboot  : /etc/iptables/ipsets + /etc/iptables/rules.v4"
T_DE[inst.done_persist]="   Reboot-Persistenz   : /etc/iptables/ipsets + /etc/iptables/rules.v4"
T_ES[inst.done_persist]="   Persistencia inicio : /etc/iptables/ipsets + /etc/iptables/rules.v4"
T_IT[inst.done_persist]="   Persistenza riavvio : /etc/iptables/ipsets + /etc/iptables/rules.v4"

T_EN[inst.done_nodep]="   No external runtime dependency (FCrDNS via getent / libc)"
T_FR[inst.done_nodep]="   Aucune dependance externe au runtime (FCrDNS via getent / libc)"
T_DE[inst.done_nodep]="   Keine externe Laufzeitabhängigkeit (FCrDNS via getent / libc)"
T_ES[inst.done_nodep]="   Sin dependencia externa en ejecución (FCrDNS vía getent / libc)"
T_IT[inst.done_nodep]="   Nessuna dipendenza esterna a runtime (FCrDNS via getent / libc)"

T_EN[inst.done_test]=" Test without changing anything:"
T_FR[inst.done_test]=" Tester sans rien modifier :"
T_DE[inst.done_test]=" Testen, ohne etwas zu ändern:"
T_ES[inst.done_test]=" Probar sin modificar nada:"
T_IT[inst.done_test]=" Provare senza modificare nulla:"

T_EN[inst.done_testcmd]="   %s --dry-run --verbose"
T_FR[inst.done_testcmd]="   %s --dry-run --verbose"
T_DE[inst.done_testcmd]="   %s --dry-run --verbose"
T_ES[inst.done_testcmd]="   %s --dry-run --verbose"
T_IT[inst.done_testcmd]="   %s --dry-run --verbose"

# Detection de la langue : locale du shell (ou /etc/default/locale en repli).
detect_lang() {
    local l="${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}"
    if [ -z "$l" ] && [ -r /etc/default/locale ]; then
        l=$(. /etc/default/locale 2>/dev/null; printf '%s' "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}")
    fi
    l="${l%%.*}"; l="${l%%_*}"; l="${l,,}"
    case "$l" in en|fr|de|es|it) printf '%s' "$l" ;; *) printf '%s' en ;; esac
}

# Langue d'affichage : valeur de la conf existante si presente, sinon locale du shell.
BAN404_LANG=""
[ -f "$CONF_PATH" ] && BAN404_LANG=$(grep -m1 '^BAN404_LANG=' "$CONF_PATH" 2>/dev/null | cut -d'"' -f2)
: "${BAN404_LANG:=$(detect_lang)}"
BAN404_LANG="${BAN404_LANG,,}"
case "$BAN404_LANG" in en|fr|de|es|it) ;; *) BAN404_LANG=en ;; esac

# t <cle> [args...] : imprime la traduction (\n du format interpretes) + saut de ligne final.
t() {
    local key="$1"; shift
    local ref="T_${BAN404_LANG^^}[$key]"
    local fmt="${!ref-}"
    [ -z "$fmt" ] && fmt="${T_EN[$key]-}"
    [ -z "$fmt" ] && fmt="$key"
    # '--' : empeche printf d'interpreter un format commencant par '-' comme une option.
    # shellcheck disable=SC2059
    printf -- "$fmt\n" "$@"
}

die(){ printf -- '%s%s\n' "$(t inst.error_prefix)" "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "$(t inst.need_root)"

t inst.pkg_install
export DEBIAN_FRONTEND=noninteractive
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
apt-get update || t inst.apt_update_warn
# curl : requis pour la recuperation initiale du moteur via l'updater (l'install depend du reseau).
install_pkgs(){ apt-get install -y ipset iptables-persistent ipset-persistent cron curl; }
if ! install_pkgs; then
    t inst.universe_try
    command -v add-apt-repository >/dev/null 2>&1 && { add-apt-repository -y universe && apt-get update || true; }
    install_pkgs || die "$(t inst.pkg_fail)"
fi

systemctl enable --now netfilter-persistent >/dev/null 2>&1 || true
mkdir -p /etc/iptables

t inst.migrate_ipset
if [ -L /etc/iptables/ipsets ]; then
    link_target=$(readlink -f /etc/iptables/ipsets 2>/dev/null || true)
    t inst.ipsets_link "${link_target:-<casse>}"
    rm -f /etc/iptables/ipsets
    if [ -n "${link_target:-}" ] && [ -f "$link_target" ]; then
        cp -a "$link_target" /etc/iptables/ipsets
        t inst.ipsets_materialized
    fi
fi
if [ -f /etc/iptables/ipset ]; then
    rm -f /etc/iptables/ipset
    t inst.old_ipset_removed
fi

t inst.decom
# Un nom evoque-t-il un ancien ban-404 ? (ban+404 dans un sens ou l'autre, insensible casse)
is_legacy_name(){ printf '%s' "$1" | grep -qiE '(ban[_-]?404|404[_-]?ban|autoban404|auto_ban_404)'; }

shopt -s nullglob
for f in /etc/cron.hourly/* /etc/cron.daily/*; do
    base=$(basename "$f")
    [ "$base" = "$CRON_BASE" ] && continue                 # notre nouvelle tache : ne pas toucher
    if [ -L "$f" ]; then
        tgt=$(readlink -f "$f" 2>/dev/null || true)
        if is_legacy_name "$base" || { [ -n "${tgt:-}" ] && is_legacy_name "$(basename "$tgt")"; }; then
            [ -n "${tgt:-}" ] && [ -f "$tgt" ] && [ "$tgt" != "$SCRIPT_PATH" ] && { rm -f "$tgt"; t inst.old_script_removed "$tgt"; }
            rm -f "$f"; t inst.old_cron_link_removed "$f"
        fi
    elif [ -f "$f" ]; then
        ref=$(grep -oE '/[^[:space:]"'\'']*\.sh' "$f" 2>/dev/null | head -n1 || true)
        if is_legacy_name "$base" || { [ -n "${ref:-}" ] && is_legacy_name "$(basename "$ref")"; }; then
            [ -n "${ref:-}" ] && [ -f "$ref" ] && [ "$ref" != "$SCRIPT_PATH" ] && { rm -f "$ref"; t inst.old_script_removed "$ref"; }
            rm -f "$f"; t inst.old_cron_removed "$f"
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
        rm -f "$s"; t inst.old_script_removed "$s"
    done
done

# References dans crontab partage : signalees, pas auto-editees
hits=$(grep -rliE '(ban[_-]?404|404[_-]?ban|auto_ban_404)' /etc/cron.d /etc/crontab /var/spool/cron 2>/dev/null | grep -v "$CRON_BASE" || true)
[ -n "${hits:-}" ] && echo "   /!\\ $(t inst.refs_manual "$hits")"

# Ancienne chaine iptables eventuelle
if iptables -nL AUTOBAN404 >/dev/null 2>&1; then
    iptables -D INPUT -j AUTOBAN404 2>/dev/null || true
    iptables -F AUTOBAN404 2>/dev/null || true
    iptables -X AUTOBAN404 2>/dev/null || true
    t inst.chain_removed
fi
[ -d /var/lib/auto-ban-404 ] && { rm -rf /var/lib/auto-ban-404; t inst.varlib_removed; }

# La config locale doit exister AVANT l'updater (qui y lit REPO_RAW et BAN404_LANG).
t inst.conf_local "$CONF_PATH"
if [ ! -f "$CONF_PATH" ]; then
    cat > "$CONF_PATH" <<EOF
# /etc/ban_404.conf — configuration LOCALE par serveur (NON versionnee).
REPO_RAW="$REPO_RAW"
WHITELIST_IP="127.0.0.1"
# Langue des messages : en (defaut) | fr | de | es | it
BAN404_LANG="$BAN404_LANG"
#WINDOW=7200
#BAN_TIMEOUT=172800
#TAIL_LINES=50000
#BAN_THRESHOLD=10
#HONEYPOT_SCORE=100
#WHITELIST_CIDR="10.0.0.0/8|192.168.0.0/16"
# Notifications (vides => desactivees ; messages dans la langue BAN404_LANG)
#WEBHOOK_URL=""
#NOTIFY_EMAIL=""
#NOTIFY_FROM=""
#NOTIFY_MIN_BANS=1
#DAILY_SUMMARY=false
EOF
    chmod 600 "$CONF_PATH"
    t inst.conf_created
else
    t inst.conf_kept
fi

# Seule copie embarquee restante : l'updater (amorce). A garder synchronise avec
# update_ban_404.sh du depot — voir la doc interne. Le self-update fait converger toute
# divergence des le premier passage cron.
t inst.selfupdater "$UPDATER_PATH" "$UPDATE_CRON"
cat > "$UPDATER_PATH" <<'UPD_EOF'
#!/bin/bash
# update_ban_404.sh — met a jour ban_404.sh ET update_ban_404.sh depuis le depot Git.
# Telecharge -> valide (shebang + syntaxe) -> bascule atomique. Jamais "curl | bash".
# L'updater se met aussi a jour lui-meme (self-update) : plus besoin de repasser sur
# les serveurs pour propager une evolution de l'updater. Il ajoute aussi BAN404_LANG
# a la conf si elle est absente (langue heritee du shell/systeme, sinon en).
set -u

UPDATER_VERSION="1.0.0"
CONF_FILE="/etc/ban_404.conf"
TARGET="/usr/local/sbin/ban_404.sh"
SELF="/usr/local/sbin/update_ban_404.sh"
LOG="/var/log/ban_404.log"

# --- i18n : messages multilingues (en, fr, de, es, it). Voir ban_404.sh pour le mecanisme. ---
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

T_EN[help.help]="  --help, -h       Show this help message."
T_FR[help.help]="  --help, -h       Afficher ce message d'aide."
T_DE[help.help]="  --help, -h       Diese Hilfemeldung anzeigen."
T_ES[help.help]="  --help, -h       Mostrar este mensaje de ayuda."
T_IT[help.help]="  --help, -h       Mostrare questo messaggio di aiuto."

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

# Detection de la langue : locale du shell (ou /etc/default/locale en repli pour cron).
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

# Resolution de la langue : conf > locale du shell > en. Puis validation.
: "${BAN404_LANG:=$(detect_lang)}"
BAN404_LANG="${BAN404_LANG,,}"
case "$BAN404_LANG" in en|fr|de|es|it) ;; *) BAN404_LANG=en ;; esac

# t <cle> [args...] : renvoie la traduction (\n du format interpretes) + saut de ligne final.
t() {
    local key="$1"; shift
    local ref="T_${BAN404_LANG^^}[$key]"
    local fmt="${!ref-}"
    [ -z "$fmt" ] && fmt="${T_EN[$key]-}"
    [ -z "$fmt" ] && fmt="$key"
    # '--' : empeche printf d'interpreter un format commencant par '-' comme une option.
    # shellcheck disable=SC2059
    printf -- "$fmt\n" "$@"
}

show_help() {
    t version.line "$UPDATER_VERSION"
    t help.usage "$0"
    echo ""
    t help.options_header
    t help.version
    t help.help
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) t version.line "$UPDATER_VERSION"; exit 0 ;;
        --help|-h) show_help ;;
        *) t err.unknown_opt "$1"; exit 1 ;;
    esac
done

: "${REPO_RAW:=}"
[ -z "$REPO_RAW" ] && { log "$(t upd.repo_undef "$CONF_FILE")"; exit 0; }

# --- Migration conf : ajoute BAN404_LANG s'il manque (idempotent) ---
if [ -f "$CONF_FILE" ] && ! grep -q '^BAN404_LANG=' "$CONF_FILE"; then
    _dl=$(detect_lang)
    {
        printf '\n# Langue des messages : en (defaut) | fr | de | es | it\n'
        printf 'BAN404_LANG="%s"\n' "$_dl"
    } >> "$CONF_FILE" && log "$(t upd.lang_added "$CONF_FILE" "$_dl")"
fi

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

    tmp=$(download "$url") || { log "$(t upd.dl_fail "$label" "$url")"; return 2; }

    # Validations avant toute bascule
    [ -s "$tmp" ] || { log "$(t upd.empty "$label")"; rm -f "$tmp"; return 2; }
    head -n1 "$tmp" | grep -q '^#!/bin/bash' || { log "$(t upd.shebang "$label")"; rm -f "$tmp"; return 2; }
    bash -n "$tmp" 2>/dev/null || { log "$(t upd.syntax "$label")"; rm -f "$tmp"; return 2; }

    # Deja a jour ?
    if [ -f "$target" ] && cmp -s "$tmp" "$target"; then rm -f "$tmp"; return 1; fi

    # Bascule atomique (copie dans le meme repertoire que la cible puis mv), avec sauvegarde
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

# Cron de resume quotidien (no-op tant que DAILY_SUMMARY != true et aucun canal configure).
t inst.summary_cron "$SUMMARY_CRON"
cat > "$SUMMARY_CRON" <<EOF
#!/bin/sh
exec $SCRIPT_PATH --summary
EOF
chmod 755 "$SUMMARY_CRON"

# Recuperation initiale du moteur : on delegue a l'updater (source unique de verite).
t inst.fetch_engine "$SCRIPT_PATH"
"$UPDATER_PATH" || true
[ -s "$SCRIPT_PATH" ] || die "$(t inst.fetch_fail "$SCRIPT_PATH" "$REPO_RAW" "$CONF_PATH" "$LOG_PATH")"

t inst.cron_hourly "$CRON_PATH"
cat > "$CRON_PATH" <<EOF
#!/bin/sh
# Horodate chaque ligne de sortie du script avant de l'ecrire dans le log.
$SCRIPT_PATH 2>&1 | while IFS= read -r line; do
    printf '%s %s\n' "\$(date '+%Y-%m-%d %H:%M:%S')" "\$line"
done >> $LOG_PATH
EOF
chmod 755 "$CRON_PATH"

t inst.logrotate "$LOGROTATE_PATH"
cat > "$LOGROTATE_PATH" <<EOF
$LOG_PATH {
    weekly
    rotate 8
    compress
    missingok
    notifempty
}
EOF

t inst.activate
modprobe ip_set 2>/dev/null || true
# Recharger d'eventuels bans deja persistes (migration / reinstall) AVANT de re-sauvegarder
[ -s /etc/iptables/ipsets ] && ipset restore -exist < /etc/iptables/ipsets 2>/dev/null || true
"$SCRIPT_PATH" || true
netfilter-persistent save >/dev/null 2>&1 || true

echo ""
echo "------------------------------------------------------------"
t inst.done_header
t inst.done_script "$SCRIPT_PATH"
t inst.done_cron "$CRON_PATH" "$LOG_PATH"
t inst.done_updater "$UPDATER_PATH"
t inst.done_persist
t inst.done_nodep
echo ""
t inst.done_test
t inst.done_testcmd "$SCRIPT_PATH"
echo "------------------------------------------------------------"
