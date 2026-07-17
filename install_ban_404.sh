#!/bin/bash
# ============================================================================
#  install_ban_404.sh — Installation "clé en main" du ban automatique sur
#  flood de 404 (ipset + iptables, persistance au reboot, exécution horaire).
#  Idempotent. Migre l'ancien chemin /etc/iptables/ipset et décommissionne
#  tout ancien script de ban 404 (quel que soit son nom).
#
#  Le moteur ban_404.sh n'est PAS embarqué ici : il est récupéré depuis le
#  dépôt par le self-updater (source unique de vérité). Seul l'updater est
#  embarqué (heredoc UPD_EOF) — amorce incontournable, puis il se met à jour
#  lui-même. L'installation requiert donc un accès réseau à REPO_RAW.
# ============================================================================
set -u

SCRIPT_PATH="/usr/local/sbin/ban_404.sh"
CRON_PATH="/etc/cron.hourly/ban_404"        # SANS extension : run-parts ignore les noms contenant '.'
CRON_BASE="ban_404"
LOG_PATH="/var/log/ban_404.log"
LOGROTATE_PATH="/etc/logrotate.d/ban_404"
UPDATER_PATH="/usr/local/sbin/update_ban_404.sh"
CONF_PATH="/etc/ban_404.conf"
UPDATE_CRON="/etc/cron.daily/0_ban_404_update"

# >>> À ÉDITER UNE FOIS avant distribution : URL "raw" de ton dépôt (sans slash final) <<<
REPO_RAW="https://raw.githubusercontent.com/Pixels-Ing/ban-404/main"

# --- i18n : messages multilingues (en, fr, de, es, it). Voir ban_404.sh pour le mécanisme. ---
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

T_EN[inst.pkg_install]="==> Checking required packages..."
T_FR[inst.pkg_install]="==> Vérification des paquets requis..."
T_DE[inst.pkg_install]="==> Erforderliche Pakete werden geprüft..."
T_ES[inst.pkg_install]="==> Verificando los paquetes necesarios..."
T_IT[inst.pkg_install]="==> Verifica dei pacchetti richiesti..."

T_EN[inst.incompatible]="unsupported system: this installer targets Debian/Ubuntu with apt (detected: %s). Aborting."
T_FR[inst.incompatible]="système non pris en charge : cet installeur cible Debian/Ubuntu avec apt (détecté : %s). Arrêt."
T_DE[inst.incompatible]="nicht unterstütztes System: dieser Installer ist für Debian/Ubuntu mit apt gedacht (erkannt: %s). Abbruch."
T_ES[inst.incompatible]="sistema no compatible: este instalador es para Debian/Ubuntu con apt (detectado: %s). Cancelando."
T_IT[inst.incompatible]="sistema non supportato: questo installer è per Debian/Ubuntu con apt (rilevato: %s). Interruzione."

T_EN[inst.deps_missing]="   Missing required packages: %s"
T_FR[inst.deps_missing]="   Paquets requis manquants : %s"
T_DE[inst.deps_missing]="   Fehlende erforderliche Pakete: %s"
T_ES[inst.deps_missing]="   Paquetes requeridos que faltan: %s"
T_IT[inst.deps_missing]="   Pacchetti richiesti mancanti: %s"

T_EN[inst.deps_prompt]="   Install them now? [y/N] "
T_FR[inst.deps_prompt]="   Les installer maintenant ? [o/N] "
T_DE[inst.deps_prompt]="   Jetzt installieren? [j/N] "
T_ES[inst.deps_prompt]="   ¿Instalarlos ahora? [s/N] "
T_IT[inst.deps_prompt]="   Installarli ora? [s/N] "

T_EN[inst.deps_proceeding]="   Installing the missing packages..."
T_FR[inst.deps_proceeding]="   Installation des paquets manquants..."
T_DE[inst.deps_proceeding]="   Fehlende Pakete werden installiert..."
T_ES[inst.deps_proceeding]="   Instalando los paquetes que faltan..."
T_IT[inst.deps_proceeding]="   Installazione dei pacchetti mancanti..."

T_EN[inst.deps_all_present]="   all required packages are already present."
T_FR[inst.deps_all_present]="   tous les paquets requis sont déjà présents."
T_DE[inst.deps_all_present]="   alle erforderlichen Pakete sind bereits vorhanden."
T_ES[inst.deps_all_present]="   todos los paquetes necesarios ya están presentes."
T_IT[inst.deps_all_present]="   tutti i pacchetti richiesti sono già presenti."

T_EN[inst.deps_aborted]="aborted at your request: required packages not installed (nothing was changed)."
T_FR[inst.deps_aborted]="arrêt à ta demande : paquets requis non installés (rien n'a été modifié)."
T_DE[inst.deps_aborted]="auf deinen Wunsch abgebrochen: erforderliche Pakete nicht installiert (nichts wurde geändert)."
T_ES[inst.deps_aborted]="cancelado a petición tuya: paquetes requeridos no instalados (no se cambió nada)."
T_IT[inst.deps_aborted]="interrotto su tua richiesta: pacchetti richiesti non installati (nulla è stato modificato)."

T_EN[inst.deps_noninteractive]="required packages missing but no TTY to confirm. Re-run with BAN404_ASSUME_YES=1 to allow, or install manually: %s"
T_FR[inst.deps_noninteractive]="paquets requis manquants mais pas de TTY pour confirmer. Relance avec BAN404_ASSUME_YES=1 pour autoriser, ou installe-les à la main : %s"
T_DE[inst.deps_noninteractive]="erforderliche Pakete fehlen, aber kein TTY zum Bestätigen. Mit BAN404_ASSUME_YES=1 erneut starten, um es zu erlauben, oder manuell installieren: %s"
T_ES[inst.deps_noninteractive]="faltan paquetes requeridos pero no hay TTY para confirmar. Reejecuta con BAN404_ASSUME_YES=1 para permitirlo, o instálalos manualmente: %s"
T_IT[inst.deps_noninteractive]="pacchetti richiesti mancanti ma nessun TTY per confermare. Riesegui con BAN404_ASSUME_YES=1 per consentirlo, oppure installali manualmente: %s"

T_EN[inst.postcheck_fail]="post-install check failed: required command '%s' is still missing. Broken package or stale mirror?"
T_FR[inst.postcheck_fail]="contrôle post-installation échoué : la commande requise « %s » reste introuvable. Paquet cassé ou miroir périmé ?"
T_DE[inst.postcheck_fail]="Post-Installations-Prüfung fehlgeschlagen: erforderlicher Befehl „%s“ fehlt weiterhin. Defektes Paket oder veralteter Spiegel?"
T_ES[inst.postcheck_fail]="comprobación posinstalación fallida: el comando requerido « %s » sigue sin encontrarse. ¿Paquete dañado o réplica obsoleta?"
T_IT[inst.postcheck_fail]="controllo post-installazione fallito: il comando richiesto « %s » è ancora assente. Pacchetto danneggiato o mirror obsoleto?"

T_EN[inst.apt_update_warn]="   (apt-get update failed — continuing with the local cache)"
T_FR[inst.apt_update_warn]="   (apt-get update en erreur — on poursuit avec le cache local)"
T_DE[inst.apt_update_warn]="   (apt-get update fehlgeschlagen — Fortsetzung mit dem lokalen Cache)"
T_ES[inst.apt_update_warn]="   (apt-get update con error — se continúa con la caché local)"
T_IT[inst.apt_update_warn]="   (apt-get update non riuscito — si prosegue con la cache locale)"

T_EN[inst.universe_try]="   failed — trying to enable the 'universe' repo (required for ipset-persistent on 22.04)..."
T_FR[inst.universe_try]="   échec — tentative d'activation du dépôt 'universe' (requis pour ipset-persistent sur 22.04)..."
T_DE[inst.universe_try]="   fehlgeschlagen — Versuch, das Repo 'universe' zu aktivieren (erforderlich für ipset-persistent auf 22.04)..."
T_ES[inst.universe_try]="   fallo — intentando activar el repositorio 'universe' (necesario para ipset-persistent en 22.04)..."
T_IT[inst.universe_try]="   errore — tentativo di attivare il repository 'universe' (richiesto per ipset-persistent su 22.04)..."

T_EN[inst.pkg_fail]="package installation failed (is the 'universe' repo enabled?)."
T_FR[inst.pkg_fail]="échec installation paquets (le dépôt 'universe' est-il activé ?)."
T_DE[inst.pkg_fail]="Paketinstallation fehlgeschlagen (ist das Repo 'universe' aktiviert?)."
T_ES[inst.pkg_fail]="fallo en la instalación de paquetes (¿está activado el repositorio 'universe'?)."
T_IT[inst.pkg_fail]="installazione dei pacchetti non riuscita (il repository 'universe' è attivo?)."

T_EN[inst.ufw_detected]="==> ufw is installed: it will be REMOVED by apt (ufw declares Breaks: iptables-persistent/netfilter-persistent)."
T_FR[inst.ufw_detected]="==> ufw est installé : il va être RETIRÉ par apt (ufw déclare Breaks: iptables-persistent/netfilter-persistent)."
T_DE[inst.ufw_detected]="==> ufw ist installiert: es wird von apt ENTFERNT (ufw deklariert Breaks: iptables-persistent/netfilter-persistent)."
T_ES[inst.ufw_detected]="==> ufw está instalado: apt lo VA A ELIMINAR (ufw declara Breaks: iptables-persistent/netfilter-persistent)."
T_IT[inst.ufw_detected]="==> ufw è installato: verrà RIMOSSO da apt (ufw dichiara Breaks: iptables-persistent/netfilter-persistent)."

T_EN[inst.ufw_explain]="   ban-404 uses ipset+iptables and needs iptables-persistent, which recent ufw refuses to coexist with. ban-404 is NOT a firewall: it only adds a DROP rule for its own ipset."
T_FR[inst.ufw_explain]="   ban-404 utilise ipset+iptables et requiert iptables-persistent, avec lequel ufw récent refuse de cohabiter. ban-404 n'est PAS un pare-feu : il n'ajoute qu'une règle DROP pour son propre ipset."
T_DE[inst.ufw_explain]="   ban-404 nutzt ipset+iptables und benötigt iptables-persistent, mit dem aktuelles ufw nicht koexistieren will. ban-404 ist KEINE Firewall: es fügt nur eine DROP-Regel für sein eigenes ipset hinzu."
T_ES[inst.ufw_explain]="   ban-404 usa ipset+iptables y necesita iptables-persistent, con el que ufw reciente se niega a convivir. ban-404 NO es un cortafuegos: solo añade una regla DROP para su propio ipset."
T_IT[inst.ufw_explain]="   ban-404 usa ipset+iptables e richiede iptables-persistent, con cui ufw recente rifiuta di coesistere. ban-404 NON è un firewall: aggiunge solo una regola DROP per il proprio ipset."

T_EN[inst.ufw_backup]="   Current firewall rules saved (iptables/ip6tables + /etc/ufw + ufw status) to: %s"
T_FR[inst.ufw_backup]="   Règles pare-feu en vigueur sauvegardées (iptables/ip6tables + /etc/ufw + ufw status) dans : %s"
T_DE[inst.ufw_backup]="   Aktuelle Firewall-Regeln gesichert (iptables/ip6tables + /etc/ufw + ufw status) nach: %s"
T_ES[inst.ufw_backup]="   Reglas del cortafuegos en vigor guardadas (iptables/ip6tables + /etc/ufw + ufw status) en: %s"
T_IT[inst.ufw_backup]="   Regole firewall in vigore salvate (iptables/ip6tables + /etc/ufw + ufw status) in: %s"

T_EN[inst.ufw_backup_hint]="   Keep this: once ufw is gone its rules are no longer visible via ufw. Re-create any access policy in iptables (persisted via 'netfilter-persistent save') from that folder."
T_FR[inst.ufw_backup_hint]="   À conserver : ufw parti, ses règles ne sont plus visibles via ufw. Reconstitue ta politique d'accès en iptables (persistée via « netfilter-persistent save ») à partir de ce dossier."
T_DE[inst.ufw_backup_hint]="   Aufbewahren: Ist ufw weg, sind seine Regeln nicht mehr über ufw sichtbar. Zugriffsrichtlinie in iptables neu erstellen (persistiert via „netfilter-persistent save“) aus diesem Ordner."
T_ES[inst.ufw_backup_hint]="   Consérvalo: sin ufw, sus reglas ya no se ven con ufw. Recrea tu política de acceso en iptables (persistida con « netfilter-persistent save ») a partir de esa carpeta."
T_IT[inst.ufw_backup_hint]="   Da conservare: senza ufw, le sue regole non sono più visibili via ufw. Ricrea la tua politica d'accesso in iptables (persistita con « netfilter-persistent save ») da quella cartella."

T_EN[inst.ufw_prompt]="   Proceed and let apt remove ufw? [y/N] "
T_FR[inst.ufw_prompt]="   Continuer et laisser apt retirer ufw ? [o/N] "
T_DE[inst.ufw_prompt]="   Fortfahren und apt ufw entfernen lassen? [j/N] "
T_ES[inst.ufw_prompt]="   ¿Continuar y dejar que apt elimine ufw? [s/N] "
T_IT[inst.ufw_prompt]="   Continuare e lasciare che apt rimuova ufw? [s/N] "

T_EN[inst.ufw_aborted]="Aborted: ufw kept, nothing changed (backup retained)."
T_FR[inst.ufw_aborted]="Abandon : ufw conservé, rien n'a été modifié (sauvegarde conservée)."
T_DE[inst.ufw_aborted]="Abbruch: ufw beibehalten, nichts geändert (Sicherung bleibt erhalten)."
T_ES[inst.ufw_aborted]="Cancelado: ufw conservado, nada cambiado (copia de seguridad conservada)."
T_IT[inst.ufw_aborted]="Annullato: ufw mantenuto, nulla è cambiato (backup conservato)."

T_EN[inst.ufw_noninteractive]="ufw would be removed but no TTY to confirm. Re-run with BAN404_REMOVE_UFW=1 to allow it, or 'apt remove ufw' first."
T_FR[inst.ufw_noninteractive]="ufw serait retiré mais pas de TTY pour confirmer. Relance avec BAN404_REMOVE_UFW=1 pour l'autoriser, ou « apt remove ufw » d'abord."
T_DE[inst.ufw_noninteractive]="ufw würde entfernt, aber kein TTY zum Bestätigen. Mit BAN404_REMOVE_UFW=1 erneut starten, um es zu erlauben, oder zuerst „apt remove ufw“."
T_ES[inst.ufw_noninteractive]="ufw se eliminaría pero no hay TTY para confirmar. Reejecuta con BAN404_REMOVE_UFW=1 para permitirlo, o « apt remove ufw » primero."
T_IT[inst.ufw_noninteractive]="ufw verrebbe rimosso ma nessun TTY per confermare. Riesegui con BAN404_REMOVE_UFW=1 per consentirlo, oppure « apt remove ufw » prima."

T_EN[inst.ufw_proceeding]="   Proceeding: ufw will be removed by apt."
T_FR[inst.ufw_proceeding]="   Poursuite : ufw va être retiré par apt."
T_DE[inst.ufw_proceeding]="   Fortsetzung: ufw wird von apt entfernt."
T_ES[inst.ufw_proceeding]="   Continuando: apt eliminará ufw."
T_IT[inst.ufw_proceeding]="   Proseguimento: ufw verrà rimosso da apt."

T_EN[inst.migrate_ipset]="==> Possible migration of the old ipset persistence path..."
T_FR[inst.migrate_ipset]="==> Migration éventuelle de l'ancien chemin de persistance ipset..."
T_DE[inst.migrate_ipset]="==> Mögliche Migration des alten ipset-Persistenzpfads..."
T_ES[inst.migrate_ipset]="==> Posible migración de la antigua ruta de persistencia de ipset..."
T_IT[inst.migrate_ipset]="==> Possibile migrazione del vecchio percorso di persistenza ipset..."

T_EN[inst.ipsets_link]="   /etc/iptables/ipsets is a symlink -> %s"
T_FR[inst.ipsets_link]="   /etc/iptables/ipsets est un lien -> %s"
T_DE[inst.ipsets_link]="   /etc/iptables/ipsets ist ein Symlink -> %s"
T_ES[inst.ipsets_link]="   /etc/iptables/ipsets es un enlace -> %s"
T_IT[inst.ipsets_link]="   /etc/iptables/ipsets è un collegamento -> %s"

T_EN[inst.ipsets_materialized]="   content materialized into a real file /etc/iptables/ipsets"
T_FR[inst.ipsets_materialized]="   contenu matérialisé dans un vrai fichier /etc/iptables/ipsets"
T_DE[inst.ipsets_materialized]="   Inhalt in eine echte Datei /etc/iptables/ipsets überführt"
T_ES[inst.ipsets_materialized]="   contenido materializado en un archivo real /etc/iptables/ipsets"
T_IT[inst.ipsets_materialized]="   contenuto materializzato in un vero file /etc/iptables/ipsets"

T_EN[inst.old_ipset_removed]="   old /etc/iptables/ipset removed"
T_FR[inst.old_ipset_removed]="   ancien /etc/iptables/ipset supprimé"
T_DE[inst.old_ipset_removed]="   altes /etc/iptables/ipset entfernt"
T_ES[inst.old_ipset_removed]="   antiguo /etc/iptables/ipset eliminado"
T_IT[inst.old_ipset_removed]="   vecchio /etc/iptables/ipset rimosso"

T_EN[inst.decom]="==> Decommissioning any old ban 404 script..."
T_FR[inst.decom]="==> Décommissionnement de tout ancien script de ban 404..."
T_DE[inst.decom]="==> Außerbetriebnahme aller alten Ban-404-Skripte..."
T_ES[inst.decom]="==> Retirada de cualquier antiguo script de ban 404..."
T_IT[inst.decom]="==> Dismissione di ogni vecchio script di ban 404..."

T_EN[inst.old_script_removed]="   old script removed: %s"
T_FR[inst.old_script_removed]="   ancien script supprimé : %s"
T_DE[inst.old_script_removed]="   altes Skript entfernt: %s"
T_ES[inst.old_script_removed]="   antiguo script eliminado: %s"
T_IT[inst.old_script_removed]="   vecchio script rimosso: %s"

T_EN[inst.old_cron_link_removed]="   old cron (symlink) removed: %s"
T_FR[inst.old_cron_link_removed]="   ancien cron (lien) supprimé : %s"
T_DE[inst.old_cron_link_removed]="   alter Cron (Symlink) entfernt: %s"
T_ES[inst.old_cron_link_removed]="   antiguo cron (enlace) eliminado: %s"
T_IT[inst.old_cron_link_removed]="   vecchio cron (collegamento) rimosso: %s"

T_EN[inst.old_cron_removed]="   old cron removed: %s"
T_FR[inst.old_cron_removed]="   ancien cron supprimé : %s"
T_DE[inst.old_cron_removed]="   alter Cron entfernt: %s"
T_ES[inst.old_cron_removed]="   antiguo cron eliminado: %s"
T_IT[inst.old_cron_removed]="   vecchio cron rimosso: %s"

T_EN[inst.refs_manual]="References to check/remove manually: %s"
T_FR[inst.refs_manual]="Références à vérifier/retirer manuellement : %s"
T_DE[inst.refs_manual]="Referenzen, die manuell zu prüfen/entfernen sind: %s"
T_ES[inst.refs_manual]="Referencias a verificar/eliminar manualmente: %s"
T_IT[inst.refs_manual]="Riferimenti da verificare/rimuovere manualmente: %s"

T_EN[inst.chain_removed]="   AUTOBAN404 chain dismantled"
T_FR[inst.chain_removed]="   chaîne AUTOBAN404 démontée"
T_DE[inst.chain_removed]="   Kette AUTOBAN404 abgebaut"
T_ES[inst.chain_removed]="   cadena AUTOBAN404 desmontada"
T_IT[inst.chain_removed]="   catena AUTOBAN404 smontata"

T_EN[inst.varlib_removed]="   /var/lib/auto-ban-404 removed"
T_FR[inst.varlib_removed]="   /var/lib/auto-ban-404 supprimé"
T_DE[inst.varlib_removed]="   /var/lib/auto-ban-404 entfernt"
T_ES[inst.varlib_removed]="   /var/lib/auto-ban-404 eliminado"
T_IT[inst.varlib_removed]="   /var/lib/auto-ban-404 rimosso"

T_EN[inst.conf_local]="==> Local configuration: %s"
T_FR[inst.conf_local]="==> Configuration locale : %s"
T_DE[inst.conf_local]="==> Lokale Konfiguration: %s"
T_ES[inst.conf_local]="==> Configuración local: %s"
T_IT[inst.conf_local]="==> Configurazione locale: %s"

T_EN[inst.conf_created]="   created (remember to adjust WHITELIST_IP on this server)"
T_FR[inst.conf_created]="   créé (pense à adapter WHITELIST_IP sur ce serveur)"
T_DE[inst.conf_created]="   erstellt (denken Sie daran, WHITELIST_IP auf diesem Server anzupassen)"
T_ES[inst.conf_created]="   creado (recuerde adaptar WHITELIST_IP en este servidor)"
T_IT[inst.conf_created]="   creato (ricordarsi di adattare WHITELIST_IP su questo server)"

T_EN[inst.conf_kept]="   existing one kept (not overwritten)"
T_FR[inst.conf_kept]="   existant conservé (non écrasé)"
T_DE[inst.conf_kept]="   vorhandene beibehalten (nicht überschrieben)"
T_ES[inst.conf_kept]="   se conserva el existente (no sobrescrito)"
T_IT[inst.conf_kept]="   esistente conservato (non sovrascritto)"

T_EN[inst.wl_self]="   server IP (%s) added to WHITELIST_IP (a server must never ban itself)"
T_FR[inst.wl_self]="   IP du serveur (%s) ajoutée à WHITELIST_IP (un serveur ne doit jamais s'auto-bannir)"
T_DE[inst.wl_self]="   Server-IP (%s) zu WHITELIST_IP hinzugefügt (ein Server darf sich nie selbst sperren)"
T_ES[inst.wl_self]="   IP del servidor (%s) añadida a WHITELIST_IP (un servidor nunca debe bloquearse a sí mismo)"
T_IT[inst.wl_self]="   IP del server (%s) aggiunto a WHITELIST_IP (un server non deve mai bloccare sé stesso)"

T_EN[inst.selfupdater]="==> Self-updater: %s (+ %s)"
T_FR[inst.selfupdater]="==> Self-updater : %s (+ %s)"
T_DE[inst.selfupdater]="==> Self-Updater: %s (+ %s)"
T_ES[inst.selfupdater]="==> Auto-actualizador: %s (+ %s)"
T_IT[inst.selfupdater]="==> Self-updater: %s (+ %s)"


T_EN[inst.fetch_engine]="==> Initial fetch of the engine via the updater: %s"
T_FR[inst.fetch_engine]="==> Récupération initiale du moteur via l'updater : %s"
T_DE[inst.fetch_engine]="==> Erstes Abrufen der Engine über den Updater: %s"
T_ES[inst.fetch_engine]="==> Recuperación inicial del motor mediante el actualizador: %s"
T_IT[inst.fetch_engine]="==> Recupero iniziale del motore tramite l'updater: %s"

T_EN[inst.fetch_fail]="cannot fetch %s from %s. Check network access and REPO_RAW in %s (see %s; nothing installed for the engine)."
T_FR[inst.fetch_fail]="impossible de récupérer %s depuis %s. Vérifie l'accès réseau et REPO_RAW dans %s (voir %s ; rien d'installé pour le moteur)."
T_DE[inst.fetch_fail]="%s kann nicht von %s abgerufen werden. Prüfen Sie den Netzwerkzugang und REPO_RAW in %s (siehe %s; nichts für die Engine installiert)."
T_ES[inst.fetch_fail]="no se puede recuperar %s desde %s. Verifique el acceso de red y REPO_RAW en %s (consulte %s; no se instaló nada para el motor)."
T_IT[inst.fetch_fail]="impossibile recuperare %s da %s. Verificare l'accesso di rete e REPO_RAW in %s (vedere %s; nulla installato per il motore)."

T_EN[inst.cron_hourly]="==> Hourly task: %s"
T_FR[inst.cron_hourly]="==> Tâche horaire : %s"
T_DE[inst.cron_hourly]="==> Stündliche Aufgabe: %s"
T_ES[inst.cron_hourly]="==> Tarea horaria: %s"
T_IT[inst.cron_hourly]="==> Attività oraria: %s"

T_EN[inst.logrotate]="==> Log rotation: %s"
T_FR[inst.logrotate]="==> Rotation du log : %s"
T_DE[inst.logrotate]="==> Log-Rotation: %s"
T_ES[inst.logrotate]="==> Rotación del registro: %s"
T_IT[inst.logrotate]="==> Rotazione del log: %s"

T_EN[inst.activate]="==> Immediate activation (creating the ipset + DROP rule, then persistence)..."
T_FR[inst.activate]="==> Activation immédiate (création de l'ipset + règle DROP, puis persistance)..."
T_DE[inst.activate]="==> Sofortige Aktivierung (Erstellung des ipset + DROP-Regel, dann Persistenz)..."
T_ES[inst.activate]="==> Activación inmediata (creación del ipset + regla DROP, luego persistencia)..."
T_IT[inst.activate]="==> Attivazione immediata (creazione dell'ipset + regola DROP, poi persistenza)..."

T_EN[inst.done_header]=" Installation complete."
T_FR[inst.done_header]=" Installation terminée."
T_DE[inst.done_header]=" Installation abgeschlossen."
T_ES[inst.done_header]=" Instalación completada."
T_IT[inst.done_header]=" Installazione completata."

T_EN[inst.done_script]="   Script              : %s  (fetched from REPO_RAW)"
T_FR[inst.done_script]="   Script              : %s  (récupéré depuis REPO_RAW)"
T_DE[inst.done_script]="   Skript              : %s  (von REPO_RAW abgerufen)"
T_ES[inst.done_script]="   Script              : %s  (recuperado desde REPO_RAW)"
T_IT[inst.done_script]="   Script              : %s  (recuperato da REPO_RAW)"

T_EN[inst.done_cron]="   Cron (hourly)       : %s   -> logs to %s"
T_FR[inst.done_cron]="   Cron (horaire)      : %s   -> log dans %s"
T_DE[inst.done_cron]="   Cron (stündlich)    : %s   -> Log in %s"
T_ES[inst.done_cron]="   Cron (cada hora)    : %s   -> registro en %s"
T_IT[inst.done_cron]="   Cron (orario)       : %s   -> log in %s"

T_EN[inst.done_updater]="   Self-updater        : %s (cron.daily) — updates the engine AND itself"
T_FR[inst.done_updater]="   Self-updater        : %s (cron.daily) — met à jour le moteur ET lui-même"
T_DE[inst.done_updater]="   Self-Updater        : %s (cron.daily) — aktualisiert die Engine UND sich selbst"
T_ES[inst.done_updater]="   Auto-actualizador   : %s (cron.daily) — actualiza el motor Y a sí mismo"
T_IT[inst.done_updater]="   Self-updater        : %s (cron.daily) — aggiorna il motore E sé stesso"

T_EN[inst.done_persist]="   Reboot persistence  : /etc/iptables/ipsets + /etc/iptables/rules.v4"
T_FR[inst.done_persist]="   Persistance reboot  : /etc/iptables/ipsets + /etc/iptables/rules.v4"
T_DE[inst.done_persist]="   Reboot-Persistenz   : /etc/iptables/ipsets + /etc/iptables/rules.v4"
T_ES[inst.done_persist]="   Persistencia inicio : /etc/iptables/ipsets + /etc/iptables/rules.v4"
T_IT[inst.done_persist]="   Persistenza riavvio : /etc/iptables/ipsets + /etc/iptables/rules.v4"

T_EN[inst.done_nodep]="   No external runtime dependency (FCrDNS via getent / libc)"
T_FR[inst.done_nodep]="   Aucune dépendance externe au runtime (FCrDNS via getent / libc)"
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

# Détection de la langue : locale du shell (ou /etc/default/locale en repli).
detect_lang() {
    local l="${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}"
    if [ -z "$l" ] && [ -r /etc/default/locale ]; then
        l=$(. /etc/default/locale 2>/dev/null; printf '%s' "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}")
    fi
    l="${l%%.*}"; l="${l%%_*}"; l="${l,,}"
    case "$l" in en|fr|de|es|it) printf '%s' "$l" ;; *) printf '%s' en ;; esac
}

# Langue d'affichage : valeur de la conf existante si présente, sinon locale du shell.
BAN404_LANG=""
[ -f "$CONF_PATH" ] && BAN404_LANG=$(grep -m1 '^BAN404_LANG=' "$CONF_PATH" 2>/dev/null | cut -d'"' -f2)
: "${BAN404_LANG:=$(detect_lang)}"
BAN404_LANG="${BAN404_LANG,,}"
case "$BAN404_LANG" in en|fr|de|es|it) ;; *) BAN404_LANG=en ;; esac

# t <clé> [args...] : imprime la traduction (\n du format interprétés) + saut de ligne final.
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

die(){ printf -- '%s%s\n' "$(t inst.error_prefix)" "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "$(t inst.need_root)"

# --- 0) Cadre compatible : famille Debian/Ubuntu + apt. Sinon message clair et ARRÊT : on
#     n'installe rien à l'aveugle sur un système qu'on ne sait pas gérer (gestionnaire de paquets
#     différent, pas d'iptables-persistent, etc.). Un /etc/os-release absent => non compatible.
_osid=""; . /etc/os-release 2>/dev/null && _osid="${PRETTY_NAME:-${ID:-}}"
case " ${ID:-} ${ID_LIKE:-} " in
    *debian*|*ubuntu*) : ;;
    *) die "$(t inst.incompatible "${_osid:-inconnu}")" ;;
esac
command -v apt-get >/dev/null 2>&1 || die "$(t inst.incompatible "${_osid:-apt absent}")"

# --- ufw : sur les versions récentes (Debian 12+, Ubuntu récentes) ufw déclare
# « Breaks: iptables-persistent, netfilter-persistent » ; installer iptables-persistent
# le fait donc RETIRER par apt — silencieusement avec -y. On prévient AVANT et on
# SAUVEGARDE les règles en vigueur : ufw parti, elles ne sont plus consultables via ufw.
# Détection sur paquet *installé* (le Breaks ne dépend pas de l'état actif/inactif).
if dpkg-query -W -f='${Status}' ufw 2>/dev/null | grep -q 'ok installed'; then
    t inst.ufw_detected
    t inst.ufw_explain
    ufw_backup="/var/lib/ban_404/ufw-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$ufw_backup"
    iptables-save  > "$ufw_backup/iptables.rules"  2>/dev/null || true
    ip6tables-save > "$ufw_backup/ip6tables.rules" 2>/dev/null || true
    command -v ufw >/dev/null 2>&1 && ufw status verbose > "$ufw_backup/ufw-status.txt" 2>/dev/null || true
    [ -d /etc/ufw ] && cp -a /etc/ufw "$ufw_backup/etc-ufw" 2>/dev/null || true
    [ -f /etc/default/ufw ] && cp -a /etc/default/ufw "$ufw_backup/default-ufw" 2>/dev/null || true
    t inst.ufw_backup "$ufw_backup"
    t inst.ufw_backup_hint
    if [ -t 0 ]; then
        printf -- '%s' "$(t inst.ufw_prompt)"
        read -r _ufw_ans || _ufw_ans=""
        case "$_ufw_ans" in
            [oOyYjJsS]*) t inst.ufw_proceeding ;;
            *) t inst.ufw_aborted; exit 0 ;;
        esac
    elif [ "${BAN404_REMOVE_UFW:-}" = "1" ]; then
        t inst.ufw_proceeding
    else
        die "$(t inst.ufw_noninteractive)"
    fi
fi

t inst.pkg_install
# 1) Lister les paquets REQUIS (moteur + updater) qui MANQUENT. awk (via mawk) : central au parsing,
#    quasi toujours présent mais on vérifie. curl : récupération initiale du moteur par l'updater.
#    anacron : /etc/crontab délègue cron.daily à anacron ; sans lui, le cron.daily de l'updater peut
#    ne jamais partir et le serveur fige ses versions (cf. --diag, pilote cron.daily). bash-completion :
#    chargement à la demande de la complétion Tab (le fichier est déposé par l'updater, plus bas).
_req_pkgs="ipset iptables-persistent ipset-persistent cron anacron curl bash-completion"
command -v awk >/dev/null 2>&1 || _req_pkgs="mawk $_req_pkgs"
_missing=""
for _p in $_req_pkgs; do
    dpkg-query -W -f='${Status}' "$_p" 2>/dev/null | grep -q 'ok installed' || _missing="$_missing $_p"
done
_missing="${_missing# }"

if [ -n "$_missing" ]; then
    # 2) Lister + DEMANDER l'autorisation. 3) Refus => ARRÊT. Sans TTY : refus par défaut, sauf
    #    override explicite BAN404_ASSUME_YES=1 (même logique que BAN404_REMOVE_UFW pour ufw).
    t inst.deps_missing "$_missing"
    if [ -t 0 ]; then
        printf -- '%s' "$(t inst.deps_prompt)"
        read -r _dep_ans || _dep_ans=""
        case "$_dep_ans" in
            [oOyYjJsS]*) t inst.deps_proceeding ;;
            *) die "$(t inst.deps_aborted)" ;;
        esac
    elif [ "${BAN404_ASSUME_YES:-}" = "1" ]; then
        t inst.deps_proceeding
    else
        die "$(t inst.deps_noninteractive "$_missing")"
    fi

    export DEBIAN_FRONTEND=noninteractive
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
    apt-get update || t inst.apt_update_warn
    install_pkgs(){ apt-get install -y $_missing; }
    if ! install_pkgs; then
        t inst.universe_try
        command -v add-apt-repository >/dev/null 2>&1 && { add-apt-repository -y universe && apt-get update || true; }
        install_pkgs || die "$(t inst.pkg_fail)"
    fi
else
    t inst.deps_all_present
fi

# Contrôle POST-INSTALL : ne pas se fier au seul rc d'apt. On vérifie que les binaires ESSENTIELS
# sont réellement là — un paquet « installé » mais binaire absent (miroir cassé, paquet transitionnel
# vide) casserait ban-404 en SILENCE au premier run cron. netfilter-persistent = persistance reboot.
for _bin in ipset iptables curl awk netfilter-persistent; do
    command -v "$_bin" >/dev/null 2>&1 || die "$(t inst.postcheck_fail "$_bin")"
done

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
# Un nom évoque-t-il un ancien ban-404 ? (ban+404 dans un sens ou l'autre, insensible casse)
is_legacy_name(){ printf '%s' "$1" | grep -qiE '(ban[_-]?404|404[_-]?ban|autoban404|auto_ban_404)'; }

shopt -s nullglob
for f in /etc/cron.hourly/* /etc/cron.daily/*; do
    base=$(basename "$f")
    [ "$base" = "$CRON_BASE" ] && continue                 # notre nouvelle tâche : ne pas toucher
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

# Copies orphelines dans les emplacements habituels (sauf nos propres scripts, réécrits ensuite)
for d in /root /usr/local/bin /usr/local/sbin; do
    [ -d "$d" ] || continue
    find "$d" -maxdepth 1 -type f -regextype posix-extended \
        -iregex '.*(ban[_-]?404|404[_-]?ban|auto_ban_404).*\.sh' 2>/dev/null | while read -r s; do
        [ "$s" = "$SCRIPT_PATH" ] && continue
        [ "$s" = "$UPDATER_PATH" ] && continue
        rm -f "$s"; t inst.old_script_removed "$s"
    done
done

# Références dans crontab partagé : signalées, pas auto-éditées
hits=$(grep -rliE '(ban[_-]?404|404[_-]?ban|auto_ban_404)' /etc/cron.d /etc/crontab /var/spool/cron 2>/dev/null | grep -v "$CRON_BASE" || true)
[ -n "${hits:-}" ] && echo "   /!\\ $(t inst.refs_manual "$hits")"

# Ancienne chaîne iptables éventuelle
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
# /etc/ban_404.conf — configuration LOCALE par serveur (NON versionnée).
# Structure complète (commentaires en 5 langues + réglages) posée par l'updater au 1er passage.
REPO_RAW="$REPO_RAW"
WHITELIST_IP="127.0.0.1"
#BAN404_LANG="$BAN404_LANG"
EOF
    chmod 600 "$CONF_PATH"
    t inst.conf_created
else
    t inst.conf_kept
fi

# IP du serveur lui-même : whitelistée d'office (un serveur ne doit jamais s'auto-bannir —
# healthchecks, wget internes… peuvent générer des 404 en rafale). Détection PUREMENT LOCALE
# (adresse source de la route par défaut ; aucun appel à un service externe). Idempotent, et
# n'écrase rien : on PRÉFIXE la valeur existante de WHITELIST_IP (conf neuve comme conservée).
# Les IP d'AUTRES serveurs d'un parc relèvent de la conf locale, jamais de ce script (dépôt
# public : n'y publier ni la cartographie d'un parc, ni une immunité croisée exploitable).
srv_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
if [ -n "$srv_ip" ]; then
    esc=$(printf '%s' "$srv_ip" | sed 's/\./\\./g')
    if ! grep -qE "^WHITELIST_IP=" "$CONF_PATH"; then
        printf 'WHITELIST_IP="%s|127.0.0.1"\n' "$srv_ip" >> "$CONF_PATH"
        t inst.wl_self "$srv_ip"
    elif ! grep -qE "^WHITELIST_IP=.*(\"|\|)${esc}(\"|\|)" "$CONF_PATH"; then
        sed -i "s#^WHITELIST_IP=\"#WHITELIST_IP=\"${srv_ip}|#" "$CONF_PATH"
        t inst.wl_self "$srv_ip"
    fi
fi

# Seule copie embarquée restante : l'updater (amorce). À garder synchronisé avec
# update_ban_404.sh du dépôt — voir la doc interne. Le self-update fait converger toute
# divergence dès le premier passage cron.
t inst.selfupdater "$UPDATER_PATH" "$UPDATE_CRON"
cat > "$UPDATER_PATH" <<'UPD_EOF'
#!/bin/bash
# update_ban_404.sh — met à jour ban_404.sh ET update_ban_404.sh depuis le dépôt Git.
# Télécharge -> valide (shebang + syntaxe) -> bascule atomique. Jamais "curl | bash".
# L'updater se met aussi à jour lui-même (self-update) : plus besoin de repasser sur
# les serveurs pour propager une évolution de l'updater. Il ajoute aussi BAN404_LANG
# à la conf si elle est absente (langue héritée du shell/système, sinon en).
set -u

UPDATER_VERSION="1.3.0"
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

T_EN[upd.cron_renamed]="Daily cron renamed to %s (updater now runs before the daily summary)."
T_FR[upd.cron_renamed]="Cron quotidien renommé en %s (l'updater passe désormais avant le résumé quotidien)."
T_DE[upd.cron_renamed]="Täglicher Cron umbenannt in %s (der Updater läuft nun vor der täglichen Zusammenfassung)."
T_ES[upd.cron_renamed]="Cron diario renombrado a %s (el updater ahora se ejecuta antes del resumen diario)."
T_IT[upd.cron_renamed]="Cron giornaliero rinominato in %s (l'updater ora viene eseguito prima del riepilogo giornaliero)."

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

# Sourcing sous set +u : une conf locale peut ÉTENDRE une variable du moteur que
# l'updater ne prédéfinit pas (pattern d'append recommandé, ex.
# NOISE_PATTERN="${NOISE_PATTERN}|^/api/push/" pour un serveur de monitoring) ; sous
# set -u, ce ${NOISE_PATTERN} non défini serait un « unbound variable » FATAL qui tue
# l'updater avant tout contrôle réseau — or il ne se sert d'aucun de ces réglages.
set +u
[ -f "$CONF_FILE" ] && . "$CONF_FILE"
set -u

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

# --- Migration cron : ban_404_update -> 0_ban_404_update (ordre run-parts) ---------------------
# run-parts exécute cron.daily en ordre lexicographique : « ban_404_summary » passait AVANT
# « ban_404_update », le résumé quotidien partait donc avec les versions de la veille (faux
# [WARN] « MAJ dispo »). Le préfixe « 0_ » place l'updater en tête ; le moteur renomme de son
# côté le cron résumé en « 1_ban_404_summary » (self_heal_summary_cron). One-shot, idempotent
# (un simple mv : le contenu — exec de $SELF — ne change pas).
if [ -f /etc/cron.daily/ban_404_update ]; then
    if [ ! -e /etc/cron.daily/0_ban_404_update ]; then
        mv -f /etc/cron.daily/ban_404_update /etc/cron.daily/0_ban_404_update 2>/dev/null \
            && log "$(t upd.cron_renamed /etc/cron.daily/0_ban_404_update)"
    else
        rm -f /etc/cron.daily/ban_404_update 2>/dev/null
    fi
fi

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
C_H_health=(
"# --- Server vital signs (shown by diag/health and the daily summary; WARN thresholds) ---"
"# --- Signes vitaux du serveur (affichés par diag/health et le résumé quotidien ; seuils de WARN) ---"
"# --- Vitalwerte des Servers (angezeigt von diag/health und der täglichen Zusammenfassung; WARN-Schwellen) ---"
"# --- Constantes vitales del servidor (mostradas por diag/health y el resumen diario; umbrales de WARN) ---"
"# --- Segni vitali del server (mostrati da diag/health e dal riepilogo giornaliero; soglie di WARN) ---")
C_OTHER=(
"# --- Other active settings preserved as-is ---"
"# --- Autres réglages actifs conservés tels quels ---"
"# --- Sonstige aktive Einstellungen unverändert beibehalten ---"
"# --- Otros ajustes activos conservados tal cual ---"
"# --- Altre impostazioni attive conservate così come sono ---")
C_SEC=(opt cidr vhosts notif health motifs)
C_opt_v=( $'WINDOW\t#WINDOW=7200' $'BAN_TIMEOUT\t#BAN_TIMEOUT=172800' $'TAIL_LINES\t#TAIL_LINES=50000' $'BAN_THRESHOLD\t#BAN_THRESHOLD=10' $'HONEYPOT_SCORE\t#HONEYPOT_SCORE=100' $'HONEYPOT_BAN_TIMEOUT\t#HONEYPOT_BAN_TIMEOUT=604800' $'POST_FLOOD_THRESHOLD\t#POST_FLOOD_THRESHOLD=20' $'RESOLVE_PTR\t#RESOLVE_PTR=false' $'PTR_TIMEOUT\t#PTR_TIMEOUT=2' $'CRON_STEP\t#CRON_STEP=""' )
C_cidr_v=( $'WHITELIST_CIDR\t#WHITELIST_CIDR="10.0.0.0/8|192.168.0.0/16"' )
C_vhosts_v=( $'EXCLUDE_VHOSTS\t#EXCLUDE_VHOSTS="staging.exemple.com|interne.exemple.com"' )
C_notif_v=( $'SERVER_NICKNAME\t#SERVER_NICKNAME=""' $'WEBHOOK_URL\t#WEBHOOK_URL=""' $'NOTIFY_EMAIL\t#NOTIFY_EMAIL=""' $'NOTIFY_FROM\t#NOTIFY_FROM=""' $'NOTIFY_MIN_BANS\t#NOTIFY_MIN_BANS=1' $'NOTIFY_BANS\t#NOTIFY_BANS=false' $'DAILY_SUMMARY\t#DAILY_SUMMARY=false' )
C_health_v=( $'HEALTH_CHECKS\t#HEALTH_CHECKS=true' $'HEALTH_LOAD_WARN\t#HEALTH_LOAD_WARN=2' $'HEALTH_MEM_WARN\t#HEALTH_MEM_WARN=10' $'HEALTH_DISK_WARN\t#HEALTH_DISK_WARN=90' $'HEALTH_MAILQ_WARN\t#HEALTH_MAILQ_WARN=50' $'HEALTH_IO_WARN\t#HEALTH_IO_WARN=25' )
C_motifs_v=( $'HONEYPOT_PATTERN\t#HONEYPOT_PATTERN='\''\.env|wp-config\.php|phpmyadmin|config\.json|setup\.php|actuator|xmlrpc\.php'\''' $'NOISE_PATTERN\t#NOISE_PATTERN='\''\.(jpg|jpeg|png|gif|webp|ico|css|js|svg|woff2?|map)$|apple-touch-icon|favicon|browserconfig\.xml|mstile|autodiscover\.xml|sitemap\.xml|robots\.txt|ads\.txt|\.well-known/(security\.txt|pki-validation)'\''' $'SECURITY_PATTERN\t#SECURITY_PATTERN='\''etc(/|%2f)passwd|\.\./\.\.|%2e%2e%2f|\.\.%2f|%00|vendor/phpunit|eval-stdin\.php|union(\+|%20)select|information_schema|amp%3bamp%3b|resultsperpage=[^& ]*%3f|resultsperpage.*resultsperpage'\''' $'POST_FLOOD_PATTERN\t#POST_FLOOD_PATTERN='\''wp-login\.php|xmlrpc\.php'\''' )
C_KNOWN=" REPO_RAW WHITELIST_IP BAN404_LANG WINDOW BAN_TIMEOUT TAIL_LINES BAN_THRESHOLD HONEYPOT_SCORE HONEYPOT_BAN_TIMEOUT WHITELIST_CIDR EXCLUDE_VHOSTS SERVER_NICKNAME WEBHOOK_URL NOTIFY_EMAIL NOTIFY_FROM NOTIFY_MIN_BANS NOTIFY_BANS DAILY_SUMMARY RESOLVE_PTR PTR_TIMEOUT HEALTH_CHECKS HEALTH_LOAD_WARN HEALTH_MEM_WARN HEALTH_DISK_WARN HEALTH_MAILQ_WARN HEALTH_IO_WARN HONEYPOT_PATTERN NOISE_PATTERN SECURITY_PATTERN POST_FLOOD_PATTERN POST_FLOOD_THRESHOLD CRON_STEP "

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

# Options réseau curl robustes. --retry seul NE réessaie PAS l'exit 7 « Couldn't connect »
# (ni timeout ni code HTTP) ; --retry-all-errors (curl >= 7.71) le couvre — mais c'est une
# option FATALE sur curl plus ancien, donc ajoutée seulement si la version la supporte
# (détection fail-safe : tout échec => on retombe sur --retry nu). Mémoïsé (un seul
# `curl --version` par exécution). --max-time reste au site d'appel (spécifique).
NET_OPTS=()
NET_OPTS_DONE=false
net_opts_init() {
    [ "${NET_OPTS_DONE:-false}" = true ] && return 0
    NET_OPTS_DONE=true
    NET_OPTS=(--retry 3 --retry-delay 2 --connect-timeout 8)
    local cv lo
    cv=$(curl --version 2>/dev/null | awk 'NR==1{print $2}')
    [ -n "$cv" ] || return 0
    lo=$(printf '%s\n%s\n' "$cv" "7.71.0" | sort -V 2>/dev/null | head -n1)
    [ "$lo" = "7.71.0" ] && NET_OPTS+=(--retry-all-errors)
    return 0
}

# Télécharge $1 dans un fichier temporaire dont le chemin est émis sur stdout.
# Retourne != 0 (et n'émet rien) en cas d'échec.
# --retry absorbe les erreurs transitoires (dont HTTP 429, curl >= 7.66) ; net_opts_init y
# ajoute --retry-all-errors (couvre l'exit 7 « Couldn't connect ») quand curl le supporte, et
# --connect-timeout. Pas d'équivalent côté wget : --retry-on-http-error est inconnu des vieux
# wget (option fatale), le repli reste donc inchangé.
download(){
    local url="$1" tmp
    tmp=$(mktemp /tmp/ban_404.XXXXXX) || return 1
    if command -v curl >/dev/null 2>&1; then
        net_opts_init
        curl -fsSL "${NET_OPTS[@]}" --max-time 30 "$url" -o "$tmp" || { rm -f "$tmp"; return 1; }
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

# 1ter) Shim de chargement ANTICIPÉ dans /etc/bash_completion.d/ (sourcé par le framework à
#    l'ouverture du shell). Indispensable pour « sudo ban_404.sh <Tab> » : la délégation sudo de
#    bash-completion <= 2.11 (_command_offset) ne fait PAS de chargement à la demande — sans shim,
#    la complétion ne marche après sudo que si elle a déjà été chargée par un Tab direct dans la
#    même session. Statique et minuscule (coût d'ouverture de shell négligeable) ; idempotent.
if [ -d /etc/bash_completion.d ]; then
    _shim="/etc/bash_completion.d/ban_404"
    _shim_body="# ban-404 : chargement anticipé de la complétion (requis pour « sudo ban_404.sh <Tab> »,
# la délégation sudo de bash-completion <= 2.11 ne charge pas à la demande). Géré par update_ban_404.sh.
[ -f $COMPLETION_PATH ] && . $COMPLETION_PATH"
    if [ ! -f "$_shim" ] || [ "$(cat "$_shim" 2>/dev/null)" != "$_shim_body" ]; then
        printf '%s\n' "$_shim_body" > "$_shim" && chmod 644 "$_shim"
    fi
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
UPD_EOF
chmod 755 "$UPDATER_PATH"
cat > "$UPDATE_CRON" <<EOF
#!/bin/sh
exec $UPDATER_PATH
EOF
chmod 755 "$UPDATE_CRON"

# Le cron de résumé quotidien (cron.daily/ban_404_summary) n'est plus posé ici : le moteur en est
# seul maître et l'aligne sur DAILY_SUMMARY à chaque passage horaire (self_heal_summary_cron).

# Récupération initiale du moteur : on délègue à l'updater (source unique de vérité).
t inst.fetch_engine "$SCRIPT_PATH"
"$UPDATER_PATH" || true
[ -s "$SCRIPT_PATH" ] || die "$(t inst.fetch_fail "$SCRIPT_PATH" "$REPO_RAW" "$CONF_PATH" "$LOG_PATH")"

t inst.cron_hourly "$CRON_PATH"
# Lanceur muet : depuis ban_404 1.4.28 le moteur journalise LUI-MÊME ses événements dans
# LOG_PATH (une seule méthode de log, cron comme manuel). Garder ce contenu en phase avec
# le wrapper canonique de self_heal_hourly_cron (ban_404.sh).
cat > "$CRON_PATH" <<EOF
#!/bin/sh
# Depuis ban_404 1.4.28, le moteur journalise lui-même ses événements dans $LOG_PATH.
exec $SCRIPT_PATH >/dev/null 2>&1
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
# Recharger d'éventuels bans déjà persistés (migration / réinstall) AVANT de re-sauvegarder
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
