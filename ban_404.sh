#!/bin/bash

BAN404_VERSION="1.4.21"

# Configuration (valeurs par défaut ; surchargées par /etc/ban_404.conf)
BASE_DIR="/var/www"
IPSET_NAME="ban_404_list"
IPSET_SAVE_FILE="/etc/iptables/ipsets"   # chemin canonique du plugin ipset-persistent
BAN_TIMEOUT=172800   # 48 heures
WINDOW=7200          # Fenêtre glissante en secondes (2h). Cron horaire => recouvrement, pas de trou aux bornes.
TAIL_LINES=50000     # On n'analyse que les N dernières lignes de chaque log (borne le coût sur gros sites).
                     # À augmenter si un site dépasse TAIL_LINES requêtes dans la fenêtre WINDOW.
LOCK_FILE="/run/ban_404_list.lock"
LOG_FILE="/var/log/ban_404.log"   # journal (écrit par le wrapper cron) ; lu par --stats/--summary
UPDATE_STAMP_FILE="/var/lib/ban_404/last_update"   # repère « l'updater a tourné » (écrit par update_ban_404.sh)

# Seuils & motifs de détection (surchargeables par la conf)
BAN_THRESHOLD=10     # Ban si le score dépasse ce seuil dans la fenêtre.
HONEYPOT_SCORE=100   # Score ajouté par hit honeypot (>= ce score => ban immédiat).
HONEYPOT_BAN_TIMEOUT=604800   # Timeout du ban honeypot (s) : 7 j, plus long que BAN_TIMEOUT (flood 404).
HONEYPOT_PATTERN='\.env|wp-config\.php|phpmyadmin|config\.json|setup\.php|actuator|xmlrpc\.php'
NOISE_PATTERN='\.(jpg|jpeg|png|gif|webp|ico|css|js|svg|woff2?|map)$|apple-touch-icon|favicon|browserconfig\.xml|mstile|autodiscover\.xml|sitemap\.xml|robots\.txt|ads\.txt|\.well-known/(security\.txt|pki-validation)'

# Whitelist des IPs à ne JAMAIS bannir (séparées par | ) -- correspondance EXACTE
WHITELIST_IP="127.0.0.1"

# Whitelist CIDR / sous-réseaux à ne JAMAIS bannir (séparés par | ), ex: "10.0.0.0/8|192.168.0.0/16"
WHITELIST_CIDR=""

# Vhosts à EXCLURE de l'analyse (noms de dossier sous BASE_DIR, séparés par | ),
# ex: "staging.exemple.com|interne.exemple.com". Vide => tous les vhosts sont analysés.
EXCLUDE_VHOSTS=""

# Notifications (optionnel ; vides => désactivées). Messages dans la langue BAN404_LANG.
WEBHOOK_URL=""        # POST JSON des nouveaux bans (Slack/Discord/Teams/n8n...)
NOTIFY_EMAIL=""       # e-mail des nouveaux bans (nécessite un MTA : mail/sendmail)
NOTIFY_FROM=""        # expéditeur e-mail (optionnel)
NOTIFY_MIN_BANS=1     # ne notifier que si AU MOINS N nouveaux bans dans le run
NOTIFY_BANS=false     # alerte à chaque run quand des IP sont bannies (true pour activer)
DAILY_SUMMARY=false   # résumé quotidien (opt-in) : --summary n'envoie que si =true ET canal configuré
SERVER_NICKNAME=""    # nom convivial ajouté au hostname dans les notifs (vide => hostname seul). Ex: "Jaubalet (prod)"

# Reverse DNS (PTR) des IP affichées par --list/--stats/--summary (opt-in ; le flag --resolve force)
RESOLVE_PTR=false     # true => résoudre le PTR des IP ; borné par PTR_TIMEOUT pour ne pas bloquer
PTR_TIMEOUT=2         # délai max par lookup getent (s), borne le coût du reverse

# ============================================================================
#  i18n — messages multilingues (en, fr, de, es, it). Le code/les commentaires
#  restent en français ; SEULS les messages affichés sont traduisibles.
#  Les tableaux sont indépendants de la langue : on peut les définir avant le
#  sourcing de la conf. La langue effective est résolue après (detect_lang).
# ============================================================================
declare -A T_EN T_FR T_DE T_ES T_IT

T_EN[version.line]="ban_404.sh version %s"
T_FR[version.line]="ban_404.sh version %s"
T_DE[version.line]="ban_404.sh version %s"
T_ES[version.line]="ban_404.sh version %s"
T_IT[version.line]="ban_404.sh version %s"

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

T_EN[help.dryrun]="  --dry-run        Simulate actions (read-only mode)."
T_FR[help.dryrun]="  --dry-run        Simuler les actions (mode lecture seule)."
T_DE[help.dryrun]="  --dry-run        Aktionen simulieren (Nur-Lese-Modus)."
T_ES[help.dryrun]="  --dry-run        Simular las acciones (modo de solo lectura)."
T_IT[help.dryrun]="  --dry-run        Simulare le azioni (modalità di sola lettura)."

T_EN[help.showblocked]="  --show-blocked   Also show IPs already in the ipset."
T_FR[help.showblocked]="  --show-blocked   Afficher aussi les IP déjà dans l'ipset."
T_DE[help.showblocked]="  --show-blocked   Auch IPs anzeigen, die bereits im ipset sind."
T_ES[help.showblocked]="  --show-blocked   Mostrar también las IP que ya están en el ipset."
T_IT[help.showblocked]="  --show-blocked   Mostrare anche gli IP già presenti nell'ipset."

T_EN[help.verbose]="  --verbose        Detail the run (log search) or, with --diag, each folder's cause."
T_FR[help.verbose]="  --verbose        Détailler le run (recherche des logs) ou, avec --diag, chaque dossier."
T_DE[help.verbose]="  --verbose        Den Lauf (Log-Suche) oder, mit --diag, jedes Verzeichnis detaillieren."
T_ES[help.verbose]="  --verbose        Detallar el run (búsqueda de registros) o, con --diag, cada carpeta."
T_IT[help.verbose]="  --verbose        Dettagliare il run (ricerca dei log) o, con --diag, ogni cartella."

T_EN[help.lang]="  --lang <code>    Set the language (en, fr, de, es, it) in the config and exit."
T_FR[help.lang]="  --lang <code>    Définir la langue (en, fr, de, es, it) dans la config et quitter."
T_DE[help.lang]="  --lang <code>    Sprache (en, fr, de, es, it) in der Konfiguration setzen und beenden."
T_ES[help.lang]="  --lang <code>    Definir el idioma (en, fr, de, es, it) en la configuración y salir."
T_IT[help.lang]="  --lang <code>    Impostare la lingua (en, fr, de, es, it) nella configurazione e uscire."

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

T_EN[lang.missing]="--lang requires a code: en, fr, de, es, it."
T_FR[lang.missing]="--lang requiert un code : en, fr, de, es, it."
T_DE[lang.missing]="--lang erfordert einen Code: en, fr, de, es, it."
T_ES[lang.missing]="--lang requiere un código: en, fr, de, es, it."
T_IT[lang.missing]="--lang richiede un codice: en, fr, de, es, it."

T_EN[lang.unsupported]="Unsupported language: %s. Supported: en, fr, de, es, it."
T_FR[lang.unsupported]="Langue non supportée : %s. Supportées : en, fr, de, es, it."
T_DE[lang.unsupported]="Nicht unterstützte Sprache: %s. Unterstützt: en, fr, de, es, it."
T_ES[lang.unsupported]="Idioma no soportado: %s. Soportados: en, fr, de, es, it."
T_IT[lang.unsupported]="Lingua non supportata: %s. Supportate: en, fr, de, es, it."

T_EN[lang.noconf]="Config file %s not found. Run the installer first."
T_FR[lang.noconf]="Fichier de config %s introuvable. Lancez d'abord l'installeur."
T_DE[lang.noconf]="Konfigurationsdatei %s nicht gefunden. Führen Sie zuerst den Installer aus."
T_ES[lang.noconf]="Archivo de configuración %s no encontrado. Ejecute primero el instalador."
T_IT[lang.noconf]="File di configurazione %s non trovato. Eseguire prima l'installer."

T_EN[lang.write_fail]="Cannot write to %s (try with sudo)."
T_FR[lang.write_fail]="Impossible d'écrire dans %s (essayez avec sudo)."
T_DE[lang.write_fail]="Schreiben in %s nicht möglich (mit sudo versuchen)."
T_ES[lang.write_fail]="No se puede escribir en %s (pruebe con sudo)."
T_IT[lang.write_fail]="Impossibile scrivere su %s (provare con sudo)."

T_EN[lang.changed]="Language set to %s in %s."
T_FR[lang.changed]="Langue définie sur %s dans %s."
T_DE[lang.changed]="Sprache auf %s in %s gesetzt."
T_ES[lang.changed]="Idioma establecido en %s en %s."
T_IT[lang.changed]="Lingua impostata su %s in %s."

T_EN[banner.sim_active]="SIMULATION MODE (DRY-RUN) ACTIVE"
T_FR[banner.sim_active]="MODE SIMULATION (DRY-RUN) ACTIF"
T_DE[banner.sim_active]="SIMULATIONSMODUS (DRY-RUN) AKTIV"
T_ES[banner.sim_active]="MODO SIMULACIÓN (DRY-RUN) ACTIVO"
T_IT[banner.sim_active]="MODALITÀ SIMULAZIONE (DRY-RUN) ATTIVA"

T_EN[verbose.filter_hidden]="   FILTER: IPs already blocked are hidden\n"
T_FR[verbose.filter_hidden]="   FILTRE : les IP déjà bloquées sont masquées\n"
T_DE[verbose.filter_hidden]="   FILTER: bereits gesperrte IPs werden ausgeblendet\n"
T_ES[verbose.filter_hidden]="   FILTRO: las IP ya bloqueadas se ocultan\n"
T_IT[verbose.filter_hidden]="   FILTRO: gli IP già bloccati sono nascosti\n"

T_EN[verbose.filter_all]="   DISPLAY: all IPs included\n"
T_FR[verbose.filter_all]="   AFFICHAGE : toutes les IP incluses\n"
T_DE[verbose.filter_all]="   ANZEIGE: alle IPs eingeschlossen\n"
T_ES[verbose.filter_all]="   VISUALIZACIÓN: todas las IP incluidas\n"
T_IT[verbose.filter_all]="   VISUALIZZAZIONE: tutti gli IP inclusi\n"

T_EN[verbose.searching_logs]="=[ Searching for log files... ]="
T_FR[verbose.searching_logs]="=[ Recherche des fichiers de logs... ]="
T_DE[verbose.searching_logs]="=[ Suche nach Log-Dateien... ]="
T_ES[verbose.searching_logs]="=[ Buscando archivos de registro... ]="
T_IT[verbose.searching_logs]="=[ Ricerca dei file di log... ]="

T_EN[verbose.log_ok]="-> OK (readable): %s"
T_FR[verbose.log_ok]="-> OK (lisible) : %s"
T_DE[verbose.log_ok]="-> OK (lesbar): %s"
T_ES[verbose.log_ok]="-> OK (legible): %s"
T_IT[verbose.log_ok]="-> OK (leggibile): %s"

T_EN[verbose.log_skip]="-> Skipped: %s"
T_FR[verbose.log_skip]="-> Ignoré : %s"
T_DE[verbose.log_skip]="-> Übersprungen: %s"
T_ES[verbose.log_skip]="-> Ignorado: %s"
T_IT[verbose.log_skip]="-> Ignorato: %s"

T_EN[verbose.vhost_excluded]="-> Skipped (excluded vhost): %s"
T_FR[verbose.vhost_excluded]="-> Ignoré (vhost exclu) : %s"
T_DE[verbose.vhost_excluded]="-> Übersprungen (ausgeschlossener vhost): %s"
T_ES[verbose.vhost_excluded]="-> Ignorado (vhost excluido): %s"
T_IT[verbose.vhost_excluded]="-> Ignorato (vhost escluso): %s"

T_EN[heal.updater]="[*] Legacy updater replaced by the current version: %s"
T_FR[heal.updater]="[*] Updater legacy remplacé par la version courante : %s"
T_DE[heal.updater]="[*] Veralteter Updater durch die aktuelle Version ersetzt: %s"
T_ES[heal.updater]="[*] Updater legacy reemplazado por la versión actual: %s"
T_IT[heal.updater]="[*] Updater legacy sostituito con la versione attuale: %s"

T_EN[heal.summary_cron]="[*] Missing daily-summary cron reinstalled: %s"
T_FR[heal.summary_cron]="[*] Cron de résumé quotidien manquant réinstallé : %s"
T_DE[heal.summary_cron]="[*] Fehlender Tageszusammenfassungs-Cron neu installiert: %s"
T_ES[heal.summary_cron]="[*] Cron de resumen diario faltante reinstalado: %s"
T_IT[heal.summary_cron]="[*] Cron del riepilogo giornaliero mancante reinstallato: %s"

T_EN[heal.summary_cron_removed]="[*] Daily-summary cron removed (DAILY_SUMMARY disabled): %s"
T_FR[heal.summary_cron_removed]="[*] Cron de résumé quotidien retiré (DAILY_SUMMARY désactivé) : %s"
T_DE[heal.summary_cron_removed]="[*] Tageszusammenfassungs-Cron entfernt (DAILY_SUMMARY deaktiviert): %s"
T_ES[heal.summary_cron_removed]="[*] Cron de resumen diario eliminado (DAILY_SUMMARY desactivado): %s"
T_IT[heal.summary_cron_removed]="[*] Cron del riepilogo giornaliero rimosso (DAILY_SUMMARY disattivato): %s"

T_EN[heal.update_triggered]="[*] cron.daily silent — updater triggered from the hourly run."
T_FR[heal.update_triggered]="[*] cron.daily muet — updater relancé depuis le passage horaire."
T_DE[heal.update_triggered]="[*] cron.daily stumm — Updater vom stündlichen Lauf ausgelöst."
T_ES[heal.update_triggered]="[*] cron.daily en silencio — updater lanzado desde la ejecución horaria."
T_IT[heal.update_triggered]="[*] cron.daily silenzioso — updater avviato dall'esecuzione oraria."

T_EN[no_valid_files]="=> No valid log file found. Done."
T_FR[no_valid_files]="=> Aucun fichier de log valide trouvé. Fin."
T_DE[no_valid_files]="=> Keine gültige Log-Datei gefunden. Ende."
T_ES[no_valid_files]="=> No se encontró ningún archivo de registro válido. Fin."
T_IT[no_valid_files]="=> Nessun file di log valido trovato. Fine."

T_EN[verbose.analyzing]="\n=[ Analyzing last %s lines/log since %s ]="
T_FR[verbose.analyzing]="\n=[ Analyse des %s dernières lignes/log depuis %s ]="
T_DE[verbose.analyzing]="\n=[ Analyse der letzten %s Zeilen/Log seit %s ]="
T_ES[verbose.analyzing]="\n=[ Analizando las últimas %s líneas/log desde %s ]="
T_IT[verbose.analyzing]="\n=[ Analisi delle ultime %s righe/log da %s ]="

T_EN[no_suspect]="No suspicious IP found."
T_FR[no_suspect]="Aucune IP suspecte trouvée."
T_DE[no_suspect]="Keine verdächtige IP gefunden."
T_ES[no_suspect]="No se encontró ninguna IP sospechosa."
T_IT[no_suspect]="Nessun IP sospetto trovato."

T_EN[verbose.processing]="\n=[ Processing IPs ]="
T_FR[verbose.processing]="\n=[ Traitement des IP ]="
T_DE[verbose.processing]="\n=[ Verarbeitung der IPs ]="
T_ES[verbose.processing]="\n=[ Procesando las IP ]="
T_IT[verbose.processing]="\n=[ Elaborazione degli IP ]="

T_EN[unban.crawler]="[-] Unbanning IP (legitimate crawler): %s (%s | %s 404)"
T_FR[unban.crawler]="[-] Déblocage de l'IP (crawler légitime) : %s (%s | %s 404)"
T_DE[unban.crawler]="[-] Entsperrung der IP (legitimer Crawler): %s (%s | %s 404)"
T_ES[unban.crawler]="[-] Desbloqueo de la IP (crawler legítimo): %s (%s | %s 404)"
T_IT[unban.crawler]="[-] Sblocco dell'IP (crawler legittimo): %s (%s | %s 404)"

T_EN[sim.unban]="[SIMULATION] [-] IP %s would be UNBANNED (real bot: %s)."
T_FR[sim.unban]="[SIMULATION] [-] L'IP %s aurait été DÉBANNIE (vrai robot : %s)."
T_DE[sim.unban]="[SIMULATION] [-] IP %s würde ENTSPERRT (echter Bot: %s)."
T_ES[sim.unban]="[SIMULATION] [-] La IP %s sería DESBLOQUEADA (robot real: %s)."
T_IT[sim.unban]="[SIMULATION] [-] L'IP %s verrebbe SBLOCCATO (bot reale: %s)."

T_EN[skip.crawler]="[SKIP] Legitimate bot not blocked: %s"
T_FR[skip.crawler]="[SKIP] Robot légitime non bloqué : %s"
T_DE[skip.crawler]="[SKIP] Legitimer Bot nicht gesperrt: %s"
T_ES[skip.crawler]="[SKIP] Robot legítimo no bloqueado: %s"
T_IT[skip.crawler]="[SKIP] Bot legittimo non bloccato: %s"

T_EN[already.banned]="[...] IP %s is already in the ipset (%s 404 errors)."
T_FR[already.banned]="[...] L'IP %s est déjà dans l'ipset (%s erreurs 404)."
T_DE[already.banned]="[...] IP %s ist bereits im ipset (%s 404-Fehler)."
T_ES[already.banned]="[...] La IP %s ya está en el ipset (%s errores 404)."
T_IT[already.banned]="[...] L'IP %s è già nell'ipset (%s errori 404)."

T_EN[sim.ban_honeypot]="[SIMULATION] [+] IP %s would be banned IMMEDIATELY (honeypot detected: %s)."
T_FR[sim.ban_honeypot]="[SIMULATION] [+] L'IP %s aurait été bannie IMMÉDIATEMENT (honeypot détecté : %s)."
T_DE[sim.ban_honeypot]="[SIMULATION] [+] IP %s würde SOFORT gesperrt (Honeypot erkannt: %s)."
T_ES[sim.ban_honeypot]="[SIMULATION] [+] La IP %s sería bloqueada INMEDIATAMENTE (honeypot detectado: %s)."
T_IT[sim.ban_honeypot]="[SIMULATION] [+] L'IP %s verrebbe bloccato IMMEDIATAMENTE (honeypot rilevato: %s)."

T_EN[sim.ban_add]="[SIMULATION] [+] IP %s would be added to the ipset (%s 404 errors)."
T_FR[sim.ban_add]="[SIMULATION] [+] L'IP %s aurait été ajoutée à l'ipset (%s erreurs 404)."
T_DE[sim.ban_add]="[SIMULATION] [+] IP %s würde zum ipset hinzugefügt (%s 404-Fehler)."
T_ES[sim.ban_add]="[SIMULATION] [+] La IP %s se añadiría al ipset (%s errores 404)."
T_IT[sim.ban_add]="[SIMULATION] [+] L'IP %s verrebbe aggiunto all'ipset (%s errori 404)."

T_EN[ban.honeypot]="[+] IMMEDIATE block (honeypot) of IP: %s (score %s)"
T_FR[ban.honeypot]="[+] Blocage IMMÉDIAT (honeypot) de l'IP : %s (score %s)"
T_DE[ban.honeypot]="[+] SOFORTIGE Sperre (Honeypot) der IP: %s (Score %s)"
T_ES[ban.honeypot]="[+] Bloqueo INMEDIATO (honeypot) de la IP: %s (puntuación %s)"
T_IT[ban.honeypot]="[+] Blocco IMMEDIATO (honeypot) dell'IP: %s (punteggio %s)"

T_EN[ban.add]="[+] Block (ipset) of IP: %s (%s 404 errors)"
T_FR[ban.add]="[+] Blocage (ipset) de l'IP : %s (%s erreurs 404)"
T_DE[ban.add]="[+] Sperre (ipset) der IP: %s (%s 404-Fehler)"
T_ES[ban.add]="[+] Bloqueo (ipset) de la IP: %s (%s errores 404)"
T_IT[ban.add]="[+] Blocco (ipset) dell'IP: %s (%s errori 404)"

T_EN[verbose.result_header]="\n=[ Result ]="
T_FR[verbose.result_header]="\n=[ Résultat ]="
T_DE[verbose.result_header]="\n=[ Ergebnis ]="
T_ES[verbose.result_header]="\n=[ Resultado ]="
T_IT[verbose.result_header]="\n=[ Risultato ]="

T_EN[result.sim]="=> Simulation finished. %s virtual action(s) generated."
T_FR[result.sim]="=> Mode simulation terminé. %s action(s) virtuelle(s) générée(s)."
T_DE[result.sim]="=> Simulation beendet. %s virtuelle Aktion(en) erzeugt."
T_ES[result.sim]="=> Simulación finalizada. %s acción(es) virtual(es) generada(s)."
T_IT[result.sim]="=> Simulazione terminata. %s azione/i virtuale/i generata/e."

T_EN[verbose.changes_saved]="=> Changes applied. Saving the ipset configuration..."
T_FR[verbose.changes_saved]="=> Changements appliqués. Sauvegarde de la configuration ipset..."
T_DE[verbose.changes_saved]="=> Änderungen angewendet. ipset-Konfiguration wird gespeichert..."
T_ES[verbose.changes_saved]="=> Cambios aplicados. Guardando la configuración de ipset..."
T_IT[verbose.changes_saved]="=> Modifiche applicate. Salvataggio della configurazione ipset..."

T_EN[verbose.no_change]="=> No change required in the ipset."
T_FR[verbose.no_change]="=> Aucune modification requise dans l'ipset."
T_DE[verbose.no_change]="=> Keine Änderung im ipset erforderlich."
T_ES[verbose.no_change]="=> No se requiere ningún cambio en el ipset."
T_IT[verbose.no_change]="=> Nessuna modifica richiesta nell'ipset."

T_EN[help.list]="  --list           List banned IPs (timeout left), sorted by IP family."
T_FR[help.list]="  --list           Lister les IP bannies (timeout restant), triées par famille d'IP."
T_DE[help.list]="  --list           Gesperrte IPs auflisten (Rest-Timeout), nach IP-Familie sortiert."
T_ES[help.list]="  --list           Listar las IP bloqueadas (timeout restante), ordenadas por familia de IP."
T_IT[help.list]="  --list           Elencare gli IP bloccati (timeout residuo), ordinati per famiglia di IP."

T_EN[help.bytimeout]="  --by-timeout     With --list: sort by remaining timeout (ascending)."
T_FR[help.bytimeout]="  --by-timeout     Avec --list : trier par timeout restant (croissant)."
T_DE[help.bytimeout]="  --by-timeout     Mit --list: nach verbleibendem Timeout sortieren (aufsteigend)."
T_ES[help.bytimeout]="  --by-timeout     Con --list: ordenar por timeout restante (ascendente)."
T_IT[help.bytimeout]="  --by-timeout     Con --list: ordinare per timeout residuo (crescente)."

T_EN[help.resolve]="  --resolve        Show reverse DNS (PTR) of IPs in --list/--stats/--summary (opt-in)."
T_FR[help.resolve]="  --resolve        Afficher le reverse DNS (PTR) des IP dans --list/--stats/--summary (opt-in)."
T_DE[help.resolve]="  --resolve        Reverse-DNS (PTR) der IPs in --list/--stats/--summary anzeigen (opt-in)."
T_ES[help.resolve]="  --resolve        Mostrar el DNS inverso (PTR) de las IP en --list/--stats/--summary (opt-in)."
T_IT[help.resolve]="  --resolve        Mostrare il reverse DNS (PTR) degli IP in --list/--stats/--summary (opt-in)."

T_EN[help.stats]="  --stats          Show ban statistics."
T_FR[help.stats]="  --stats          Afficher les statistiques de ban."
T_DE[help.stats]="  --stats          Sperr-Statistiken anzeigen."
T_ES[help.stats]="  --stats          Mostrar las estadísticas de bloqueo."
T_IT[help.stats]="  --stats          Mostrare le statistiche di blocco."

T_EN[help.unban]="  --unban <IP|all> Remove an IP (or all) from the ban list and exit."
T_FR[help.unban]="  --unban <IP|all> Retirer une IP (ou toutes) de la liste de bannissement et quitter."
T_DE[help.unban]="  --unban <IP|all> Eine IP (oder alle) aus der Sperrliste entfernen und beenden."
T_ES[help.unban]="  --unban <IP|all> Eliminar una IP (o todas) de la lista de bloqueo y salir."
T_IT[help.unban]="  --unban <IP|all> Rimuovere un IP (o tutti) dalla lista di blocco e uscire."

T_EN[help.summary]="  --summary        Send the daily summary via the configured channel (opt-in)."
T_FR[help.summary]="  --summary        Envoyer le résumé quotidien via le canal configuré (opt-in)."
T_DE[help.summary]="  --summary        Tägliche Zusammenfassung über den konfigurierten Kanal senden (opt-in)."
T_ES[help.summary]="  --summary        Enviar el resumen diario por el canal configurado (opt-in)."
T_IT[help.summary]="  --summary        Inviare il riepilogo giornaliero tramite il canale configurato (opt-in)."

T_EN[help.checknotif]="  --check-notification [email|webhook|all]  Send a test notification and report the result (default: all)."
T_FR[help.checknotif]="  --check-notification [email|webhook|all]  Envoyer une notification de test et afficher le résultat (défaut : all)."
T_DE[help.checknotif]="  --check-notification [email|webhook|all]  Eine Testbenachrichtigung senden und das Ergebnis anzeigen (Standard: all)."
T_ES[help.checknotif]="  --check-notification [email|webhook|all]  Enviar una notificación de prueba y mostrar el resultado (por defecto: all)."
T_IT[help.checknotif]="  --check-notification [email|webhook|all]  Inviare una notifica di prova e mostrare il risultato (predefinito: all)."

T_EN[help.diag]="  --diag           Run a read-only self-diagnostic and list any anomalies."
T_FR[help.diag]="  --diag           Lancer un auto-diagnostic en lecture seule et lister les anomalies."
T_DE[help.diag]="  --diag           Eine schreibgeschützte Selbstdiagnose ausführen und Anomalien auflisten."
T_ES[help.diag]="  --diag           Ejecutar un autodiagnóstico de solo lectura y listar las anomalías."
T_IT[help.diag]="  --diag           Eseguire un'autodiagnostica in sola lettura ed elencare le anomalie."

T_EN[check.header]="=[ ban-404 notification test ]="
T_FR[check.header]="=[ Test des notifications ban-404 ]="
T_DE[check.header]="=[ ban-404 Benachrichtigungstest ]="
T_ES[check.header]="=[ Prueba de notificaciones ban-404 ]="
T_IT[check.header]="=[ Test delle notifiche ban-404 ]="

T_EN[check.subject]="ban-404 notification test on %s"
T_FR[check.subject]="Test de notification ban-404 sur %s"
T_DE[check.subject]="ban-404 Benachrichtigungstest auf %s"
T_ES[check.subject]="Prueba de notificación ban-404 en %s"
T_IT[check.subject]="Test di notifica ban-404 su %s"

T_EN[check.body]="Test notification from ban-404 on %s. If you receive this, the channel works."
T_FR[check.body]="Notification de test de ban-404 sur %s. Si vous recevez ceci, le canal fonctionne."
T_DE[check.body]="Testbenachrichtigung von ban-404 auf %s. Wenn Sie dies erhalten, funktioniert der Kanal."
T_ES[check.body]="Notificación de prueba de ban-404 en %s. Si recibe esto, el canal funciona."
T_IT[check.body]="Notifica di prova da ban-404 su %s. Se ricevi questo, il canale funziona."

T_EN[check.webhook_off]="Webhook: not configured (WEBHOOK_URL empty)."
T_FR[check.webhook_off]="Webhook : non configuré (WEBHOOK_URL vide)."
T_DE[check.webhook_off]="Webhook: nicht konfiguriert (WEBHOOK_URL leer)."
T_ES[check.webhook_off]="Webhook: no configurado (WEBHOOK_URL vacío)."
T_IT[check.webhook_off]="Webhook: non configurato (WEBHOOK_URL vuoto)."

T_EN[check.webhook_nocurl]="Webhook: curl not available."
T_FR[check.webhook_nocurl]="Webhook : curl indisponible."
T_DE[check.webhook_nocurl]="Webhook: curl nicht verfügbar."
T_ES[check.webhook_nocurl]="Webhook: curl no disponible."
T_IT[check.webhook_nocurl]="Webhook: curl non disponibile."

T_EN[check.webhook_ok]="Webhook: OK (HTTP %s)."
T_FR[check.webhook_ok]="Webhook : OK (HTTP %s)."
T_DE[check.webhook_ok]="Webhook: OK (HTTP %s)."
T_ES[check.webhook_ok]="Webhook: OK (HTTP %s)."
T_IT[check.webhook_ok]="Webhook: OK (HTTP %s)."

T_EN[check.webhook_fail]="Webhook: FAILED (HTTP %s)."
T_FR[check.webhook_fail]="Webhook : ÉCHEC (HTTP %s)."
T_DE[check.webhook_fail]="Webhook: FEHLGESCHLAGEN (HTTP %s)."
T_ES[check.webhook_fail]="Webhook: FALLÓ (HTTP %s)."
T_IT[check.webhook_fail]="Webhook: FALLITO (HTTP %s)."

T_EN[check.webhook_err]="Webhook: FAILED (connection error / unreachable)."
T_FR[check.webhook_err]="Webhook : ÉCHEC (erreur de connexion / injoignable)."
T_DE[check.webhook_err]="Webhook: FEHLGESCHLAGEN (Verbindungsfehler / nicht erreichbar)."
T_ES[check.webhook_err]="Webhook: FALLÓ (error de conexión / inaccesible)."
T_IT[check.webhook_err]="Webhook: FALLITO (errore di connessione / irraggiungibile)."

T_EN[check.email_off]="E-mail: not configured (NOTIFY_EMAIL empty)."
T_FR[check.email_off]="E-mail : non configuré (NOTIFY_EMAIL vide)."
T_DE[check.email_off]="E-Mail: nicht konfiguriert (NOTIFY_EMAIL leer)."
T_ES[check.email_off]="E-mail: no configurado (NOTIFY_EMAIL vacío)."
T_IT[check.email_off]="E-mail: non configurato (NOTIFY_EMAIL vuoto)."

T_EN[check.email_no_mta]="E-mail: no MTA found (install mail or sendmail)."
T_FR[check.email_no_mta]="E-mail : aucun MTA trouvé (installez mail ou sendmail)."
T_DE[check.email_no_mta]="E-Mail: kein MTA gefunden (mail oder sendmail installieren)."
T_ES[check.email_no_mta]="E-mail: no se encontró MTA (instale mail o sendmail)."
T_IT[check.email_no_mta]="E-mail: nessun MTA trovato (installare mail o sendmail)."

T_EN[check.email_sent]="E-mail: handed to the MTA for %s (check the inbox)."
T_FR[check.email_sent]="E-mail : remis au MTA pour %s (vérifiez la boîte de réception)."
T_DE[check.email_sent]="E-Mail: an den MTA übergeben für %s (Posteingang prüfen)."
T_ES[check.email_sent]="E-mail: entregado al MTA para %s (revise la bandeja de entrada)."
T_IT[check.email_sent]="E-mail: consegnato all'MTA per %s (controllare la posta)."

T_EN[check.email_fail]="E-mail: the MTA rejected the message."
T_FR[check.email_fail]="E-mail : le MTA a rejeté le message."
T_DE[check.email_fail]="E-Mail: der MTA hat die Nachricht abgelehnt."
T_ES[check.email_fail]="E-mail: el MTA rechazó el mensaje."
T_IT[check.email_fail]="E-mail: l'MTA ha rifiutato il messaggio."

T_EN[check.none_configured]="No notification channel is configured."
T_FR[check.none_configured]="Aucun canal de notification n'est configuré."
T_DE[check.none_configured]="Kein Benachrichtigungskanal ist konfiguriert."
T_ES[check.none_configured]="No hay ningún canal de notificación configurado."
T_IT[check.none_configured]="Nessun canale di notifica è configurato."

T_EN[check.invalid]="Invalid target: %s. Use: email, webhook, all."
T_FR[check.invalid]="Cible invalide : %s. Utilisez : email, webhook, all."
T_DE[check.invalid]="Ungültiges Ziel: %s. Verwenden Sie: email, webhook, all."
T_ES[check.invalid]="Objetivo inválido: %s. Use: email, webhook, all."
T_IT[check.invalid]="Destinazione non valida: %s. Usare: email, webhook, all."

T_EN[check.diag]="  ↳ diagnostic: %s"
T_FR[check.diag]="  ↳ diagnostic : %s"
T_DE[check.diag]="  ↳ Diagnose: %s"
T_ES[check.diag]="  ↳ diagnóstico: %s"
T_IT[check.diag]="  ↳ diagnostica: %s"

# --- --diag : auto-diagnostic (lecture seule) ---
T_EN[diag.header]="=[ ban-404 diagnostic ]="
T_FR[diag.header]="=[ Diagnostic ban-404 ]="
T_DE[diag.header]="=[ ban-404 Diagnose ]="
T_ES[diag.header]="=[ Diagnóstico ban-404 ]="
T_IT[diag.header]="=[ Diagnostica ban-404 ]="

T_EN[diag.engine_ok]="Engine ban_404.sh present (v%s)."
T_FR[diag.engine_ok]="Moteur ban_404.sh présent (v%s)."
T_DE[diag.engine_ok]="Engine ban_404.sh vorhanden (v%s)."
T_ES[diag.engine_ok]="Motor ban_404.sh presente (v%s)."
T_IT[diag.engine_ok]="Motore ban_404.sh presente (v%s)."

T_EN[diag.engine_missing]="Engine missing: %s"
T_FR[diag.engine_missing]="Moteur absent : %s"
T_DE[diag.engine_missing]="Engine fehlt: %s"
T_ES[diag.engine_missing]="Motor ausente: %s"
T_IT[diag.engine_missing]="Motore assente: %s"

T_EN[diag.updater_ok]="Updater present and versioned (v%s)."
T_FR[diag.updater_ok]="Updater présent et versionné (v%s)."
T_DE[diag.updater_ok]="Updater vorhanden und versioniert (v%s)."
T_ES[diag.updater_ok]="Updater presente y versionado (v%s)."
T_IT[diag.updater_ok]="Updater presente e versionato (v%s)."

T_EN[diag.updater_legacy]="Updater present but legacy (no version) — will self-heal on the next hourly run."
T_FR[diag.updater_legacy]="Updater présent mais legacy (sans version) — auto-guérison au prochain passage horaire."
T_DE[diag.updater_legacy]="Updater vorhanden, aber veraltet (ohne Version) — Selbstheilung beim nächsten stündlichen Lauf."
T_ES[diag.updater_legacy]="Updater presente pero legacy (sin versión) — autocuración en la próxima ejecución horaria."
T_IT[diag.updater_legacy]="Updater presente ma legacy (senza versione) — autoguarigione alla prossima esecuzione oraria."

T_EN[diag.updater_missing]="Updater missing: %s"
T_FR[diag.updater_missing]="Updater absent : %s"
T_DE[diag.updater_missing]="Updater fehlt: %s"
T_ES[diag.updater_missing]="Updater ausente: %s"
T_IT[diag.updater_missing]="Updater assente: %s"

T_EN[diag.repo_uptodate]="Repository: engine and updater are up to date."
T_FR[diag.repo_uptodate]="Dépôt : moteur et updater à jour."
T_DE[diag.repo_uptodate]="Repository: Engine und Updater sind aktuell."
T_ES[diag.repo_uptodate]="Repositorio: motor y updater actualizados."
T_IT[diag.repo_uptodate]="Repository: motore e updater aggiornati."

T_EN[diag.engine_update]="Engine update available (local %s / repo %s)."
T_FR[diag.engine_update]="MAJ du moteur disponible (local %s / dépôt %s)."
T_DE[diag.engine_update]="Engine-Update verfügbar (lokal %s / Repo %s)."
T_ES[diag.engine_update]="Actualización del motor disponible (local %s / repo %s)."
T_IT[diag.engine_update]="Aggiornamento motore disponibile (locale %s / repo %s)."

T_EN[diag.updater_update]="Updater update available (local %s / repo %s)."
T_FR[diag.updater_update]="MAJ de l'updater disponible (local %s / dépôt %s)."
T_DE[diag.updater_update]="Updater-Update verfügbar (lokal %s / Repo %s)."
T_ES[diag.updater_update]="Actualización del updater disponible (local %s / repo %s)."
T_IT[diag.updater_update]="Aggiornamento updater disponibile (locale %s / repo %s)."

T_EN[diag.repo_unreachable]="Repository unreachable (no version comparison): %s"
T_FR[diag.repo_unreachable]="Dépôt injoignable (pas de comparaison de version) : %s"
T_DE[diag.repo_unreachable]="Repository nicht erreichbar (kein Versionsvergleich): %s"
T_ES[diag.repo_unreachable]="Repositorio inaccesible (sin comparación de versión): %s"
T_IT[diag.repo_unreachable]="Repository irraggiungibile (nessun confronto di versione): %s"

T_EN[diag.repo_unset]="REPO_RAW not set — no updates or self-healing possible."
T_FR[diag.repo_unset]="REPO_RAW non défini — ni MAJ ni auto-guérison possibles."
T_DE[diag.repo_unset]="REPO_RAW nicht gesetzt — keine Updates oder Selbstheilung möglich."
T_ES[diag.repo_unset]="REPO_RAW no definido — sin actualizaciones ni autocuración posibles."
T_IT[diag.repo_unset]="REPO_RAW non impostato — nessun aggiornamento o autoguarigione possibile."

T_EN[diag.present]="Present: %s"
T_FR[diag.present]="Présent : %s"
T_DE[diag.present]="Vorhanden: %s"
T_ES[diag.present]="Presente: %s"
T_IT[diag.present]="Presente: %s"

T_EN[diag.absent]="Missing: %s"
T_FR[diag.absent]="Absent : %s"
T_DE[diag.absent]="Fehlt: %s"
T_ES[diag.absent]="Ausente: %s"
T_IT[diag.absent]="Assente: %s"

T_EN[diag.update_stale]="Updater not run for %s day(s) — cron.daily/anacron down?"
T_FR[diag.update_stale]="Updater non exécuté depuis %s jour(s) — cron.daily/anacron en panne ?"
T_DE[diag.update_stale]="Updater seit %s Tag(en) nicht gelaufen — cron.daily/anacron defekt?"
T_ES[diag.update_stale]="Updater sin ejecutar desde hace %s día(s) — ¿cron.daily/anacron caído?"
T_IT[diag.update_stale]="Updater non eseguito da %s giorno/i — cron.daily/anacron guasto?"

T_EN[diag.update_fresh]="Updater ran recently (daily update active)."
T_FR[diag.update_fresh]="Updater exécuté récemment (MAJ quotidienne active)."
T_DE[diag.update_fresh]="Updater kürzlich gelaufen (tägliches Update aktiv)."
T_ES[diag.update_fresh]="Updater ejecutado recientemente (actualización diaria activa)."
T_IT[diag.update_fresh]="Updater eseguito di recente (aggiornamento giornaliero attivo)."

T_EN[diag.update_never]="No record of an updater run (stamp missing)."
T_FR[diag.update_never]="Aucune trace d'exécution de l'updater (repère absent)."
T_DE[diag.update_never]="Kein Nachweis eines Updater-Laufs (Marker fehlt)."
T_ES[diag.update_never]="Sin rastro de ejecución del updater (marcador ausente)."
T_IT[diag.update_never]="Nessuna traccia di esecuzione dell'updater (marcatore assente)."

T_EN[diag.anacron_ok]="Daily-cron driver OK (anacron installed and scheduled)."
T_FR[diag.anacron_ok]="Pilote de cron.daily OK (anacron installé et planifié)."
T_DE[diag.anacron_ok]="cron.daily-Treiber OK (anacron installiert und geplant)."
T_ES[diag.anacron_ok]="Driver de cron.daily OK (anacron instalado y planificado)."
T_IT[diag.anacron_ok]="Driver di cron.daily OK (anacron installato e pianificato)."

T_EN[diag.anacron_deferred]="anacron installed but NOT scheduled (timer off) — cron defers cron.daily to it, so it never runs."
T_FR[diag.anacron_deferred]="anacron installé mais NON planifié (timer éteint) — cron lui délègue cron.daily, qui ne se déclenche donc jamais."
T_DE[diag.anacron_deferred]="anacron installiert, aber NICHT eingeplant (Timer aus) — cron delegiert cron.daily an es, es läuft also nie."
T_ES[diag.anacron_deferred]="anacron instalado pero NO planificado (timer apagado) — cron le delega cron.daily, que entonces nunca se ejecuta."
T_IT[diag.anacron_deferred]="anacron installato ma NON pianificato (timer spento) — cron gli delega cron.daily, che quindi non parte mai."

T_EN[diag.anacron_absent_ok]="anacron absent — cron.daily handled by cron at 06:25 (no catch-up; anacron recommended)."
T_FR[diag.anacron_absent_ok]="anacron absent — cron.daily assuré par cron à 06:25 (sans rattrapage ; anacron recommandé)."
T_DE[diag.anacron_absent_ok]="anacron fehlt — cron.daily von cron um 06:25 ausgeführt (kein Nachholen; anacron empfohlen)."
T_ES[diag.anacron_absent_ok]="anacron ausente — cron.daily ejecutado por cron a las 06:25 (sin recuperación; anacron recomendado)."
T_IT[diag.anacron_absent_ok]="anacron assente — cron.daily gestito da cron alle 06:25 (senza recupero; anacron consigliato)."

T_EN[diag.anacron_absent_nocron]="anacron absent and /etc/crontab does not run cron.daily — it will not fire."
T_FR[diag.anacron_absent_nocron]="anacron absent et /etc/crontab ne lance pas cron.daily — il ne se déclenchera pas."
T_DE[diag.anacron_absent_nocron]="anacron fehlt und /etc/crontab führt cron.daily nicht aus — es läuft nicht."
T_ES[diag.anacron_absent_nocron]="anacron ausente y /etc/crontab no ejecuta cron.daily — no se activará."
T_IT[diag.anacron_absent_nocron]="anacron assente e /etc/crontab non esegue cron.daily — non partirà."

T_EN[diag.summary_cron_ok]="Summary cron present (DAILY_SUMMARY enabled)."
T_FR[diag.summary_cron_ok]="Cron de résumé présent (DAILY_SUMMARY activé)."
T_DE[diag.summary_cron_ok]="Zusammenfassungs-Cron vorhanden (DAILY_SUMMARY aktiviert)."
T_ES[diag.summary_cron_ok]="Cron de resumen presente (DAILY_SUMMARY activado)."
T_IT[diag.summary_cron_ok]="Cron del riepilogo presente (DAILY_SUMMARY attivato)."

T_EN[diag.summary_cron_missing_wanted]="Summary cron missing although DAILY_SUMMARY is enabled — will self-heal on the next hourly run."
T_FR[diag.summary_cron_missing_wanted]="Cron de résumé absent alors que DAILY_SUMMARY est activé — auto-guérison au prochain passage horaire."
T_DE[diag.summary_cron_missing_wanted]="Zusammenfassungs-Cron fehlt, obwohl DAILY_SUMMARY aktiviert ist — Selbstheilung beim nächsten stündlichen Lauf."
T_ES[diag.summary_cron_missing_wanted]="Cron de resumen ausente aunque DAILY_SUMMARY está activado — autocuración en la próxima ejecución horaria."
T_IT[diag.summary_cron_missing_wanted]="Cron del riepilogo assente benché DAILY_SUMMARY sia attivato — autoguarigione alla prossima esecuzione oraria."

T_EN[diag.summary_cron_orphan]="Summary cron present although DAILY_SUMMARY is disabled — will be removed on the next hourly run."
T_FR[diag.summary_cron_orphan]="Cron de résumé présent alors que DAILY_SUMMARY est désactivé — sera retiré au prochain passage horaire."
T_DE[diag.summary_cron_orphan]="Zusammenfassungs-Cron vorhanden, obwohl DAILY_SUMMARY deaktiviert ist — wird beim nächsten stündlichen Lauf entfernt."
T_ES[diag.summary_cron_orphan]="Cron de resumen presente aunque DAILY_SUMMARY está desactivado — se eliminará en la próxima ejecución horaria."
T_IT[diag.summary_cron_orphan]="Cron del riepilogo presente benché DAILY_SUMMARY sia disattivato — sarà rimosso alla prossima esecuzione oraria."

T_EN[diag.summary_cron_off]="Summary cron absent (DAILY_SUMMARY disabled)."
T_FR[diag.summary_cron_off]="Cron de résumé absent (DAILY_SUMMARY désactivé)."
T_DE[diag.summary_cron_off]="Zusammenfassungs-Cron nicht vorhanden (DAILY_SUMMARY deaktiviert)."
T_ES[diag.summary_cron_off]="Cron de resumen ausente (DAILY_SUMMARY desactivado)."
T_IT[diag.summary_cron_off]="Cron del riepilogo assente (DAILY_SUMMARY disattivato)."

T_EN[diag.ipset_ok]="ipset %s present (%s members)."
T_FR[diag.ipset_ok]="ipset %s présent (%s membres)."
T_DE[diag.ipset_ok]="ipset %s vorhanden (%s Einträge)."
T_ES[diag.ipset_ok]="ipset %s presente (%s miembros)."
T_IT[diag.ipset_ok]="ipset %s presente (%s membri)."

T_EN[diag.ipset_missing]="ipset %s missing — no bans are enforced."
T_FR[diag.ipset_missing]="ipset %s absent — aucun ban n'est appliqué."
T_DE[diag.ipset_missing]="ipset %s fehlt — keine Sperren aktiv."
T_ES[diag.ipset_missing]="ipset %s ausente — no se aplica ningún bloqueo."
T_IT[diag.ipset_missing]="ipset %s assente — nessun blocco applicato."

T_EN[diag.iptables_ok]="iptables INPUT DROP rule present."
T_FR[diag.iptables_ok]="Règle iptables INPUT DROP présente."
T_DE[diag.iptables_ok]="iptables INPUT-DROP-Regel vorhanden."
T_ES[diag.iptables_ok]="Regla iptables INPUT DROP presente."
T_IT[diag.iptables_ok]="Regola iptables INPUT DROP presente."

T_EN[diag.iptables_missing]="iptables INPUT DROP rule missing — bans are not enforced."
T_FR[diag.iptables_missing]="Règle iptables INPUT DROP absente — les bans ne sont pas appliqués."
T_DE[diag.iptables_missing]="iptables INPUT-DROP-Regel fehlt — Sperren werden nicht durchgesetzt."
T_ES[diag.iptables_missing]="Regla iptables INPUT DROP ausente — los bloqueos no se aplican."
T_IT[diag.iptables_missing]="Regola iptables INPUT DROP assente — i blocchi non vengono applicati."

T_EN[diag.persist_ok]="Firewall persistence present (ipset + rules.v4)."
T_FR[diag.persist_ok]="Persistance du pare-feu présente (ipset + rules.v4)."
T_DE[diag.persist_ok]="Firewall-Persistenz vorhanden (ipset + rules.v4)."
T_ES[diag.persist_ok]="Persistencia del firewall presente (ipset + rules.v4)."
T_IT[diag.persist_ok]="Persistenza del firewall presente (ipset + rules.v4)."

T_EN[diag.persist_missing]="Firewall persistence incomplete — bans may be lost on reboot."
T_FR[diag.persist_missing]="Persistance du pare-feu incomplète — les bans risquent d'être perdus au reboot."
T_DE[diag.persist_missing]="Firewall-Persistenz unvollständig — Sperren gehen beim Neustart evtl. verloren."
T_ES[diag.persist_missing]="Persistencia del firewall incompleta — los bloqueos pueden perderse al reiniciar."
T_IT[diag.persist_missing]="Persistenza del firewall incompleta — i blocchi potrebbero perdersi al riavvio."

T_EN[diag.root_skip]="Firewall checks skipped (root required)."
T_FR[diag.root_skip]="Contrôles pare-feu ignorés (root requis)."
T_DE[diag.root_skip]="Firewall-Prüfungen übersprungen (root erforderlich)."
T_ES[diag.root_skip]="Comprobaciones del firewall omitidas (se requiere root)."
T_IT[diag.root_skip]="Controlli firewall ignorati (root richiesto)."

T_EN[diag.logs]="Logs: %s active, %s inactive/empty, %s unreadable, %s excluded."
T_FR[diag.logs]="Logs : %s actifs, %s inactifs/vides, %s illisibles, %s exclus."
T_DE[diag.logs]="Logs: %s aktiv, %s inaktiv/leer, %s nicht lesbar, %s ausgeschlossen."
T_ES[diag.logs]="Logs: %s activos, %s inactivos/vacíos, %s ilegibles, %s excluidos."
T_IT[diag.logs]="Log: %s attivi, %s inattivi/vuoti, %s illeggibili, %s esclusi."

T_EN[diag.log_v_nolog]="   - %s: no access.log (inactive site)"
T_FR[diag.log_v_nolog]="   - %s : aucun access.log (site inactif)"
T_DE[diag.log_v_nolog]="   - %s: kein access.log (inaktive Site)"
T_ES[diag.log_v_nolog]="   - %s: sin access.log (sitio inactivo)"
T_IT[diag.log_v_nolog]="   - %s: nessun access.log (sito inattivo)"

T_EN[diag.log_v_broken]="   - %s: broken access.log symlink (inactive site)"
T_FR[diag.log_v_broken]="   - %s : symlink access.log cassé (site inactif)"
T_DE[diag.log_v_broken]="   - %s: defekter access.log-Symlink (inaktive Site)"
T_ES[diag.log_v_broken]="   - %s: symlink access.log roto (sitio inactivo)"
T_IT[diag.log_v_broken]="   - %s: symlink access.log rotto (sito inattivo)"

T_EN[diag.log_v_empty]="   - %s: empty access.log (inactive site)"
T_FR[diag.log_v_empty]="   - %s : access.log vide (site inactif)"
T_DE[diag.log_v_empty]="   - %s: leeres access.log (inaktive Site)"
T_ES[diag.log_v_empty]="   - %s: access.log vacío (sitio inactivo)"
T_IT[diag.log_v_empty]="   - %s: access.log vuoto (sito inattivo)"

T_EN[diag.log_v_unreadable]="   - %s: access.log present but NOT READABLE (permission)"
T_FR[diag.log_v_unreadable]="   - %s : access.log présent mais NON LISIBLE (permission)"
T_DE[diag.log_v_unreadable]="   - %s: access.log vorhanden, aber NICHT LESBAR (Rechte)"
T_ES[diag.log_v_unreadable]="   - %s: access.log presente pero NO LEGIBLE (permisos)"
T_IT[diag.log_v_unreadable]="   - %s: access.log presente ma NON LEGGIBILE (permessi)"

T_EN[diag.notify_channels]="Notification channels configured: %s."
T_FR[diag.notify_channels]="Canaux de notification configurés : %s."
T_DE[diag.notify_channels]="Konfigurierte Benachrichtigungskanäle: %s."
T_ES[diag.notify_channels]="Canales de notificación configurados: %s."
T_IT[diag.notify_channels]="Canali di notifica configurati: %s."

T_EN[diag.notify_none]="No notification channel configured (optional)."
T_FR[diag.notify_none]="Aucun canal de notification configuré (optionnel)."
T_DE[diag.notify_none]="Kein Benachrichtigungskanal konfiguriert (optional)."
T_ES[diag.notify_none]="Ningún canal de notificación configurado (opcional)."
T_IT[diag.notify_none]="Nessun canale di notifica configurato (opzionale)."

T_EN[diag.notify_orphan_bans]="NOTIFY_BANS is enabled but no channel is configured."
T_FR[diag.notify_orphan_bans]="NOTIFY_BANS est activé mais aucun canal n'est configuré."
T_DE[diag.notify_orphan_bans]="NOTIFY_BANS ist aktiviert, aber kein Kanal konfiguriert."
T_ES[diag.notify_orphan_bans]="NOTIFY_BANS está activado pero no hay ningún canal configurado."
T_IT[diag.notify_orphan_bans]="NOTIFY_BANS è attivato ma nessun canale è configurato."

T_EN[diag.notify_orphan_summary]="DAILY_SUMMARY is enabled but no channel is configured."
T_FR[diag.notify_orphan_summary]="DAILY_SUMMARY est activé mais aucun canal n'est configuré."
T_DE[diag.notify_orphan_summary]="DAILY_SUMMARY ist aktiviert, aber kein Kanal konfiguriert."
T_ES[diag.notify_orphan_summary]="DAILY_SUMMARY está activado pero no hay ningún canal configurado."
T_IT[diag.notify_orphan_summary]="DAILY_SUMMARY è attivato ma nessun canale è configurato."

T_EN[diag.tally_clean]="All checks passed — no anomaly detected."
T_FR[diag.tally_clean]="Tous les contrôles passent — aucune anomalie détectée."
T_DE[diag.tally_clean]="Alle Prüfungen bestanden — keine Anomalie erkannt."
T_ES[diag.tally_clean]="Todas las comprobaciones pasaron — ninguna anomalía detectada."
T_IT[diag.tally_clean]="Tutti i controlli superati — nessuna anomalia rilevata."

T_EN[diag.tally_problems]="%s anomaly(ies) detected — see the [WARN]/[FAIL] lines above."
T_FR[diag.tally_problems]="%s anomalie(s) détectée(s) — voir les lignes [WARN]/[FAIL] ci-dessus."
T_DE[diag.tally_problems]="%s Anomalie(n) erkannt — siehe die [WARN]/[FAIL]-Zeilen oben."
T_ES[diag.tally_problems]="%s anomalía(s) detectada(s) — vea las líneas [WARN]/[FAIL] de arriba."
T_IT[diag.tally_problems]="%s anomalia(e) rilevata(e) — vedere le righe [WARN]/[FAIL] qui sopra."

# --- Aide : section configuration (/etc/ban_404.conf) ---
T_EN[help.conf_header]="Configuration: %s (overrides defaults; never overwritten by updates)"
T_FR[help.conf_header]="Configuration : %s (surcharge les valeurs par défaut ; jamais écrasée par les MAJ)"
T_DE[help.conf_header]="Konfiguration: %s (überschreibt Standardwerte; wird von Updates nie überschrieben)"
T_ES[help.conf_header]="Configuración: %s (sobrescribe los valores por defecto; nunca sobrescrita por las actualizaciones)"
T_IT[help.conf_header]="Configurazione: %s (sovrascrive i valori predefiniti; mai sovrascritta dagli aggiornamenti)"

T_EN[help.conf_repo_raw]="  REPO_RAW         Repo raw URL used by the self-updater (required)."
T_FR[help.conf_repo_raw]="  REPO_RAW         URL raw du dépôt, utilisée par le self-updater (requis)."
T_DE[help.conf_repo_raw]="  REPO_RAW         Raw-URL des Repos für den Self-Updater (erforderlich)."
T_ES[help.conf_repo_raw]="  REPO_RAW         URL raw del repositorio para el self-updater (obligatorio)."
T_IT[help.conf_repo_raw]="  REPO_RAW         URL raw del repository per il self-updater (obbligatorio)."

T_EN[help.conf_whitelist_ip]="  WHITELIST_IP     IPs never banned, exact match, '|'-separated (default 127.0.0.1)."
T_FR[help.conf_whitelist_ip]="  WHITELIST_IP     IP jamais bannies, exactes, séparées par '|' (défaut 127.0.0.1)."
T_DE[help.conf_whitelist_ip]="  WHITELIST_IP     Nie gesperrte IPs, exakt, '|'-getrennt (Standard 127.0.0.1)."
T_ES[help.conf_whitelist_ip]="  WHITELIST_IP     IP nunca bloqueadas, exactas, separadas por '|' (por defecto 127.0.0.1)."
T_IT[help.conf_whitelist_ip]="  WHITELIST_IP     IP mai bloccati, esatti, separati da '|' (predefinito 127.0.0.1)."

T_EN[help.conf_whitelist_cidr]="  WHITELIST_CIDR   Subnets never banned, CIDR '|'-separated (e.g. 10.0.0.0/8|192.168.0.0/16)."
T_FR[help.conf_whitelist_cidr]="  WHITELIST_CIDR   Sous-réseaux jamais bannis, CIDR séparés par '|' (ex. 10.0.0.0/8|192.168.0.0/16)."
T_DE[help.conf_whitelist_cidr]="  WHITELIST_CIDR   Nie gesperrte Subnetze, CIDR '|'-getrennt (z. B. 10.0.0.0/8|192.168.0.0/16)."
T_ES[help.conf_whitelist_cidr]="  WHITELIST_CIDR   Subredes nunca bloqueadas, CIDR separadas por '|' (ej. 10.0.0.0/8|192.168.0.0/16)."
T_IT[help.conf_whitelist_cidr]="  WHITELIST_CIDR   Sottoreti mai bloccate, CIDR separati da '|' (es. 10.0.0.0/8|192.168.0.0/16)."

T_EN[help.conf_exclude_vhosts]="  EXCLUDE_VHOSTS   Vhosts excluded from analysis, dir names '|'-separated (e.g. staging.example.com)."
T_FR[help.conf_exclude_vhosts]="  EXCLUDE_VHOSTS   Vhosts exclus de l'analyse, noms de dossier séparés par '|' (ex. staging.exemple.com)."
T_DE[help.conf_exclude_vhosts]="  EXCLUDE_VHOSTS   Von der Analyse ausgeschlossene Vhosts, Verzeichnisnamen '|'-getrennt (z. B. staging.example.com)."
T_ES[help.conf_exclude_vhosts]="  EXCLUDE_VHOSTS   Vhosts excluidos del análisis, nombres de carpeta separados por '|' (ej. staging.example.com)."
T_IT[help.conf_exclude_vhosts]="  EXCLUDE_VHOSTS   Vhost esclusi dall'analisi, nomi di cartella separati da '|' (es. staging.example.com)."

T_EN[help.conf_lang]="  BAN404_LANG      Message language: en, fr, de, es, it (default: auto-detected)."
T_FR[help.conf_lang]="  BAN404_LANG      Langue des messages : en, fr, de, es, it (défaut : auto-détectée)."
T_DE[help.conf_lang]="  BAN404_LANG      Sprache der Meldungen: en, fr, de, es, it (Standard: automatisch)."
T_ES[help.conf_lang]="  BAN404_LANG      Idioma de los mensajes: en, fr, de, es, it (por defecto: autodetectado)."
T_IT[help.conf_lang]="  BAN404_LANG      Lingua dei messaggi: en, fr, de, es, it (predefinito: rilevamento automatico)."

T_EN[help.conf_window]="  WINDOW           Sliding window in seconds for counting 404s (default 7200 = 2h)."
T_FR[help.conf_window]="  WINDOW           Fenêtre glissante en s pour compter les 404 (défaut 7200 = 2h)."
T_DE[help.conf_window]="  WINDOW           Gleitendes Fenster in s zum Zählen der 404 (Standard 7200 = 2h)."
T_ES[help.conf_window]="  WINDOW           Ventana deslizante en s para contar los 404 (por defecto 7200 = 2h)."
T_IT[help.conf_window]="  WINDOW           Finestra scorrevole in s per contare i 404 (predefinito 7200 = 2h)."

T_EN[help.conf_ban_timeout]="  BAN_TIMEOUT      Ban duration in seconds (default 172800 = 48h)."
T_FR[help.conf_ban_timeout]="  BAN_TIMEOUT      Durée du ban en s (défaut 172800 = 48h)."
T_DE[help.conf_ban_timeout]="  BAN_TIMEOUT      Sperrdauer in Sekunden (Standard 172800 = 48h)."
T_ES[help.conf_ban_timeout]="  BAN_TIMEOUT      Duración del bloqueo en s (por defecto 172800 = 48h)."
T_IT[help.conf_ban_timeout]="  BAN_TIMEOUT      Durata del blocco in s (predefinito 172800 = 48h)."

T_EN[help.conf_tail]="  TAIL_LINES       Lines analyzed per log file (default 50000)."
T_FR[help.conf_tail]="  TAIL_LINES       Lignes analysées par fichier log (défaut 50000)."
T_DE[help.conf_tail]="  TAIL_LINES       Analysierte Zeilen pro Log-Datei (Standard 50000)."
T_ES[help.conf_tail]="  TAIL_LINES       Líneas analizadas por archivo de registro (por defecto 50000)."
T_IT[help.conf_tail]="  TAIL_LINES       Righe analizzate per file di log (predefinito 50000)."

T_EN[help.conf_threshold]="  BAN_THRESHOLD    Ban when the score exceeds this in the window (default 10)."
T_FR[help.conf_threshold]="  BAN_THRESHOLD    Ban si le score dépasse ce seuil dans la fenêtre (défaut 10)."
T_DE[help.conf_threshold]="  BAN_THRESHOLD    Sperre, wenn der Score dies im Fenster überschreitet (Standard 10)."
T_ES[help.conf_threshold]="  BAN_THRESHOLD    Bloquear si el score supera este umbral en la ventana (por defecto 10)."
T_IT[help.conf_threshold]="  BAN_THRESHOLD    Blocco se il punteggio supera questa soglia nella finestra (predefinito 10)."

T_EN[help.conf_honeypot_score]="  HONEYPOT_SCORE   Score per honeypot hit; >= this means instant ban (default 100)."
T_FR[help.conf_honeypot_score]="  HONEYPOT_SCORE   Score par hit honeypot ; >= ce score => ban immédiat (défaut 100)."
T_DE[help.conf_honeypot_score]="  HONEYPOT_SCORE   Score pro Honeypot-Treffer; >= bedeutet Sofortsperre (Standard 100)."
T_ES[help.conf_honeypot_score]="  HONEYPOT_SCORE   Score por hit honeypot; >= significa bloqueo inmediato (por defecto 100)."
T_IT[help.conf_honeypot_score]="  HONEYPOT_SCORE   Punteggio per hit honeypot; >= significa blocco immediato (predefinito 100)."

T_EN[help.conf_honeypot_timeout]="  HONEYPOT_BAN_TIMEOUT  Ban duration (s) for honeypot hits (default 604800 = 7 days)."
T_FR[help.conf_honeypot_timeout]="  HONEYPOT_BAN_TIMEOUT  Durée du ban (s) pour les hits honeypot (défaut 604800 = 7 jours)."
T_DE[help.conf_honeypot_timeout]="  HONEYPOT_BAN_TIMEOUT  Sperrdauer (s) für Honeypot-Treffer (Standard 604800 = 7 Tage)."
T_ES[help.conf_honeypot_timeout]="  HONEYPOT_BAN_TIMEOUT  Duración del bloqueo (s) para hits honeypot (por defecto 604800 = 7 días)."
T_IT[help.conf_honeypot_timeout]="  HONEYPOT_BAN_TIMEOUT  Durata del blocco (s) per gli hit honeypot (predefinito 604800 = 7 giorni)."

T_EN[help.conf_nickname]="  SERVER_NICKNAME  Friendly server name shown with the hostname in notifications (empty = hostname only)."
T_FR[help.conf_nickname]="  SERVER_NICKNAME  Nom convivial affiché avec le hostname dans les notifications (vide = hostname seul)."
T_DE[help.conf_nickname]="  SERVER_NICKNAME  Anzeigename des Servers, zusammen mit dem Hostnamen in Benachrichtigungen (leer = nur Hostname)."
T_ES[help.conf_nickname]="  SERVER_NICKNAME  Nombre descriptivo mostrado junto al hostname en las notificaciones (vacío = solo hostname)."
T_IT[help.conf_nickname]="  SERVER_NICKNAME  Nome descrittivo mostrato con l'hostname nelle notifiche (vuoto = solo hostname)."

T_EN[help.conf_webhook]="  WEBHOOK_URL      JSON POST of new bans (Slack/Discord/Teams/Google Chat...); empty = off."
T_FR[help.conf_webhook]="  WEBHOOK_URL      POST JSON des nouveaux bans (Slack/Discord/Teams/Google Chat...) ; vide = inactif."
T_DE[help.conf_webhook]="  WEBHOOK_URL      JSON-POST neuer Sperren (Slack/Discord/Teams/Google Chat...); leer = aus."
T_ES[help.conf_webhook]="  WEBHOOK_URL      POST JSON de nuevos bloqueos (Slack/Discord/Teams/Google Chat...); vacío = inactivo."
T_IT[help.conf_webhook]="  WEBHOOK_URL      POST JSON dei nuovi blocchi (Slack/Discord/Teams/Google Chat...); vuoto = disattivato."

T_EN[help.conf_email]="  NOTIFY_EMAIL     E-mail of new bans (needs an MTA: mail/sendmail); empty = off."
T_FR[help.conf_email]="  NOTIFY_EMAIL     E-mail des nouveaux bans (MTA requis : mail/sendmail) ; vide = inactif."
T_DE[help.conf_email]="  NOTIFY_EMAIL     E-Mail neuer Sperren (MTA nötig: mail/sendmail); leer = aus."
T_ES[help.conf_email]="  NOTIFY_EMAIL     E-mail de nuevos bloqueos (requiere un MTA: mail/sendmail); vacío = inactivo."
T_IT[help.conf_email]="  NOTIFY_EMAIL     E-mail dei nuovi blocchi (richiede un MTA: mail/sendmail); vuoto = disattivato."

T_EN[help.conf_from]="  NOTIFY_FROM      E-mail sender (optional)."
T_FR[help.conf_from]="  NOTIFY_FROM      Expéditeur e-mail (optionnel)."
T_DE[help.conf_from]="  NOTIFY_FROM      E-Mail-Absender (optional)."
T_ES[help.conf_from]="  NOTIFY_FROM      Remitente del e-mail (opcional)."
T_IT[help.conf_from]="  NOTIFY_FROM      Mittente e-mail (opzionale)."

T_EN[help.conf_min_bans]="  NOTIFY_MIN_BANS  Notify only if at least N new bans in the run (default 1)."
T_FR[help.conf_min_bans]="  NOTIFY_MIN_BANS  Notifier seulement si au moins N nouveaux bans dans le run (défaut 1)."
T_DE[help.conf_min_bans]="  NOTIFY_MIN_BANS  Nur benachrichtigen bei mindestens N neuen Sperren pro Lauf (Standard 1)."
T_ES[help.conf_min_bans]="  NOTIFY_MIN_BANS  Notificar solo si hay al menos N nuevos bloqueos en la ejecución (por defecto 1)."
T_IT[help.conf_min_bans]="  NOTIFY_MIN_BANS  Notificare solo se almeno N nuovi blocchi nell'esecuzione (predefinito 1)."

T_EN[help.conf_notify_bans]="  NOTIFY_BANS      Per-run alert when IPs are banned (default false; true to enable)."
T_FR[help.conf_notify_bans]="  NOTIFY_BANS      Alerte par run quand des IP sont bannies (défaut false ; true pour activer)."
T_DE[help.conf_notify_bans]="  NOTIFY_BANS      Pro-Lauf-Warnung, wenn IPs gesperrt werden (Standard false; true zum Aktivieren)."
T_ES[help.conf_notify_bans]="  NOTIFY_BANS      Alerta por ejecución cuando se bloquean IP (por defecto false; true para activar)."
T_IT[help.conf_notify_bans]="  NOTIFY_BANS      Avviso a ogni esecuzione quando degli IP vengono bloccati (predefinito false; true per attivare)."

T_EN[help.conf_daily]="  DAILY_SUMMARY    Daily summary (opt-in, default false), via the configured channel."
T_FR[help.conf_daily]="  DAILY_SUMMARY    Résumé quotidien (opt-in, défaut false), via le canal configuré."
T_DE[help.conf_daily]="  DAILY_SUMMARY    Tägliche Zusammenfassung (opt-in, Standard false), über den konfigurierten Kanal."
T_ES[help.conf_daily]="  DAILY_SUMMARY    Resumen diario (opt-in, por defecto false), por el canal configurado."
T_IT[help.conf_daily]="  DAILY_SUMMARY    Riepilogo giornaliero (opt-in, predefinito false), tramite il canale configurato."

T_EN[help.conf_resolve]="  RESOLVE_PTR      Resolve reverse DNS (PTR) in --list/--stats/--summary (default false)."
T_FR[help.conf_resolve]="  RESOLVE_PTR      Résoudre le reverse DNS (PTR) dans --list/--stats/--summary (défaut false)."
T_DE[help.conf_resolve]="  RESOLVE_PTR      Reverse-DNS (PTR) in --list/--stats/--summary auflösen (Standard false)."
T_ES[help.conf_resolve]="  RESOLVE_PTR      Resolver el DNS inverso (PTR) en --list/--stats/--summary (por defecto false)."
T_IT[help.conf_resolve]="  RESOLVE_PTR      Risolvere il reverse DNS (PTR) in --list/--stats/--summary (predefinito false)."

T_EN[help.conf_ptr_timeout]="  PTR_TIMEOUT      Max seconds per reverse-DNS lookup (default 2)."
T_FR[help.conf_ptr_timeout]="  PTR_TIMEOUT      Délai max par requête reverse DNS, en s (défaut 2)."
T_DE[help.conf_ptr_timeout]="  PTR_TIMEOUT      Max. Sekunden pro Reverse-DNS-Abfrage (Standard 2)."
T_ES[help.conf_ptr_timeout]="  PTR_TIMEOUT      Segundos máx. por consulta de DNS inverso (por defecto 2)."
T_IT[help.conf_ptr_timeout]="  PTR_TIMEOUT      Secondi max per query reverse DNS (predefinito 2)."

T_EN[help.conf_advanced]="  Advanced: HONEYPOT_PATTERN / NOISE_PATTERN (awk regex) — override with care."
T_FR[help.conf_advanced]="  Avancé : HONEYPOT_PATTERN / NOISE_PATTERN (regex awk) — surcharger avec prudence."
T_DE[help.conf_advanced]="  Erweitert: HONEYPOT_PATTERN / NOISE_PATTERN (awk-Regex) — mit Bedacht ändern."
T_ES[help.conf_advanced]="  Avanzado: HONEYPOT_PATTERN / NOISE_PATTERN (regex awk) — sobrescribir con cuidado."
T_IT[help.conf_advanced]="  Avanzato: HONEYPOT_PATTERN / NOISE_PATTERN (regex awk) — sovrascrivere con cautela."

T_EN[help.conf_example_pointer]="  See ban_404.conf.example for full documentation and defaults."
T_FR[help.conf_example_pointer]="  Voir ban_404.conf.example pour la doc complète et les valeurs par défaut."
T_DE[help.conf_example_pointer]="  Siehe ban_404.conf.example für vollständige Doku und Standardwerte."
T_ES[help.conf_example_pointer]="  Vea ban_404.conf.example para la documentación completa y los valores por defecto."
T_IT[help.conf_example_pointer]="  Vedere ban_404.conf.example per la documentazione completa e i valori predefiniti."

T_EN[list.header]="Currently banned IPs (ipset %s):"
T_FR[list.header]="IP actuellement bannies (ipset %s) :"
T_DE[list.header]="Aktuell gesperrte IPs (ipset %s):"
T_ES[list.header]="IP actualmente bloqueadas (ipset %s):"
T_IT[list.header]="IP attualmente bloccati (ipset %s):"

T_EN[list.empty]="No IP currently banned."
T_FR[list.empty]="Aucune IP actuellement bannie."
T_DE[list.empty]="Derzeit keine IP gesperrt."
T_ES[list.empty]="Ninguna IP bloqueada actualmente."
T_IT[list.empty]="Nessun IP attualmente bloccato."

T_EN[list.item]="  %s  (timeout: %s s)"
T_FR[list.item]="  %s  (timeout : %s s)"
T_DE[list.item]="  %s  (Timeout: %s s)"
T_ES[list.item]="  %s  (timeout: %s s)"
T_IT[list.item]="  %s  (timeout: %s s)"

T_EN[list.item_rdns]="  %s  (timeout: %s s)  [%s]"
T_FR[list.item_rdns]="  %s  (timeout : %s s)  [%s]"
T_DE[list.item_rdns]="  %s  (Timeout: %s s)  [%s]"
T_ES[list.item_rdns]="  %s  (timeout: %s s)  [%s]"
T_IT[list.item_rdns]="  %s  (timeout: %s s)  [%s]"

T_EN[stats.header]="ban-404 · report"
T_FR[stats.header]="ban-404 · rapport"
T_DE[stats.header]="ban-404 · Bericht"
T_ES[stats.header]="ban-404 · informe"
T_IT[stats.header]="ban-404 · rapporto"

T_EN[stats.versions]="Versions: engine v%s · updater v%s"
T_FR[stats.versions]="Versions : moteur v%s · updater v%s"
T_DE[stats.versions]="Versionen: Engine v%s · Updater v%s"
T_ES[stats.versions]="Versiones: motor v%s · updater v%s"
T_IT[stats.versions]="Versioni: motore v%s · updater v%s"

T_EN[stats.health_header]="Health (anomalies):"
T_FR[stats.health_header]="Santé (anomalies) :"
T_DE[stats.health_header]="Zustand (Anomalien):"
T_ES[stats.health_header]="Estado (anomalías):"
T_IT[stats.health_header]="Stato (anomalie):"

T_EN[stats.health_ok]="Health: no anomaly detected."
T_FR[stats.health_ok]="Santé : aucune anomalie détectée."
T_DE[stats.health_ok]="Zustand: keine Anomalie erkannt."
T_ES[stats.health_ok]="Estado: ninguna anomalía detectada."
T_IT[stats.health_ok]="Stato: nessuna anomalia rilevata."

T_EN[stats.sec_stats]="Statistics (24h)"
T_FR[stats.sec_stats]="Statistiques (24h)"
T_DE[stats.sec_stats]="Statistiken (24h)"
T_ES[stats.sec_stats]="Estadísticas (24h)"
T_IT[stats.sec_stats]="Statistiche (24h)"

T_EN[stats.banned_now]="Currently banned: %s IP(s)"
T_FR[stats.banned_now]="Actuellement bannies : %s IP"
T_DE[stats.banned_now]="Aktuell gesperrt: %s IP(s)"
T_ES[stats.banned_now]="Actualmente bloqueadas: %s IP"
T_IT[stats.banned_now]="Attualmente bloccati: %s IP"

T_EN[stats.bans_unbans]="New bans: %s · unbans: %s"
T_FR[stats.bans_unbans]="Nouveaux bans : %s · Débans : %s"
T_DE[stats.bans_unbans]="Neue Sperren: %s · Entsperrungen: %s"
T_ES[stats.bans_unbans]="Nuevos bloqueos: %s · Desbloqueos: %s"
T_IT[stats.bans_unbans]="Nuovi blocchi: %s · Sblocchi: %s"

T_EN[stats.top_header]="Top 404 (24h)"
T_FR[stats.top_header]="Top 404 (24h)"
T_DE[stats.top_header]="Top 404 (24h)"
T_ES[stats.top_header]="Top 404 (24h)"
T_IT[stats.top_header]="Top 404 (24h)"

T_EN[stats.top_hp_header]="Top honeypot (24h)"
T_FR[stats.top_hp_header]="Top honeypot (24h)"
T_DE[stats.top_hp_header]="Top honeypot (24h)"
T_ES[stats.top_hp_header]="Top honeypot (24h)"
T_IT[stats.top_hp_header]="Top honeypot (24h)"

T_EN[stats.top_item]="%s — %s 404 errors"
T_FR[stats.top_item]="%s — %s erreurs 404"
T_DE[stats.top_item]="%s — %s 404-Fehler"
T_ES[stats.top_item]="%s — %s errores 404"
T_IT[stats.top_item]="%s — %s errori 404"

T_EN[stats.top_item_rdns]="%s — %s 404 errors  [%s]"
T_FR[stats.top_item_rdns]="%s — %s erreurs 404  [%s]"
T_DE[stats.top_item_rdns]="%s — %s 404-Fehler  [%s]"
T_ES[stats.top_item_rdns]="%s — %s errores 404  [%s]"
T_IT[stats.top_item_rdns]="%s — %s errori 404  [%s]"

T_EN[stats.top_item_hp]="%s — honeypot"
T_FR[stats.top_item_hp]="%s — honeypot"
T_DE[stats.top_item_hp]="%s — honeypot"
T_ES[stats.top_item_hp]="%s — honeypot"
T_IT[stats.top_item_hp]="%s — honeypot"

T_EN[stats.top_item_hp_rdns]="%s — honeypot  [%s]"
T_FR[stats.top_item_hp_rdns]="%s — honeypot  [%s]"
T_DE[stats.top_item_hp_rdns]="%s — honeypot  [%s]"
T_ES[stats.top_item_hp_rdns]="%s — honeypot  [%s]"
T_IT[stats.top_item_hp_rdns]="%s — honeypot  [%s]"

T_EN[stats.top_item_hp_score]="%s — score %s"
T_FR[stats.top_item_hp_score]="%s — score %s"
T_DE[stats.top_item_hp_score]="%s — Score %s"
T_ES[stats.top_item_hp_score]="%s — puntuación %s"
T_IT[stats.top_item_hp_score]="%s — punteggio %s"

T_EN[stats.top_item_hp_score_rdns]="%s — score %s  [%s]"
T_FR[stats.top_item_hp_score_rdns]="%s — score %s  [%s]"
T_DE[stats.top_item_hp_score_rdns]="%s — Score %s  [%s]"
T_ES[stats.top_item_hp_score_rdns]="%s — puntuación %s  [%s]"
T_IT[stats.top_item_hp_score_rdns]="%s — punteggio %s  [%s]"

T_EN[cidr.unban]="[-] Unbanning IP (whitelisted CIDR): %s (score %s)"
T_FR[cidr.unban]="[-] Déblocage de l'IP (CIDR en liste blanche) : %s (score %s)"
T_DE[cidr.unban]="[-] Entsperrung der IP (CIDR auf Whitelist): %s (Score %s)"
T_ES[cidr.unban]="[-] Desbloqueo de la IP (CIDR en lista blanca): %s (puntuación %s)"
T_IT[cidr.unban]="[-] Sblocco dell'IP (CIDR in whitelist): %s (punteggio %s)"

T_EN[cidr.sim_unban]="[SIMULATION] [-] IP %s would be UNBANNED (whitelisted CIDR)."
T_FR[cidr.sim_unban]="[SIMULATION] [-] L'IP %s aurait été DÉBANNIE (CIDR en liste blanche)."
T_DE[cidr.sim_unban]="[SIMULATION] [-] IP %s würde ENTSPERRT (CIDR auf Whitelist)."
T_ES[cidr.sim_unban]="[SIMULATION] [-] La IP %s sería DESBLOQUEADA (CIDR en lista blanca)."
T_IT[cidr.sim_unban]="[SIMULATION] [-] L'IP %s verrebbe SBLOCCATO (CIDR in whitelist)."

T_EN[cidr.skip]="[SKIP] Whitelisted CIDR, not blocked: %s"
T_FR[cidr.skip]="[SKIP] CIDR en liste blanche, non bloqué : %s"
T_DE[cidr.skip]="[SKIP] CIDR auf Whitelist, nicht gesperrt: %s"
T_ES[cidr.skip]="[SKIP] CIDR en lista blanca, no bloqueado: %s"
T_IT[cidr.skip]="[SKIP] CIDR in whitelist, non bloccato: %s"

T_EN[wl.unban]="[-] Unbanning IP (whitelisted): %s"
T_FR[wl.unban]="[-] Déblocage de l'IP (liste blanche) : %s"
T_DE[wl.unban]="[-] Entsperrung der IP (Whitelist): %s"
T_ES[wl.unban]="[-] Desbloqueo de la IP (lista blanca): %s"
T_IT[wl.unban]="[-] Sblocco dell'IP (whitelist): %s"

T_EN[wl.sim_unban]="[SIMULATION] [-] IP %s would be UNBANNED (whitelisted)."
T_FR[wl.sim_unban]="[SIMULATION] [-] L'IP %s aurait été DÉBANNIE (liste blanche)."
T_DE[wl.sim_unban]="[SIMULATION] [-] IP %s würde ENTSPERRT (Whitelist)."
T_ES[wl.sim_unban]="[SIMULATION] [-] La IP %s sería DESBLOQUEADA (lista blanca)."
T_IT[wl.sim_unban]="[SIMULATION] [-] L'IP %s verrebbe SBLOCCATO (whitelist)."

T_EN[unban.missing]="--unban requires an IP or 'all'."
T_FR[unban.missing]="--unban requiert une IP ou 'all'."
T_DE[unban.missing]="--unban erfordert eine IP oder 'all'."
T_ES[unban.missing]="--unban requiere una IP o 'all'."
T_IT[unban.missing]="--unban richiede un IP o 'all'."

T_EN[unban.needroot]="--unban requires root privileges (use sudo)."
T_FR[unban.needroot]="--unban requiert les privilèges root (utilisez sudo)."
T_DE[unban.needroot]="--unban erfordert Root-Rechte (sudo verwenden)."
T_ES[unban.needroot]="--unban requiere privilegios de root (use sudo)."
T_IT[unban.needroot]="--unban richiede i privilegi di root (usare sudo)."

T_EN[unban.noset]="ipset %s does not exist — nothing to unban."
T_FR[unban.noset]="l'ipset %s n'existe pas — rien à débannir."
T_DE[unban.noset]="ipset %s existiert nicht — nichts zu entsperren."
T_ES[unban.noset]="el ipset %s no existe — nada que desbloquear."
T_IT[unban.noset]="l'ipset %s non esiste — niente da sbloccare."

T_EN[unban.done]="[-] IP %s removed from the ban list."
T_FR[unban.done]="[-] IP %s retirée de la liste de bannissement."
T_DE[unban.done]="[-] IP %s von der Sperrliste entfernt."
T_ES[unban.done]="[-] IP %s eliminada de la lista de bloqueo."
T_IT[unban.done]="[-] IP %s rimossa dalla lista di blocco."

T_EN[unban.all_done]="[-] All bans removed (%s IP(s) cleared)."
T_FR[unban.all_done]="[-] Tous les bans retirés (%s IP effacée(s))."
T_DE[unban.all_done]="[-] Alle Sperren entfernt (%s IP(s) gelöscht)."
T_ES[unban.all_done]="[-] Todos los bloqueos eliminados (%s IP borrada(s))."
T_IT[unban.all_done]="[-] Tutti i ban rimossi (%s IP cancellati)."

T_EN[unban.notfound]="IP %s is not in the ban list."
T_FR[unban.notfound]="L'IP %s n'est pas dans la liste de bannissement."
T_DE[unban.notfound]="IP %s ist nicht in der Sperrliste."
T_ES[unban.notfound]="La IP %s no está en la lista de bloqueo."
T_IT[unban.notfound]="L'IP %s non è nella lista di blocco."

T_EN[unban.fail]="Failed to unban %s (ipset error)."
T_FR[unban.fail]="Échec du débannissement de %s (erreur ipset)."
T_DE[unban.fail]="Entsperren von %s fehlgeschlagen (ipset-Fehler)."
T_ES[unban.fail]="Error al desbloquear %s (error de ipset)."
T_IT[unban.fail]="Sblocco di %s non riuscito (errore ipset)."

T_EN[notify.subject]="ban-404 [%s]: %s new IP(s) banned"
T_FR[notify.subject]="ban-404 [%s] : %s nouvelle(s) IP bannie(s)"
T_DE[notify.subject]="ban-404 [%s]: %s neue IP(s) gesperrt"
T_ES[notify.subject]="ban-404 [%s]: %s nueva(s) IP bloqueada(s)"
T_IT[notify.subject]="ban-404 [%s]: %s nuovo/i IP bloccato/i"

T_EN[notify.body_header]="%s new IP(s) banned on %s:"
T_FR[notify.body_header]="%s nouvelle(s) IP bannie(s) sur %s :"
T_DE[notify.body_header]="%s neue IP(s) auf %s gesperrt:"
T_ES[notify.body_header]="%s nueva(s) IP bloqueada(s) en %s:"
T_IT[notify.body_header]="%s nuovo/i IP bloccato/i su %s:"

T_EN[notify.item]="  %s — score %s (404 flood)"
T_FR[notify.item]="  %s — score %s (flood 404)"
T_DE[notify.item]="  %s — Score %s (404-Flut)"
T_ES[notify.item]="  %s — puntuación %s (flood 404)"
T_IT[notify.item]="  %s — punteggio %s (flood 404)"

T_EN[notify.item_hp]="  %s — score %s (honeypot)"
T_FR[notify.item_hp]="  %s — score %s (honeypot)"
T_DE[notify.item_hp]="  %s — Score %s (Honeypot)"
T_ES[notify.item_hp]="  %s — puntuación %s (honeypot)"
T_IT[notify.item_hp]="  %s — punteggio %s (honeypot)"

T_EN[notify.no_mta]="NOTIFY_EMAIL set but no MTA (mail/sendmail) found — email skipped."
T_FR[notify.no_mta]="NOTIFY_EMAIL défini mais aucun MTA (mail/sendmail) trouvé — e-mail ignoré."
T_DE[notify.no_mta]="NOTIFY_EMAIL gesetzt, aber kein MTA (mail/sendmail) gefunden — E-Mail übersprungen."
T_ES[notify.no_mta]="NOTIFY_EMAIL definido pero no se encontró ningún MTA (mail/sendmail) — correo omitido."
T_IT[notify.no_mta]="NOTIFY_EMAIL definito ma nessun MTA (mail/sendmail) trovato — e-mail ignorata."

T_EN[summary.subject]="ban-404 [%s]: daily summary"
T_FR[summary.subject]="ban-404 [%s] : résumé quotidien"
T_DE[summary.subject]="ban-404 [%s]: tägliche Zusammenfassung"
T_ES[summary.subject]="ban-404 [%s]: resumen diario"
T_IT[summary.subject]="ban-404 [%s]: riepilogo giornaliero"

# Détection de la langue : locale du shell (ou /etc/default/locale en repli pour
# le contexte cron), code 2 lettres retenu s'il fait partie des langues gérées.
detect_lang() {
    local l="${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}"
    if [ -z "$l" ] && [ -r /etc/default/locale ]; then
        l=$(. /etc/default/locale 2>/dev/null; printf '%s' "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}")
    fi
    l="${l%%.*}"; l="${l%%_*}"; l="${l,,}"
    case "$l" in en|fr|de|es|it) printf '%s' "$l" ;; *) printf '%s' en ;; esac
}

# --- Surcharge par la config locale, NON versionnée (whitelist par serveur, REPO_RAW, langue, etc.) ---
CONF_FILE="/etc/ban_404.conf"
[ -f "$CONF_FILE" ] && . "$CONF_FILE"

# Résolution de la langue : conf > locale du shell > en. Puis validation.
: "${BAN404_LANG:=$(detect_lang)}"
BAN404_LANG="${BAN404_LANG,,}"
case "$BAN404_LANG" in en|fr|de|es|it) ;; *) BAN404_LANG=en ;; esac

# t <clé> [args...] : imprime la traduction (\n du format interprétés) + saut de ligne final.
# Le format est TOUJOURS notre chaîne ; les données ($ip, $count...) passent en arguments
# positionnels consommés par les %s -> aucune injection de format possible.
t() {
    local key="$1"; shift
    local ref="T_${BAN404_LANG^^}[$key]"
    local fmt="${!ref-}"
    [ -z "$fmt" ] && fmt="${T_EN[$key]-}"   # fallback EN si la clé manque pour la langue
    [ -z "$fmt" ] && fmt="$key"             # ultime garde-fou : jamais muet
    # '--' : empêche printf d'interpréter un format commençant par '-' comme une option.
    # shellcheck disable=SC2059
    printf -- "$fmt\n" "$@"
}

# Initialisation des options
DRY_RUN=false
SHOW_BLOCKED=false
VERBOSE=false
DO_LIST=false
DO_STATS=false
DO_DIAG=false
LIST_BY_TIMEOUT=false

show_help() {
    t version.line "$BAN404_VERSION"
    t version.author
    t help.usage "$0"
    echo ""
    t help.options_header
    t help.dryrun
    t help.showblocked
    t help.verbose
    t help.list
    t help.bytimeout
    t help.resolve
    t help.stats
    t help.unban
    t help.summary
    t help.checknotif
    t help.diag
    t help.lang
    t help.version
    t help.help
    echo ""
    t help.conf_header "$CONF_FILE"
    t help.conf_repo_raw
    t help.conf_whitelist_ip
    t help.conf_whitelist_cidr
    t help.conf_exclude_vhosts
    t help.conf_lang
    t help.conf_window
    t help.conf_ban_timeout
    t help.conf_tail
    t help.conf_threshold
    t help.conf_honeypot_score
    t help.conf_honeypot_timeout
    t help.conf_nickname
    t help.conf_webhook
    t help.conf_email
    t help.conf_from
    t help.conf_min_bans
    t help.conf_notify_bans
    t help.conf_daily
    t help.conf_resolve
    t help.conf_ptr_timeout
    t help.conf_advanced
    t help.conf_example_pointer
    exit 0
}

# --lang <code> : écrit BAN404_LANG dans la conf (remplace ou ajoute), puis quitte.
change_lang() {
    local new_lang="${1:-}"
    new_lang="${new_lang,,}"
    case "$new_lang" in
        en|fr|de|es|it) ;;
        "") t lang.missing; exit 1 ;;
        *) t lang.unsupported "$new_lang"; exit 1 ;;
    esac
    if [ ! -f "$CONF_FILE" ]; then
        t lang.noconf "$CONF_FILE"; exit 1
    fi
    if grep -qE '^[[:space:]]*#?[[:space:]]*BAN404_LANG=' "$CONF_FILE"; then
        local tmp
        tmp=$(mktemp) || { t lang.write_fail "$CONF_FILE"; exit 1; }
        # cat > conserve les permissions/propriétaire de la conf (chmod 600 root)
        # décommente et/ou remplace la ligne BAN404_LANG (active ou commentée).
        if sed -E "s/^[[:space:]]*#?[[:space:]]*BAN404_LANG=.*/BAN404_LANG=\"$new_lang\"/" "$CONF_FILE" > "$tmp" && cat "$tmp" > "$CONF_FILE"; then
            rm -f "$tmp"
        else
            rm -f "$tmp"; t lang.write_fail "$CONF_FILE"; exit 1
        fi
    else
        {
            printf '\n'
            printf '%s\n' "# Messages language: en (default) | fr | de | es | it"
            printf '%s\n' "# Langue des messages : en (défaut) | fr | de | es | it"
            printf '%s\n' "# Sprache der Meldungen: en (Standard) | fr | de | es | it"
            printf '%s\n' "# Idioma de los mensajes: en (por defecto) | fr | de | es | it"
            printf '%s\n' "# Lingua dei messaggi: en (predefinito) | fr | de | es | it"
            printf 'BAN404_LANG="%s"\n' "$new_lang"
        } >> "$CONF_FILE" || { t lang.write_fail "$CONF_FILE"; exit 1; }
    fi
    BAN404_LANG="$new_lang"   # confirmation dans la NOUVELLE langue
    t lang.changed "$new_lang" "$CONF_FILE"
    exit 0
}

# ---------- Whitelist CIDR (IPv4) ----------
ip2int() { local a b c d; IFS=. read -r a b c d <<< "$1"; printf '%s' "$(( (a<<24)+(b<<16)+(c<<8)+d ))"; }
ip_in_cidr() {  # $1=ip  $2=cidr (a.b.c.d ou a.b.c.d/n)
    local ip="$1" cidr="$2" net bits ipi neti mask
    net="${cidr%/*}"; bits="${cidr#*/}"
    [ "$cidr" = "$net" ] && bits=32
    case "$ip$net" in *[!0-9.]*) return 1 ;; esac   # IPv4 uniquement
    ipi=$(ip2int "$ip"); neti=$(ip2int "$net")
    [ "$bits" -eq 0 ] && return 0
    mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
    [ $(( ipi & mask )) -eq $(( neti & mask )) ]
}
in_whitelist_cidr() {  # $1=ip
    [ -z "$WHITELIST_CIDR" ] && return 1
    local ip="$1" c IFS='|'
    for c in $WHITELIST_CIDR; do
        [ -n "$c" ] && ip_in_cidr "$ip" "$c" && return 0
    done
    return 1
}
in_whitelist_ip() {  # $1=ip ; correspondance EXACTE dans WHITELIST_IP (séparé par | )
    [ -z "$WHITELIST_IP" ] && return 1
    local ip="$1" w IFS='|'
    for w in $WHITELIST_IP; do
        [ -n "$w" ] && [ "$ip" = "$w" ] && return 0
    done
    return 1
}
# Débannit activement les IP déjà dans l'ipset que la whitelist couvre (WHITELIST_IP exacte
# ou WHITELIST_CIDR). Comble l'angle mort : une IP bannie PUIS whitelistée n'apparaît plus
# dans les candidats (awk l'exclut côté IP exacte ; elle ne floode plus), donc elle n'était
# jamais retirée et n'expirait qu'au BAN_TIMEOUT. Idempotent ; respecte --dry-run.
enforce_whitelist_unban() {
    local ip removed=false
    while read -r ip; do
        [ -z "$ip" ] && continue
        in_whitelist_ip "$ip" || in_whitelist_cidr "$ip" || continue
        if [ "$DRY_RUN" = true ]; then
            t wl.sim_unban "$ip"
        elif ipset del "$IPSET_NAME" "$ip" 2>/dev/null; then
            t wl.unban "$ip"; removed=true
        fi
    done < <(ipset list "$IPSET_NAME" 2>/dev/null | awk '/^Members:/{m=1;next} m&&NF{print $1}')
    if [ "$removed" = true ]; then
        mkdir -p "$(dirname "$IPSET_SAVE_FILE")"
        ipset save > "$IPSET_SAVE_FILE"
    fi
}

# ---------- Exclusion de vhosts (découverte des logs) ----------
is_excluded_vhost() {  # $1 = nom du vhost (dossier sous BASE_DIR)
    [ -z "$EXCLUDE_VHOSTS" ] && return 1
    local v="$1" e IFS='|'
    for e in $EXCLUDE_VHOSTS; do
        [ -n "$e" ] && [ "$v" = "$e" ] && return 0
    done
    return 1
}

# ---------- Notifications (langue = BAN404_LANG) ----------
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}
# Construit le corps JSON du webhook selon le service (logique centralisée).
build_webhook_payload() {  # $1 = texte brut -> imprime le JSON
    local esc; esc=$(json_escape "$1")
    # Google Chat n'accepte QUE "text" (rejet 400 des champs inconnus) ; les autres
    # acceptent "text" (Slack/Mattermost/n8n) et "content" (Discord/Teams).
    case "$WEBHOOK_URL" in
        *chat.googleapis.com*) printf '{"text":"%s"}' "$esc" ;;
        *)                     printf '{"text":"%s","content":"%s"}' "$esc" "$esc" ;;
    esac
}
send_webhook() {  # $1 = texte complet
    [ -z "$WEBHOOK_URL" ] && return 0
    command -v curl >/dev/null 2>&1 || return 0
    curl -fsS -m 15 -H 'Content-Type: application/json' \
         -X POST -d "$(build_webhook_payload "$1")" "$WEBHOOK_URL" >/dev/null 2>&1 || true
}
send_email() {  # $1 = sujet, $2 = corps
    [ -z "$NOTIFY_EMAIL" ] && return 0
    if command -v mail >/dev/null 2>&1; then
        if [ -n "$NOTIFY_FROM" ]; then printf '%s\n' "$2" | mail -s "$1" -r "$NOTIFY_FROM" "$NOTIFY_EMAIL" 2>/dev/null || true
        else printf '%s\n' "$2" | mail -s "$1" "$NOTIFY_EMAIL" 2>/dev/null || true; fi
    elif command -v sendmail >/dev/null 2>&1; then
        { printf 'To: %s\n' "$NOTIFY_EMAIL"; [ -n "$NOTIFY_FROM" ] && printf 'From: %s\n' "$NOTIFY_FROM"
          printf 'Subject: %s\n\n%s\n' "$1" "$2"; } | sendmail -t 2>/dev/null || true
    else
        t notify.no_mta >&2
    fi
}
# Identifiant du serveur dans les notifications (mail/webhook). Si SERVER_NICKNAME est défini,
# on l'affiche AVEC le hostname (« nickname [hostname] ») : repérage humain immédiat sans perdre
# l'identifiant technique. Sinon, le hostname seul.
server_label() {
    local host; host=$(hostname 2>/dev/null || printf '?')
    if [ -n "${SERVER_NICKNAME:-}" ]; then printf '%s [%s]' "$SERVER_NICKNAME" "$host"
    else printf '%s' "$host"; fi
}
notify() {  # $1 = sujet, $2 = corps
    send_webhook "$1"$'\n'"$2"
    send_email "$1" "$2"
}
maybe_notify_new_bans() {
    [ -z "$WEBHOOK_URL" ] && [ -z "$NOTIFY_EMAIL" ] && return 0
    local host n subj body line ip sc hp
    host=$(server_label)
    n=${#new_bans[@]}
    subj=$(t notify.subject "$host" "$n")
    body=$(t notify.body_header "$n" "$host")
    for line in "${new_bans[@]}"; do
        IFS='|' read -r ip sc hp <<< "$line"
        if [ "$hp" = "1" ]; then body="$body"$'\n'"$(t notify.item_hp "$ip" "$sc")"
        else body="$body"$'\n'"$(t notify.item "$ip" "$sc")"; fi
    done
    notify "$subj" "$body"
}

# ---------- --list / --stats / --summary ----------
# Reverse DNS (PTR) d'une IP, borné par PTR_TIMEOUT pour ne jamais bloquer : getent (libc/nsswitch,
# aucune dépendance externe, même voie que is_legit_crawler). Imprime le hostname ou rien.
reverse_dns() {  # $1 = IP
    if command -v timeout >/dev/null 2>&1; then
        timeout "${PTR_TIMEOUT:-2}" getent hosts "$1" 2>/dev/null | awk 'NR==1{print $2; exit}'
    else
        getent hosts "$1" 2>/dev/null | awk 'NR==1{print $2; exit}'
    fi
}
# Vrai si le reverse doit être résolu (conf RESOLVE_PTR, ou flag --resolve qui force RESOLVE_PTR=true).
resolve_ptr_on() { case "${RESOLVE_PTR:-}" in true|1|yes|on) return 0 ;; *) return 1 ;; esac; }

build_stats_text() {
    local banned bans unbans cutoff24 cnt ip rdns updater upd_ver issue div kind sc top_raw top404 tophp
    printf -v div '─%.0s' {1..30}        # filet sous le titre (largeur fixe)
    banned=$(ipset list "$IPSET_NAME" 2>/dev/null | awk '/^Members:/{m=1;next} m&&NF{c++} END{print c+0}')
    cutoff24=$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    bans=0; unbans=0
    if [ -r "$LOG_FILE" ] && [ -n "$cutoff24" ]; then
        bans=$(awk -v c="$cutoff24" '($1" "$2) >= c && /\[\+\]/' "$LOG_FILE" | wc -l)
        unbans=$(awk -v c="$cutoff24" '($1" "$2) >= c && /\[-\]/' "$LOG_FILE" | wc -l)
    fi
    # --- En-tête + filet ---
    t stats.header
    printf '%s\n\n' "$div"
    # --- Versions (moteur + updater installé) — en tête pour surveiller le parc ---
    updater="/usr/local/sbin/update_ban_404.sh"; upd_ver="?"
    if [ -f "$updater" ]; then
        upd_ver=$(grep -m1 '^UPDATER_VERSION=' "$updater" 2>/dev/null | cut -d'"' -f2)
        [ -z "$upd_ver" ] && upd_ver="?"   # updater legacy sans UPDATER_VERSION
    fi
    t stats.versions "$BAN404_VERSION" "$upd_ver"
    # --- Santé : uniquement les WARN/FAIL des contrôles de diagnostic (réseau inclus) ---
    DIAG_QUIET=true; DIAG_PROBLEMS=0; DIAG_ISSUES=()
    run_diag_checks            # remplit DIAG_ISSUES sans rien imprimer
    DIAG_QUIET=false
    if [ "${#DIAG_ISSUES[@]}" -eq 0 ]; then
        t stats.health_ok                       # ligne inline « Santé : aucune anomalie détectée. »
    else
        t stats.health_header                   # « Santé (anomalies) : »
        for issue in "${DIAG_ISSUES[@]}"; do
            printf '  %s\n' "$issue"             # déjà préfixé [WARN]/[FAIL] + déjà localisé (pas de re-format t)
        done
    fi
    # --- Statistiques (24h) ---
    printf '\n── %s ──\n' "$(t stats.sec_stats)"
    t stats.banned_now "$banned"
    t stats.bans_unbans "$bans" "$unbans"
    # --- Top 404 (24h) PUIS Top honeypot (24h) : deux classements distincts ; débans exclus ---
    if [ -r "$LOG_FILE" ] && [ -n "$cutoff24" ]; then
        # awk émet « kind score ip » : kind r = ban classique (score = nb de 404) ; kind h = honeypot
        # (score pondéré = 100/hit-honeypot + 1/autre-404 ; 0 sur les vieilles lignes sans score). Le
        # nombre est relu entre parenthèses après l'IP (« (48 … » ou « (score 250) »), robuste aux 5
        # langues ; honeypot reconnu par le mot « honeypot » (présent tel quel dans les 5 langues).
        top_raw=$(awk -v c="$cutoff24" '
            ($1" "$2) >= c && /\[\+\]/ {
                ip=""; ipi=0
                for(i=3;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/){ip=$i; ipi=i; break}
                if(ip=="") next
                n=0
                for(i=ipi+1;i<=NF;i++) if($i ~ /[0-9]/){ s=$i; gsub(/[^0-9]/,"",s); if(s!=""){n=s+0; break} }
                if($0 ~ /[Hh]oneypot/){ if(n>H[ip]) H[ip]=n; hs[ip]=1 }
                else                  { if(n>R[ip]) R[ip]=n; rs[ip]=1 }
            }
            END{
                for(ip in rs) printf "r %d %s\n", R[ip]+0, ip
                for(ip in hs) printf "h %d %s\n", H[ip]+0, ip
            }
        ' "$LOG_FILE")
        top404=$(printf '%s\n' "$top_raw" | awk '$1=="r"' | sort -k2,2nr | head -n 10)
        tophp=$( printf '%s\n' "$top_raw" | awk '$1=="h"' | sort -k2,2nr | head -n 10)
        if [ -n "$top404" ]; then
            printf '\n── %s ──\n' "$(t stats.top_header)"
            while read -r kind cnt ip; do
                [ -z "$ip" ] && continue
                rdns=""; if resolve_ptr_on; then rdns=$(reverse_dns "$ip"); fi
                [ -n "$rdns" ] && t stats.top_item_rdns "$ip" "$cnt" "$rdns" || t stats.top_item "$ip" "$cnt"
            done <<< "$top404"
        fi
        if [ -n "$tophp" ]; then
            printf '\n── %s ──\n' "$(t stats.top_hp_header)"
            while read -r kind sc ip; do
                [ -z "$ip" ] && continue
                rdns=""; if resolve_ptr_on; then rdns=$(reverse_dns "$ip"); fi
                if [ "${sc:-0}" -gt 0 ] 2>/dev/null; then
                    [ -n "$rdns" ] && t stats.top_item_hp_score_rdns "$ip" "$sc" "$rdns" || t stats.top_item_hp_score "$ip" "$sc"
                else
                    [ -n "$rdns" ] && t stats.top_item_hp_rdns "$ip" "$rdns" || t stats.top_item_hp "$ip"
                fi
            done <<< "$tophp"
        fi
    fi
}
do_list() {
    local members ip rest to_raw to fam key ipkey
    members=$(ipset list "$IPSET_NAME" 2>/dev/null | awk '/^Members:/{m=1;next} m&&NF{print}')
    t list.header "$IPSET_NAME"
    if [ -z "$members" ]; then t list.empty; return 0; fi
    # Construit des lignes triables "<clef>\t<ip>\t<timeout>", trie en LC_ALL=C
    # (ordre déterministe), puis affiche. Tri par défaut : IPv4 d'abord (octets
    # zéro-paddés pour un ordre numérique croissant), puis IPv6. Avec --by-timeout :
    # tri croissant par timeout résiduel, puis par IP (départage des ex æquo).
    printf '%s\n' "$members" | while read -r ip rest; do
        to_raw=$(printf '%s' "$rest" | sed -n 's/.*timeout \([0-9]*\).*/\1/p')
        to="${to_raw:-?}"
        case "$ip" in *:*) fam=1 ;; *) fam=0 ;; esac
        # Clef IP : IPv4 d'abord (octets zéro-paddés => ordre numérique croissant), puis IPv6.
        if [ "$fam" -eq 0 ]; then
            ipkey="0_$(printf '%s' "$ip" | awk -F. '{printf "%03d.%03d.%03d.%03d",$1,$2,$3,$4}')"
        else
            ipkey="1_$ip"
        fi
        if [ "$LIST_BY_TIMEOUT" = true ]; then
            # Tri primaire = timeout croissant ; tri secondaire = IP (en cas d'égalité).
            key="$(printf '%012d' "${to_raw:-0}" 2>/dev/null || printf '%s' "${to_raw:-0}")_$ipkey"
        else
            key="$ipkey"
        fi
        printf '%s\t%s\t%s\n' "$key" "$ip" "$to"
    done | LC_ALL=C sort | while IFS=$'\t' read -r key ip to; do
        if resolve_ptr_on; then
            rdns=$(reverse_dns "$ip")
            [ -n "$rdns" ] && t list.item_rdns "$ip" "$to" "$rdns" || t list.item "$ip" "$to"
        else
            t list.item "$ip" "$to"
        fi
    done
}
do_summary() {
    case "$DAILY_SUMMARY" in true|1|yes|on) ;; *) exit 0 ;; esac
    [ -z "$WEBHOOK_URL" ] && [ -z "$NOTIFY_EMAIL" ] && exit 0
    local host; host=$(server_label)
    notify "$(t summary.subject "$host")" "$(build_stats_text)"
    exit 0
}

# ---------- --check-notification : test des canaux, avec retour + diagnostic ----------
# Codes retour des check_* : 0 = OK, 1 = configuré mais en échec, 2 = non configuré.
check_webhook() {
    [ -z "$WEBHOOK_URL" ] && { t check.webhook_off; return 2; }
    command -v curl >/dev/null 2>&1 || { t check.webhook_nocurl; return 1; }
    local host code rc tmp body
    host=$(server_label)
    tmp=$(mktemp 2>/dev/null) || tmp=""
    code=$(curl -sS -m 15 -o "${tmp:-/dev/null}" -w '%{http_code}' -H 'Content-Type: application/json' \
                -X POST -d "$(build_webhook_payload "$(t check.body "$host")")" "$WEBHOOK_URL" 2>/dev/null); rc=$?
    body=""; [ -n "$tmp" ] && { body=$(tr -d '\r' < "$tmp" 2>/dev/null | tr '\n' ' ' | head -c 300); rm -f "$tmp"; }
    if [ "$rc" -ne 0 ]; then t check.webhook_err; [ -n "$body" ] && t check.diag "$body"; return 1; fi
    case "$code" in
        2*) t check.webhook_ok "$code"; return 0 ;;
        *)  t check.webhook_fail "$code"; [ -n "$body" ] && t check.diag "$body"; return 1 ;;
    esac
}
check_email() {
    [ -z "$NOTIFY_EMAIL" ] && { t check.email_off; return 2; }
    local host subj body rc tmp err
    host=$(server_label)
    subj=$(t check.subject "$host"); body=$(t check.body "$host")
    tmp=$(mktemp 2>/dev/null) || tmp=""
    if command -v mail >/dev/null 2>&1; then
        if [ -n "$NOTIFY_FROM" ]; then printf '%s\n' "$body" | mail -s "$subj" -r "$NOTIFY_FROM" "$NOTIFY_EMAIL" 2>"${tmp:-/dev/null}"
        else printf '%s\n' "$body" | mail -s "$subj" "$NOTIFY_EMAIL" 2>"${tmp:-/dev/null}"; fi
        rc=$?
    elif command -v sendmail >/dev/null 2>&1; then
        { printf 'To: %s\n' "$NOTIFY_EMAIL"; [ -n "$NOTIFY_FROM" ] && printf 'From: %s\n' "$NOTIFY_FROM"
          printf 'Subject: %s\n\n%s\n' "$subj" "$body"; } | sendmail -t 2>"${tmp:-/dev/null}"; rc=$?
    else
        t check.email_no_mta; [ -n "$tmp" ] && rm -f "$tmp"; return 1
    fi
    err=""; [ -n "$tmp" ] && { err=$(tr '\n' ' ' < "$tmp" 2>/dev/null | head -c 300); rm -f "$tmp"; }
    if [ "$rc" -eq 0 ]; then t check.email_sent "$NOTIFY_EMAIL"; return 0; fi
    t check.email_fail; [ -n "$err" ] && t check.diag "$err"; return 1
}
check_notification() {  # $1 = email|webhook|all (défaut all)
    local target="${1:-all}"; target="${target,,}"
    case "$target" in email|webhook|all) ;; *) t check.invalid "$target"; exit 1 ;; esac
    t check.header
    local rc_w=3 rc_e=3
    case "$target" in webhook|all) check_webhook; rc_w=$? ;; esac
    case "$target" in email|all)   check_email;   rc_e=$? ;; esac
    { [ "$rc_w" -eq 1 ] || [ "$rc_e" -eq 1 ]; } && exit 1   # un canal testé a échoué
    if [ "$rc_w" -ne 0 ] && [ "$rc_e" -ne 0 ]; then t check.none_configured; exit 1; fi
    exit 0
}

# ---------- --diag : auto-diagnostic lecture seule de l'état du serveur ----------
# Liste les anomalies (composants & versions, crons, pare-feu, conf/réseau, logs, cohérence des
# notifications) sans rien modifier ni envoyer (≠ --check-notification qui émet un test live).
# Calque check_notification : en-tête, une ligne [ OK ]/[WARN]/[FAIL] par contrôle, bilan, exit
# (0 = sain, 1 = au moins une anomalie). DIAG_PROBLEMS compte les WARN + FAIL.
DIAG_PROBLEMS=0
DIAG_QUIET=false           # true => diag_line accumule sans imprimer (réutilisé par le résumé)
declare -a DIAG_ISSUES=()  # lignes "[WARN]/[FAIL] message" accumulées (pour le résumé quotidien)
diag_line() {  # $1 = ok|warn|fail ; $2 = message déjà localisé
    local tag
    case "$1" in
        ok)   tag="[ OK ]" ;;
        warn) tag="[WARN]"; DIAG_PROBLEMS=$((DIAG_PROBLEMS + 1)); DIAG_ISSUES+=("$tag $2") ;;
        *)    tag="[FAIL]"; DIAG_PROBLEMS=$((DIAG_PROBLEMS + 1)); DIAG_ISSUES+=("$tag $2") ;;
    esac
    [ "$DIAG_QUIET" = true ] && return 0
    printf '%s %s\n' "$tag" "$2"
}
diag_is_on() { case "${1:-}" in true|1|yes|on) return 0 ;; *) return 1 ;; esac; }

# run_diag_checks : exécute les ~25 contrôles (appels diag_line), SANS en-tête ni bilan ni exit.
# Extrait de do_diag pour être réutilisable par le résumé quotidien (build_stats_text) en mode
# DIAG_QUIET (accumulation dans DIAG_ISSUES sans impression). do_diag l'enrobe (en-tête + bilan).
run_diag_checks() {
    local engine="/usr/local/sbin/ban_404.sh" updater="/usr/local/sbin/update_ban_404.sh"
    local upd_ver="" repo_engine repo_upd up n chans
    local active inactive excluded unreadable log_dir vhost f now mt age_d

    # 1. Composants & versions (local)
    if [ -f "$engine" ]; then diag_line ok "$(t diag.engine_ok "$BAN404_VERSION")"
    else diag_line fail "$(t diag.engine_missing "$engine")"; fi
    if [ -f "$updater" ]; then
        upd_ver=$(grep -m1 '^UPDATER_VERSION=' "$updater" 2>/dev/null | cut -d'"' -f2)
        if [ -n "$upd_ver" ]; then diag_line ok "$(t diag.updater_ok "$upd_ver")"
        else diag_line warn "$(t diag.updater_legacy)"; fi
    else
        diag_line fail "$(t diag.updater_missing "$updater")"
    fi

    # 2. Comparaison réseau au dépôt (versions locales vs REPO_RAW)
    if [ -z "${REPO_RAW:-}" ]; then
        diag_line warn "$(t diag.repo_unset)"
    elif ! command -v curl >/dev/null 2>&1; then
        diag_line warn "$(t diag.repo_unreachable "$REPO_RAW")"
    else
        repo_engine=$(curl -fsSL --max-time 15 "$REPO_RAW/ban_404.sh"        2>/dev/null | grep -m1 '^BAN404_VERSION='   | cut -d'"' -f2)
        repo_upd=$(   curl -fsSL --max-time 15 "$REPO_RAW/update_ban_404.sh" 2>/dev/null | grep -m1 '^UPDATER_VERSION=' | cut -d'"' -f2)
        if [ -z "$repo_engine" ] && [ -z "$repo_upd" ]; then
            diag_line warn "$(t diag.repo_unreachable "$REPO_RAW")"
        else
            up=1
            if [ -n "$repo_engine" ] && [ "$repo_engine" != "$BAN404_VERSION" ]; then
                diag_line warn "$(t diag.engine_update "$BAN404_VERSION" "$repo_engine")"; up=0
            fi
            if [ -n "$repo_upd" ] && [ -n "$upd_ver" ] && [ "$repo_upd" != "$upd_ver" ]; then
                diag_line warn "$(t diag.updater_update "$upd_ver" "$repo_upd")"; up=0
            fi
            [ "$up" -eq 1 ] && diag_line ok "$(t diag.repo_uptodate)"
        fi
    fi

    # 3. Crons (hourly = FAIL si absent ; update = WARN ; summary = cohérence avec DAILY_SUMMARY)
    if [ -f /etc/cron.hourly/ban_404 ]; then diag_line ok "$(t diag.present /etc/cron.hourly/ban_404)"
    else diag_line fail "$(t diag.absent /etc/cron.hourly/ban_404)"; fi
    if [ -f /etc/cron.daily/ban_404_update ]; then diag_line ok "$(t diag.present /etc/cron.daily/ban_404_update)"
    else diag_line warn "$(t diag.absent /etc/cron.daily/ban_404_update)"; fi
    # Pilote de cron.daily. /etc/crontab le délègue à anacron SI présent (test -x /usr/sbin/anacron),
    # SINON le lance lui-même à 06:25 via run-parts (le `||` est un fallback, pas une dépendance).
    # Pièges détectés ici :
    #  - anacron présent mais NON planifié (timer/cron.d inactif) => cron délègue à un anacron mort
    #    => cron.daily ne part jamais (hourly OK, daily figé : le cas le plus pervers) ;
    #  - anacron absent ET /etc/crontab sans la ligne cron.daily => personne ne le lance.
    # anacron absent AVEC la ligne standard est SAIN (cron s'en charge à 06:25, sans rattrapage).
    if command -v anacron >/dev/null 2>&1 || [ -x /usr/sbin/anacron ]; then
        if { command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet anacron.timer 2>/dev/null; } \
           || [ -e /etc/cron.d/anacron ]; then
            diag_line ok "$(t diag.anacron_ok)"
        else
            diag_line warn "$(t diag.anacron_deferred)"
        fi
    elif grep -qsrE 'run-parts.*/etc/cron\.daily' /etc/crontab /etc/cron.d; then
        diag_line ok "$(t diag.anacron_absent_ok)"
    else
        diag_line warn "$(t diag.anacron_absent_nocron)"
    fi
    # Fraîcheur : l'updater a-t-il tourné récemment ? (un cron.daily/anacron muet fige le parc)
    if [ -f "$UPDATE_STAMP_FILE" ]; then
        now=$(date +%s); mt=$(stat -c %Y "$UPDATE_STAMP_FILE" 2>/dev/null || echo 0)
        age_d=$(( (now - mt) / 86400 ))
        if [ "$age_d" -ge 2 ]; then diag_line warn "$(t diag.update_stale "$age_d")"
        else diag_line ok "$(t diag.update_fresh)"; fi
    else
        diag_line warn "$(t diag.update_never)"
    fi
    if diag_is_on "$DAILY_SUMMARY"; then
        if [ -f /etc/cron.daily/ban_404_summary ]; then diag_line ok "$(t diag.summary_cron_ok)"
        else diag_line warn "$(t diag.summary_cron_missing_wanted)"; fi
    else
        if [ -f /etc/cron.daily/ban_404_summary ]; then diag_line warn "$(t diag.summary_cron_orphan)"
        else diag_line ok "$(t diag.summary_cron_off)"; fi
    fi

    # 4. Pare-feu (lecture ipset/iptables => root requis)
    if [ "$(id -u)" -eq 0 ]; then
        if ipset list "$IPSET_NAME" &>/dev/null; then
            n=$(ipset list "$IPSET_NAME" 2>/dev/null | awk '/^Members:/{m=1;next} m&&NF{c++} END{print c+0}')
            diag_line ok "$(t diag.ipset_ok "$IPSET_NAME" "$n")"
        else
            diag_line fail "$(t diag.ipset_missing "$IPSET_NAME")"
        fi
        if /sbin/iptables -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP &>/dev/null; then
            diag_line ok "$(t diag.iptables_ok)"
        else
            diag_line fail "$(t diag.iptables_missing)"
        fi
        if [ -f "$IPSET_SAVE_FILE" ] && [ -f /etc/iptables/rules.v4 ]; then
            diag_line ok "$(t diag.persist_ok)"
        else
            diag_line warn "$(t diag.persist_missing)"
        fi
    else
        diag_line warn "$(t diag.root_skip)"
    fi

    # 5. Conf & logrotate
    if [ -f "$CONF_FILE" ]; then diag_line ok "$(t diag.present "$CONF_FILE")"
    else diag_line fail "$(t diag.absent "$CONF_FILE")"; fi
    if [ -f /etc/logrotate.d/ban_404 ]; then diag_line ok "$(t diag.present /etc/logrotate.d/ban_404)"
    else diag_line warn "$(t diag.absent /etc/logrotate.d/ban_404)"; fi

    # 6. Découverte des logs (même logique que l'analyse ; purement lecture). On sépare les cas
    # BÉNINS (site inactif : aucun access.log, symlink cassé, ou fichier vide — fréquent en
    # ISPConfig où access.log pointe sur le log du jour, absent si le site ne logue plus) du SEUL
    # vrai problème : un log présent mais NON LISIBLE (permission/ACL). --verbose détaille chaque
    # dossier fautif pour repérer un éventuel vrai site mal classé.
    active=0; inactive=0; unreadable=0; excluded=0
    for log_dir in ${BASE_DIR}/*/log/; do
        [ -d "$log_dir" ] || continue
        vhost="${log_dir%/log/}"; vhost="${vhost##*/}"
        if is_excluded_vhost "$vhost"; then excluded=$((excluded + 1)); continue; fi
        # yesterday-access.log : artefact ISPConfig (symlink vers le log de la veille, souvent
        # périmé) — jamais le bon fichier à analyser, on l'écarte du fallback.
        if [ -f "${log_dir}access.log" ]; then f="${log_dir}access.log"
        else f=$(ls -1t "${log_dir}"*access.log 2>/dev/null | grep -v '/yesterday-access\.log$' | head -n 1); fi
        if   [ -z "$f" ];   then inactive=$((inactive + 1));     [ "$VERBOSE" = true ] && t diag.log_v_nolog "$vhost"
        elif [ ! -e "$f" ]; then inactive=$((inactive + 1));     [ "$VERBOSE" = true ] && t diag.log_v_broken "$vhost"
        elif [ ! -r "$f" ]; then unreadable=$((unreadable + 1)); [ "$VERBOSE" = true ] && t diag.log_v_unreadable "$vhost"
        elif [ ! -s "$f" ]; then inactive=$((inactive + 1));     [ "$VERBOSE" = true ] && t diag.log_v_empty "$vhost"
        else active=$((active + 1)); fi
    done
    if   [ "$unreadable" -gt 0 ]; then diag_line warn "$(t diag.logs "$active" "$inactive" "$unreadable" "$excluded")"
    elif [ "$active" -gt 0 ];     then diag_line ok   "$(t diag.logs "$active" "$inactive" "$unreadable" "$excluded")"
    else                               diag_line warn "$(t diag.logs "$active" "$inactive" "$unreadable" "$excluded")"; fi

    # 7. Cohérence des notifications (config seule, aucun envoi)
    chans=""
    [ -n "$WEBHOOK_URL" ] && chans="webhook"
    [ -n "$NOTIFY_EMAIL" ] && chans="${chans:+$chans, }e-mail"
    if [ -n "$chans" ]; then diag_line ok "$(t diag.notify_channels "$chans")"
    else diag_line ok "$(t diag.notify_none)"; fi
    if diag_is_on "$NOTIFY_BANS"   && [ -z "$WEBHOOK_URL" ] && [ -z "$NOTIFY_EMAIL" ]; then diag_line warn "$(t diag.notify_orphan_bans)"; fi
    if diag_is_on "$DAILY_SUMMARY" && [ -z "$WEBHOOK_URL" ] && [ -z "$NOTIFY_EMAIL" ]; then diag_line warn "$(t diag.notify_orphan_summary)"; fi
}

do_diag() {
    t diag.header
    run_diag_checks
    # Bilan
    echo ""
    if [ "$DIAG_PROBLEMS" -eq 0 ]; then t diag.tally_clean; exit 0; fi
    t diag.tally_problems "$DIAG_PROBLEMS"; exit 1
}

# ---------- --unban <IP|all> : retrait manuel de l'ipset (sans bricoler ipset à la main) ----------
do_unban() {  # $1 = IP | all  (valeur requise, pas de défaut)
    local target="${1:-}" n
    [ -z "$target" ] && { t unban.missing; exit 1; }
    [ "$(id -u)" -ne 0 ] && { t unban.needroot; exit 1; }
    ipset list "$IPSET_NAME" &>/dev/null || { t unban.noset "$IPSET_NAME"; exit 1; }
    if [ "${target,,}" = "all" ]; then
        n=$(ipset list "$IPSET_NAME" 2>/dev/null | awk '/^Members:/{m=1;next} m&&NF{c++} END{print c+0}')
        ipset flush "$IPSET_NAME" 2>/dev/null || { t unban.fail "all"; exit 1; }
        t unban.all_done "$n"
    elif ipset test "$IPSET_NAME" "$target" &>/dev/null; then
        ipset del "$IPSET_NAME" "$target" 2>/dev/null || { t unban.fail "$target"; exit 1; }
        t unban.done "$target"
    else
        t unban.notfound "$target"; exit 0
    fi
    mkdir -p "$(dirname "$IPSET_SAVE_FILE")"
    ipset save > "$IPSET_SAVE_FILE" 2>/dev/null
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --show-blocked) SHOW_BLOCKED=true; shift ;;
        --verbose) VERBOSE=true; shift ;;
        --lang) change_lang "${2:-}" ;;
        --lang=*) change_lang "${1#*=}" ;;
        --by-timeout) LIST_BY_TIMEOUT=true; shift ;;
        --resolve) RESOLVE_PTR=true; shift ;;
        --list) DO_LIST=true; shift ;;
        --stats) DO_STATS=true; shift ;;
        --summary) do_summary ;;
        --check-notification) check_notification "${2:-all}" ;;
        --check-notification=*) check_notification "${1#*=}" ;;
        --diag) DO_DIAG=true; shift ;;
        --unban) do_unban "${2:-}" ;;
        --unban=*) do_unban "${1#*=}" ;;
        --version) t version.line "$BAN404_VERSION"; t version.author; exit 0 ;;
        --help|-h) show_help ;;
        *) t err.unknown_opt "$1"; exit 1 ;;
    esac
done

# --- Auto-diagnostic (lecture seule), exécuté APRÈS la boucle de parsing : ainsi --verbose est
# déjà pris en compte par run_diag_checks (détail par dossier) quel que soit l'ordre sur la ligne
# (--diag --verbose autant que --verbose --diag). do_diag sort. ---
[ "$DO_DIAG" = true ] && do_diag

# --- Actions de rapport (cumulables) : --stats et/ou --list, puis on sort. ---
if [ "$DO_STATS" = true ] || [ "$DO_LIST" = true ]; then
    [ "$DO_STATS" = true ] && build_stats_text
    [ "$DO_STATS" = true ] && [ "$DO_LIST" = true ] && echo ""
    [ "$DO_LIST" = true ] && do_list
    exit 0
fi

# --- Verrou anti-chevauchement (cron). Inutile en simulation (lecture seule). ---
if [ "$DRY_RUN" = false ]; then
    exec 9>"$LOCK_FILE" || { t lock.open_fail "$LOCK_FILE"; exit 1; }
    if ! flock -n 9; then
        t lock.busy "$LOCK_FILE"
        exit 1
    fi
fi

if [ "$VERBOSE" = true ]; then
    if [ "$DRY_RUN" = true ]; then
        echo "========================================="
        echo "   /!\\  $(t banner.sim_active)  /!\\"
        echo "========================================="
    fi
    if [ "$SHOW_BLOCKED" = false ]; then
        t verbose.filter_hidden
    else
        t verbose.filter_all
    fi
    t verbose.searching_logs
fi

# FCrDNS sans dépendance externe (getent, via la libc/nsswitch) :
#   1) PTR de l'IP  2) hostname = sous-domaine d'un crawler connu
#   3) ce hostname doit RE-RÉSOUDRE vers l'IP d'origine (anti-spoofing du PTR)
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

# --- Auto-guérison de l'updater "legacy" -------------------------------------
# Certains serveurs portent un ancien updater qui ne met à jour QUE ban_404.sh
# (jamais lui-même) : il ne se modernisera donc jamais seul. Or le moteur, lui,
# EST déployé partout (l'updater legacy le rafraîchit). Le moteur peut donc
# réinstaller un updater moderne depuis REPO_RAW. Détection = absence de la
# variable UPDATER_VERSION (les updaters modernes la portent et s'auto-mettent
# à jour) ; dès qu'un updater versionné est en place, ce bloc ne fait plus rien.
self_heal_updater() {
    local upd="/usr/local/sbin/update_ban_404.sh" repo="${REPO_RAW:-}" dir tmp
    [ "$DRY_RUN" = true ] && return 0
    [ "$(id -u)" -eq 0 ] || return 0
    [ -f "$upd" ] && grep -q '^UPDATER_VERSION=' "$upd" && return 0   # déjà moderne
    [ -z "$repo" ] && return 0
    command -v curl >/dev/null 2>&1 || return 0
    dir=$(dirname "$upd")
    tmp=$(mktemp "$dir/.upd.XXXXXX" 2>/dev/null) || return 0
    # Télécharge -> valide (shebang + versionné + bash -n) -> bascule atomique (.bak)
    if curl -fsSL --max-time 30 "$repo/update_ban_404.sh" -o "$tmp" \
       && [ -s "$tmp" ] && head -n1 "$tmp" | grep -q '^#!/bin/bash' \
       && grep -q '^UPDATER_VERSION=' "$tmp" && bash -n "$tmp" 2>/dev/null; then
        chmod 755 "$tmp"
        [ -f "$upd" ] && cp -a "$upd" "${upd}.bak" 2>/dev/null || true
        if mv -f "$tmp" "$upd"; then t heal.updater "$upd"; return 0; fi
    fi
    rm -f "$tmp"
    return 0
}

# Réconciliation du cron de résumé quotidien selon DAILY_SUMMARY. La feature --summary (et son
# cron.daily) a été ajoutée après coup, et l'installeur — seul à le poser autrefois — n'est jamais
# rejoué. Le moteur, lui, est rafraîchi partout par l'updater : à chaque passage horaire il aligne
# l'existence du fichier sur DAILY_SUMMARY (le crée si activé, le retire si désactivé). DAILY_SUMMARY
# devient ainsi l'interrupteur unique (exécution ET présence du cron) ; le moteur en est seul maître
# (l'installeur ne le pose plus). Idempotent : sans effet si le fichier est déjà dans l'état voulu.
self_heal_summary_cron() {
    local f="/etc/cron.daily/ban_404_summary"
    [ "$DRY_RUN" = true ] && return 0
    [ "$(id -u)" -eq 0 ] || return 0
    case "$DAILY_SUMMARY" in
        true|1|yes|on)
            [ -f "$f" ] && return 0                   # déjà présent => rien à faire
            cat > "$f" <<'EOF'
#!/bin/sh
exec /usr/local/sbin/ban_404.sh --summary
EOF
            chmod 755 "$f" && t heal.summary_cron "$f" ;;
        *)
            [ -f "$f" ] || return 0                   # déjà absent => rien à faire
            rm -f "$f" && t heal.summary_cron_removed "$f" ;;
    esac
    return 0
}

# --- Filet de sécurité MAJ -----------------------------------------------------
# Sur certains serveurs, cron.daily (piloté par anacron) cesse de se déclencher
# silencieusement : l'updater n'est alors JAMAIS appelé et tout fige (moteur +
# updater + conf). Le moteur, lui, tourne via cron.hourly (piloté DIRECTEMENT par
# cron, indépendant d'anacron) : on l'utilise pour relancer l'updater EN DERNIER
# RECOURS. N'ajoute AUCUN cron (réutilise le passage horaire existant) et reste
# DORMANT sur un serveur sain : il n'agit que si l'updater n'a pas tourné depuis
# ~36 h (l'updater rafraîchit UPDATE_STAMP_FILE à chaque passage). Le seuil dépasse
# 24 h pour laisser un cron.daily sain faire foi malgré le jitter d'anacron : le
# filet ne s'active donc qu'après au moins un jour sauté.
self_heal_update_trigger() {
    local upd="/usr/local/sbin/update_ban_404.sh" now mt age
    [ "$DRY_RUN" = true ] && return 0
    [ "$(id -u)" -eq 0 ] || return 0
    [ -n "${REPO_RAW:-}" ] || return 0
    [ -x "$upd" ] || return 0
    now=$(date +%s); mt=$(stat -c %Y "$UPDATE_STAMP_FILE" 2>/dev/null || echo 0)
    age=$(( now - mt ))
    [ "$age" -lt 129600 ] && return 0      # < ~36 h : cron.daily a (ou a eu) la main
    t heal.update_triggered                # journalisé via le wrapper cron
    "$upd" >/dev/null 2>&1 || true         # l'updater journalise lui-même dans /var/log/ban_404.log
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

# Débannissement actif des IP whitelistées déjà présentes dans l'ipset (avant l'analyse,
# pour s'appliquer même s'il n'y a aucun nouveau suspect ce passage-ci).
enforce_whitelist_unban

# Auto-guérison éventuelle de l'updater legacy (one-shot ; sans effet si déjà moderne).
self_heal_updater

# Réconciliation du cron de résumé quotidien sur DAILY_SUMMARY (le crée/retire selon le réglage).
self_heal_summary_cron

# 1. Recherche des fichiers de logs
FILES_FOUND=()
for log_dir in ${BASE_DIR}/*/log/; do
    [ -d "$log_dir" ] || continue
    vhost="${log_dir%/log/}"; vhost="${vhost##*/}"   # nom du dossier vhost sous BASE_DIR
    if is_excluded_vhost "$vhost"; then
        [ "$VERBOSE" = true ] && t verbose.vhost_excluded "$vhost"
        continue
    fi
    if [ -f "${log_dir}access.log" ]; then
        FILES_FOUND+=("${log_dir}access.log")
    else
        # On écarte yesterday-access.log (symlink ISPConfig vers le log de la veille, souvent
        # périmé) : jamais le bon fichier à analyser.
        latest=$(ls -1t "${log_dir}"*access.log 2>/dev/null | grep -v '/yesterday-access\.log$' | head -n 1)
        [ -n "$latest" ] && FILES_FOUND+=("$latest")
    fi
done

# 2. Filtrage des fichiers lisibles
VALID_FILES=()
for file in "${FILES_FOUND[@]}"; do
    if [ -r "$file" ] && [ -s "$file" ]; then
        [ "$VERBOSE" = true ] && t verbose.log_ok "$file"
        VALID_FILES+=("$file")
    else
        [ "$VERBOSE" = true ] && t verbose.log_skip "$file"
    fi
done

if [ ${#VALID_FILES[@]} -eq 0 ]; then
    t no_valid_files
    exit 0
fi

# Borne basse de la fenêtre, au format AAAAMMJJHHMMSS (comparable directement, sans mktime)
CUTOFF=$(date -d "@$(( $(date +%s) - WINDOW ))" '+%Y%m%d%H%M%S')
[ "$VERBOSE" = true ] && t verbose.analyzing "${TAIL_LINES}" "$CUTOFF"

# 3. Extraction et tri via awk
#    - tail -q : seulement les dernières lignes de CHAQUE log (borne le coût)
#    - whitelist en correspondance EXACTE (split sur |)
#    - fenêtre temporelle (on ignore les 404 trop vieux)
#    - insensibilité à la casse via tolower() (le flag /i n'existe pas en awk)
#    - filtre anti-bruit + honeypots, seuils/motifs surchargeables via la conf.
#    Les motifs passent par ENVIRON (pas -v) : pas de re-traitement des échappements
#    (\.  reste \.) ; les seuils numériques passent par -v.
ips_data=$(tail -n "$TAIL_LINES" -q "${VALID_FILES[@]}" | \
    HONEYPOT_RE="$HONEYPOT_PATTERN" NOISE_RE="$NOISE_PATTERN" \
    awk -v wl="$WHITELIST_IP" -v cutoff="$CUTOFF" -v thr="$BAN_THRESHOLD" -v hp="$HONEYPOT_SCORE" '
BEGIN {
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", M, " ")
    for (i=1;i<=12;i++) mon[M[i]]=i
    n=split(wl, Wl, "|"); for (i=1;i<=n;i++) white[Wl[i]]=1
    noise_re = ENVIRON["NOISE_RE"]
    honeypot_re = ENVIRON["HONEYPOT_RE"]
}
$9 == 404 && !($1 in white) {

    # --- Fenêtre temporelle : $4 = [jj/Mon/aaaa:hh:mm:ss ---
    split(substr($4,2), d, /[\/:]/)
    ts = sprintf("%04d%02d%02d%02d%02d%02d", d[3], mon[d[2]], d[1], d[4], d[5], d[6])
    if (ts < cutoff) next

    p = tolower($7)

    # --- A. Bruit de fond (faux positifs) ---
    if (p ~ noise_re) next

    # --- B. Honeypots : +HONEYPOT_SCORE (ban quasi immédiat) ---
    if (p ~ honeypot_re) {
        count[$1] += hp
    } else {
        count[$1]++
    }
}
END {
    for (ip in count) if (count[ip] > thr) print count[ip], ip
}' | sort -rn)

if [ -z "$ips_data" ]; then
    [ "$VERBOSE" = true ] && t no_suspect
    exit 0
fi

changes_made=false
rules_simulated=0
new_bans=()   # accumulés pour la notification (format : "ip|score|honeypot")
[ "$VERBOSE" = true ] && t verbose.processing

# 4. Boucle de traitement
while read -r count ip; do
    [ -z "$ip" ] && continue

    crawler_domain=$(is_legit_crawler "$ip")
    if [ $? -eq 0 ]; then
        if [ "$DRY_RUN" = false ] && ipset test "$IPSET_NAME" "$ip" &>/dev/null; then
            t unban.crawler "$ip" "$crawler_domain" "$count"
            ipset del "$IPSET_NAME" "$ip"
            changes_made=true
        elif [ "$DRY_RUN" = true ] && ipset test "$IPSET_NAME" "$ip" &>/dev/null; then
            t sim.unban "$ip" "$crawler_domain"
            rules_simulated=$((rules_simulated + 1))
        else
            [ "$SHOW_BLOCKED" = true ] && t skip.crawler "$ip"
        fi
        continue
    fi

    # Whitelist CIDR : même logique que les crawlers (deban si présent, sinon skip)
    if in_whitelist_cidr "$ip"; then
        if [ "$DRY_RUN" = false ] && ipset test "$IPSET_NAME" "$ip" &>/dev/null; then
            t cidr.unban "$ip" "$count"
            ipset del "$IPSET_NAME" "$ip"
            changes_made=true
        elif [ "$DRY_RUN" = true ] && ipset test "$IPSET_NAME" "$ip" &>/dev/null; then
            t cidr.sim_unban "$ip"
            rules_simulated=$((rules_simulated + 1))
        else
            [ "$SHOW_BLOCKED" = true ] && t cidr.skip "$ip"
        fi
        continue
    fi

    if ipset test "$IPSET_NAME" "$ip" &>/dev/null; then
        [ "$SHOW_BLOCKED" = true ] && t already.banned "$ip" "$count"
    else
        if [ "$DRY_RUN" = true ]; then
            if [ "$count" -ge "$HONEYPOT_SCORE" ]; then
                t sim.ban_honeypot "$ip" "$count"
            else
                t sim.ban_add "$ip" "$count"
            fi
            rules_simulated=$((rules_simulated + 1))
        else
            if [ "$count" -ge "$HONEYPOT_SCORE" ]; then
                t ban.honeypot "$ip" "$count"; hp=1
                # Ban honeypot : timeout différencié (plus long que le défaut du set).
                ipset -exist add "$IPSET_NAME" "$ip" timeout "$HONEYPOT_BAN_TIMEOUT"
            else
                t ban.add "$ip" "$count"; hp=0
                ipset -exist add "$IPSET_NAME" "$ip"
            fi
            changes_made=true
            new_bans+=("$ip|$count|$hp")
        fi
    fi
done <<< "$ips_data"

# 5. Sauvegarde
[ "$VERBOSE" = true ] && t verbose.result_header
if [ "$DRY_RUN" = true ]; then
    t result.sim "$rules_simulated"
else
    if [ "$changes_made" = true ]; then
        [ "$VERBOSE" = true ] && t verbose.changes_saved
        mkdir -p "$(dirname "$IPSET_SAVE_FILE")"
        ipset save > "$IPSET_SAVE_FILE"
    else
        [ "$VERBOSE" = true ] && t verbose.no_change
    fi
    # Notification des nouveaux bans (si NOTIFY_BANS activé, seuil atteint et canal configuré)
    case "$NOTIFY_BANS" in
        true|1|yes|on)
            if [ "${#new_bans[@]}" -gt 0 ] && [ "${#new_bans[@]}" -ge "$NOTIFY_MIN_BANS" ]; then
                maybe_notify_new_bans
            fi ;;
    esac
fi

# Filet de sécurité MAJ : relance l'updater si cron.daily est resté muet (~36 h). En toute fin de
# run pour que, si l'updater remplace ce script (bascule atomique = nouvel inode), le process
# courant — déjà terminé — ne soit pas affecté. Dormant sur un serveur sain ; ne fait rien en dry-run.
self_heal_update_trigger
