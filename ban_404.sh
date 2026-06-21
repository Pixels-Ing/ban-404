#!/bin/bash

BAN404_VERSION="1.4.1"

# Configuration (valeurs par defaut ; surchargees par /etc/ban_404.conf)
BASE_DIR="/var/www"
IPSET_NAME="ban_404_list"
IPSET_SAVE_FILE="/etc/iptables/ipsets"   # chemin canonique du plugin ipset-persistent
BAN_TIMEOUT=172800   # 48 heures
WINDOW=7200          # Fenetre glissante en secondes (2h). Cron horaire => recouvrement, pas de trou aux bornes.
TAIL_LINES=50000     # On n'analyse que les N dernieres lignes de chaque log (borne le cout sur gros sites).
                     # A augmenter si un site depasse TAIL_LINES requetes dans la fenetre WINDOW.
LOCK_FILE="/run/ban_404_list.lock"
LOG_FILE="/var/log/ban_404.log"   # journal (ecrit par le wrapper cron) ; lu par --stats/--summary

# Seuils & motifs de detection (surchargables par la conf)
BAN_THRESHOLD=10     # Ban si le score depasse ce seuil dans la fenetre.
HONEYPOT_SCORE=100   # Score ajoute par hit honeypot (>= ce score => ban immediat).
HONEYPOT_PATTERN='\.env|wp-config\.php|phpmyadmin|config\.json|setup\.php|actuator|xmlrpc\.php'
NOISE_PATTERN='\.(jpg|jpeg|png|gif|webp|ico|css|js|svg|woff2?|map)$|apple-touch-icon|favicon|browserconfig\.xml|mstile|autodiscover\.xml|sitemap\.xml|robots\.txt|ads\.txt|\.well-known/(security\.txt|pki-validation)'

# Whitelist des IPs a ne JAMAIS bannir (separees par | ) -- correspondance EXACTE
WHITELIST_IP="127.0.0.1"

# Whitelist CIDR / sous-reseaux a ne JAMAIS bannir (separes par | ), ex: "10.0.0.0/8|192.168.0.0/16"
WHITELIST_CIDR=""

# Vhosts a EXCLURE de l'analyse (noms de dossier sous BASE_DIR, separes par | ),
# ex: "staging.exemple.com|interne.exemple.com". Vide => tous les vhosts sont analyses.
EXCLUDE_VHOSTS=""

# Notifications (optionnel ; vides => desactivees). Messages dans la langue BAN404_LANG.
WEBHOOK_URL=""        # POST JSON des nouveaux bans (Slack/Discord/Teams/n8n...)
NOTIFY_EMAIL=""       # e-mail des nouveaux bans (necessite un MTA : mail/sendmail)
NOTIFY_FROM=""        # expediteur e-mail (optionnel)
NOTIFY_MIN_BANS=1     # ne notifier que si AU MOINS N nouveaux bans dans le run
DAILY_SUMMARY=false   # resume quotidien (opt-in) : --summary n'envoie que si =true ET canal configure

# ============================================================================
#  i18n — messages multilingues (en, fr, de, es, it). Le code/les commentaires
#  restent en francais ; SEULS les messages affiches sont traduisibles.
#  Les tableaux sont independants de la langue : on peut les definir avant le
#  sourcing de la conf. La langue effective est resolue apres (detect_lang).
# ============================================================================
declare -A T_EN T_FR T_DE T_ES T_IT

T_EN[version.line]="ban_404.sh version %s"
T_FR[version.line]="ban_404.sh version %s"
T_DE[version.line]="ban_404.sh version %s"
T_ES[version.line]="ban_404.sh version %s"
T_IT[version.line]="ban_404.sh version %s"

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

T_EN[help.verbose]="  --verbose        Show details of the log search."
T_FR[help.verbose]="  --verbose        Afficher le détail de la recherche des logs."
T_DE[help.verbose]="  --verbose        Details der Log-Suche anzeigen."
T_ES[help.verbose]="  --verbose        Mostrar el detalle de la búsqueda de registros."
T_IT[help.verbose]="  --verbose        Mostrare il dettaglio della ricerca dei log."

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

T_EN[ban.honeypot]="[+] IMMEDIATE block (honeypot) of IP: %s"
T_FR[ban.honeypot]="[+] Blocage IMMÉDIAT (honeypot) de l'IP : %s"
T_DE[ban.honeypot]="[+] SOFORTIGE Sperre (Honeypot) der IP: %s"
T_ES[ban.honeypot]="[+] Bloqueo INMEDIATO (honeypot) de la IP: %s"
T_IT[ban.honeypot]="[+] Blocco IMMEDIATO (honeypot) dell'IP: %s"

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

T_EN[help.stats]="  --stats          Show ban statistics."
T_FR[help.stats]="  --stats          Afficher les statistiques de ban."
T_DE[help.stats]="  --stats          Sperr-Statistiken anzeigen."
T_ES[help.stats]="  --stats          Mostrar las estadísticas de bloqueo."
T_IT[help.stats]="  --stats          Mostrare le statistiche di blocco."

T_EN[help.summary]="  --summary        Send the daily summary via the configured channel (opt-in)."
T_FR[help.summary]="  --summary        Envoyer le résumé quotidien via le canal configuré (opt-in)."
T_DE[help.summary]="  --summary        Tägliche Zusammenfassung über den konfigurierten Kanal senden (opt-in)."
T_ES[help.summary]="  --summary        Enviar el resumen diario por el canal configurado (opt-in)."
T_IT[help.summary]="  --summary        Inviare il riepilogo giornaliero tramite il canale configurato (opt-in)."

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

T_EN[help.conf_webhook]="  WEBHOOK_URL      JSON POST of new bans (Slack/Discord/Teams...); empty = off."
T_FR[help.conf_webhook]="  WEBHOOK_URL      POST JSON des nouveaux bans (Slack/Discord/Teams...) ; vide = inactif."
T_DE[help.conf_webhook]="  WEBHOOK_URL      JSON-POST neuer Sperren (Slack/Discord/Teams...); leer = aus."
T_ES[help.conf_webhook]="  WEBHOOK_URL      POST JSON de nuevos bloqueos (Slack/Discord/Teams...); vacío = inactivo."
T_IT[help.conf_webhook]="  WEBHOOK_URL      POST JSON dei nuovi blocchi (Slack/Discord/Teams...); vuoto = disattivato."

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

T_EN[help.conf_daily]="  DAILY_SUMMARY    Daily summary (opt-in, default false), via the configured channel."
T_FR[help.conf_daily]="  DAILY_SUMMARY    Résumé quotidien (opt-in, défaut false), via le canal configuré."
T_DE[help.conf_daily]="  DAILY_SUMMARY    Tägliche Zusammenfassung (opt-in, Standard false), über den konfigurierten Kanal."
T_ES[help.conf_daily]="  DAILY_SUMMARY    Resumen diario (opt-in, por defecto false), por el canal configurado."
T_IT[help.conf_daily]="  DAILY_SUMMARY    Riepilogo giornaliero (opt-in, predefinito false), tramite il canale configurato."

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

T_EN[stats.header]="=[ ban-404 statistics ]="
T_FR[stats.header]="=[ Statistiques ban-404 ]="
T_DE[stats.header]="=[ ban-404-Statistiken ]="
T_ES[stats.header]="=[ Estadísticas ban-404 ]="
T_IT[stats.header]="=[ Statistiche ban-404 ]="

T_EN[stats.banned_now]="Currently banned: %s IP(s)"
T_FR[stats.banned_now]="Actuellement bannies : %s IP"
T_DE[stats.banned_now]="Aktuell gesperrt: %s IP(s)"
T_ES[stats.banned_now]="Actualmente bloqueadas: %s IP"
T_IT[stats.banned_now]="Attualmente bloccati: %s IP"

T_EN[stats.last24_bans]="Bans in the last 24h: %s"
T_FR[stats.last24_bans]="Bans sur les dernières 24h : %s"
T_DE[stats.last24_bans]="Sperren in den letzten 24h: %s"
T_ES[stats.last24_bans]="Bloqueos en las últimas 24h: %s"
T_IT[stats.last24_bans]="Blocchi nelle ultime 24h: %s"

T_EN[stats.last24_unbans]="Unbans in the last 24h: %s"
T_FR[stats.last24_unbans]="Débans sur les dernières 24h : %s"
T_DE[stats.last24_unbans]="Entsperrungen in den letzten 24h: %s"
T_ES[stats.last24_unbans]="Desbloqueos en las últimas 24h: %s"
T_IT[stats.last24_unbans]="Sblocchi nelle ultime 24h: %s"

T_EN[stats.top_header]="Top offending IPs (last 24h):"
T_FR[stats.top_header]="Top des IP fautives (24h) :"
T_DE[stats.top_header]="Top der auffälligen IPs (24h):"
T_ES[stats.top_header]="Top de IP infractoras (24h):"
T_IT[stats.top_header]="Top degli IP colpevoli (24h):"

T_EN[stats.top_item]="  %s  (%s event(s))"
T_FR[stats.top_item]="  %s  (%s événement(s))"
T_DE[stats.top_item]="  %s  (%s Ereignis(se))"
T_ES[stats.top_item]="  %s  (%s evento(s))"
T_IT[stats.top_item]="  %s  (%s evento/i)"

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

# Detection de la langue : locale du shell (ou /etc/default/locale en repli pour
# le contexte cron), code 2 lettres retenu s'il fait partie des langues gerees.
detect_lang() {
    local l="${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}"
    if [ -z "$l" ] && [ -r /etc/default/locale ]; then
        l=$(. /etc/default/locale 2>/dev/null; printf '%s' "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}")
    fi
    l="${l%%.*}"; l="${l%%_*}"; l="${l,,}"
    case "$l" in en|fr|de|es|it) printf '%s' "$l" ;; *) printf '%s' en ;; esac
}

# --- Surcharge par la config locale, NON versionnee (whitelist par serveur, REPO_RAW, langue, etc.) ---
CONF_FILE="/etc/ban_404.conf"
[ -f "$CONF_FILE" ] && . "$CONF_FILE"

# Resolution de la langue : conf > locale du shell > en. Puis validation.
: "${BAN404_LANG:=$(detect_lang)}"
BAN404_LANG="${BAN404_LANG,,}"
case "$BAN404_LANG" in en|fr|de|es|it) ;; *) BAN404_LANG=en ;; esac

# t <cle> [args...] : imprime la traduction (\n du format interpretes) + saut de ligne final.
# Le format est TOUJOURS notre chaine ; les donnees ($ip, $count...) passent en arguments
# positionnels consommes par les %s -> aucune injection de format possible.
t() {
    local key="$1"; shift
    local ref="T_${BAN404_LANG^^}[$key]"
    local fmt="${!ref-}"
    [ -z "$fmt" ] && fmt="${T_EN[$key]-}"   # fallback EN si la cle manque pour la langue
    [ -z "$fmt" ] && fmt="$key"             # ultime garde-fou : jamais muet
    # '--' : empeche printf d'interpreter un format commencant par '-' comme une option.
    # shellcheck disable=SC2059
    printf -- "$fmt\n" "$@"
}

# Initialisation des options
DRY_RUN=false
SHOW_BLOCKED=false
VERBOSE=false
DO_LIST=false
DO_STATS=false
LIST_BY_TIMEOUT=false

show_help() {
    t version.line "$BAN404_VERSION"
    t help.usage "$0"
    echo ""
    t help.options_header
    t help.dryrun
    t help.showblocked
    t help.verbose
    t help.list
    t help.bytimeout
    t help.stats
    t help.summary
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
    t help.conf_webhook
    t help.conf_email
    t help.conf_from
    t help.conf_min_bans
    t help.conf_daily
    t help.conf_advanced
    t help.conf_example_pointer
    exit 0
}

# --lang <code> : ecrit BAN404_LANG dans la conf (remplace ou ajoute), puis quitte.
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
        # cat > conserve les permissions/proprietaire de la conf (chmod 600 root)
        # decommente et/ou remplace la ligne BAN404_LANG (active ou commentee).
        if sed -E "s/^[[:space:]]*#?[[:space:]]*BAN404_LANG=.*/BAN404_LANG=\"$new_lang\"/" "$CONF_FILE" > "$tmp" && cat "$tmp" > "$CONF_FILE"; then
            rm -f "$tmp"
        else
            rm -f "$tmp"; t lang.write_fail "$CONF_FILE"; exit 1
        fi
    else
        {
            printf '\n# Langue des messages : en (defaut) | fr | de | es | it\n'
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

# ---------- Exclusion de vhosts (decouverte des logs) ----------
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
send_webhook() {  # $1 = texte complet
    [ -z "$WEBHOOK_URL" ] && return 0
    command -v curl >/dev/null 2>&1 || return 0
    local esc; esc=$(json_escape "$1")
    curl -fsS -m 15 -H 'Content-Type: application/json' \
         -X POST -d "{\"text\":\"$esc\",\"content\":\"$esc\"}" "$WEBHOOK_URL" >/dev/null 2>&1 || true
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
notify() {  # $1 = sujet, $2 = corps
    send_webhook "$1"$'\n'"$2"
    send_email "$1" "$2"
}
maybe_notify_new_bans() {
    [ -z "$WEBHOOK_URL" ] && [ -z "$NOTIFY_EMAIL" ] && return 0
    local host n subj body line ip sc hp
    host=$(hostname 2>/dev/null || echo '?')
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
build_stats_text() {
    local banned bans unbans cutoff24 top cnt ip
    banned=$(ipset list "$IPSET_NAME" 2>/dev/null | awk '/^Members:/{m=1;next} m&&NF{c++} END{print c+0}')
    cutoff24=$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    bans=0; unbans=0
    if [ -r "$LOG_FILE" ] && [ -n "$cutoff24" ]; then
        bans=$(awk -v c="$cutoff24" '($1" "$2) >= c && /\[\+\]/' "$LOG_FILE" | wc -l)
        unbans=$(awk -v c="$cutoff24" '($1" "$2) >= c && /\[-\]/' "$LOG_FILE" | wc -l)
    fi
    t stats.header
    t stats.banned_now "$banned"
    t stats.last24_bans "$bans"
    t stats.last24_unbans "$unbans"
    if [ -r "$LOG_FILE" ] && [ -n "$cutoff24" ]; then
        top=$(awk -v c="$cutoff24" '($1" "$2) >= c && (/\[\+\]/||/\[-\]/){
            for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/){print $i; break}
        }' "$LOG_FILE" | sort | uniq -c | sort -rn | head -n 10)
        if [ -n "$top" ]; then
            t stats.top_header
            while read -r cnt ip; do [ -n "$ip" ] && t stats.top_item "$ip" "$cnt"; done <<< "$top"
        fi
    fi
}
do_list() {
    local members ip rest to_raw to fam key
    members=$(ipset list "$IPSET_NAME" 2>/dev/null | awk '/^Members:/{m=1;next} m&&NF{print}')
    t list.header "$IPSET_NAME"
    if [ -z "$members" ]; then t list.empty; return 0; fi
    # Construit des lignes triables "<clef>\t<ip>\t<timeout>", trie en LC_ALL=C
    # (ordre deterministe), puis affiche. Tri par defaut : IPv4 d'abord (octets
    # zero-paddes pour un ordre numerique croissant), puis IPv6. Avec --by-timeout :
    # tri croissant par timeout residuel.
    printf '%s\n' "$members" | while read -r ip rest; do
        to_raw=$(printf '%s' "$rest" | sed -n 's/.*timeout \([0-9]*\).*/\1/p')
        to="${to_raw:-?}"
        case "$ip" in *:*) fam=1 ;; *) fam=0 ;; esac
        if [ "$LIST_BY_TIMEOUT" = true ]; then
            key=$(printf '%012d' "${to_raw:-0}" 2>/dev/null || printf '%s' "${to_raw:-0}")
        elif [ "$fam" -eq 0 ]; then
            key="0_$(printf '%s' "$ip" | awk -F. '{printf "%03d.%03d.%03d.%03d",$1,$2,$3,$4}')"
        else
            key="1_$ip"
        fi
        printf '%s\t%s\t%s\n' "$key" "$ip" "$to"
    done | LC_ALL=C sort | while IFS=$'\t' read -r key ip to; do
        t list.item "$ip" "$to"
    done
}
do_summary() {
    case "$DAILY_SUMMARY" in true|1|yes|on) ;; *) exit 0 ;; esac
    [ -z "$WEBHOOK_URL" ] && [ -z "$NOTIFY_EMAIL" ] && exit 0
    local host; host=$(hostname 2>/dev/null || echo '?')
    notify "$(t summary.subject "$host")" "$(build_stats_text)"
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
        --list) DO_LIST=true; shift ;;
        --stats) DO_STATS=true; shift ;;
        --summary) do_summary ;;
        --version) t version.line "$BAN404_VERSION"; exit 0 ;;
        --help|-h) show_help ;;
        *) t err.unknown_opt "$1"; exit 1 ;;
    esac
done

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

# --- Auto-guerison de l'updater "legacy" -------------------------------------
# Certains serveurs portent un ancien updater qui ne met a jour QUE ban_404.sh
# (jamais lui-meme) : il ne se modernisera donc jamais seul. Or le moteur, lui,
# EST deploye partout (l'updater legacy le rafraichit). Le moteur peut donc
# reinstaller un updater moderne depuis REPO_RAW. Detection = absence de la
# variable UPDATER_VERSION (les updaters modernes la portent et s'auto-mettent
# a jour) ; des qu'un updater versionne est en place, ce bloc ne fait plus rien.
self_heal_updater() {
    local upd="/usr/local/sbin/update_ban_404.sh" repo="${REPO_RAW:-}" dir tmp
    [ "$DRY_RUN" = true ] && return 0
    [ "$(id -u)" -eq 0 ] || return 0
    [ -f "$upd" ] && grep -q '^UPDATER_VERSION=' "$upd" && return 0   # deja moderne
    [ -z "$repo" ] && return 0
    command -v curl >/dev/null 2>&1 || return 0
    dir=$(dirname "$upd")
    tmp=$(mktemp "$dir/.upd.XXXXXX" 2>/dev/null) || return 0
    # Telecharge -> valide (shebang + versionne + bash -n) -> bascule atomique (.bak)
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

# Auto-guerison eventuelle de l'updater legacy (one-shot ; sans effet si deja moderne).
self_heal_updater

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
        latest=$(ls -1t "${log_dir}"*access.log 2>/dev/null | head -n 1)
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

# Borne basse de la fenetre, au format AAAAMMJJHHMMSS (comparable directement, sans mktime)
CUTOFF=$(date -d "@$(( $(date +%s) - WINDOW ))" '+%Y%m%d%H%M%S')
[ "$VERBOSE" = true ] && t verbose.analyzing "${TAIL_LINES}" "$CUTOFF"

# 3. Extraction et tri via awk
#    - tail -q : seulement les dernieres lignes de CHAQUE log (borne le cout)
#    - whitelist en correspondance EXACTE (split sur |)
#    - fenetre temporelle (on ignore les 404 trop vieux)
#    - insensibilite a la casse via tolower() (le flag /i n'existe pas en awk)
#    - filtre anti-bruit + honeypots, seuils/motifs surchargables via la conf.
#    Les motifs passent par ENVIRON (pas -v) : pas de re-traitement des echappements
#    (\.  reste \.) ; les seuils numeriques passent par -v.
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

    # --- Fenetre temporelle : $4 = [jj/Mon/aaaa:hh:mm:ss ---
    split(substr($4,2), d, /[\/:]/)
    ts = sprintf("%04d%02d%02d%02d%02d%02d", d[3], mon[d[2]], d[1], d[4], d[5], d[6])
    if (ts < cutoff) next

    p = tolower($7)

    # --- A. Bruit de fond (faux positifs) ---
    if (p ~ noise_re) next

    # --- B. Honeypots : +HONEYPOT_SCORE (ban quasi immediat) ---
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

    # Whitelist CIDR : meme logique que les crawlers (deban si present, sinon skip)
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
                t ban.honeypot "$ip"; hp=1
            else
                t ban.add "$ip" "$count"; hp=0
            fi
            ipset -exist add "$IPSET_NAME" "$ip"
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
    # Notification des nouveaux bans (si seuil atteint et canal configure)
    if [ "${#new_bans[@]}" -gt 0 ] && [ "${#new_bans[@]}" -ge "$NOTIFY_MIN_BANS" ]; then
        maybe_notify_new_bans
    fi
fi
