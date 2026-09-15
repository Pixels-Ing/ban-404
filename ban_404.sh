#!/bin/bash

BAN404_VERSION="2.3.11"

# Configuration (valeurs par défaut ; surchargées par /etc/ban_404.conf)
BASE_DIR="/var/www"
IPSET_NAME="ban_404_list"
IPSET_SAVE_FILE="/etc/iptables/ipsets"   # chemin canonique du plugin ipset-persistent
IPTABLES_RULES_FILE="/etc/iptables/rules.v4"   # persistance des règles iptables (plugin iptables-persistent)
FW_BACKEND="auto"    # backend pare-feu : auto (défaut = préférer iptables+ipset, coexistence) | iptables | nftables
FW_ACTIVE="iptables" # backend EFFECTIF, résolu par fw_init après le sourcing de la conf (ne pas régler à la main)
BAN_TIMEOUT=172800   # 48 heures
WINDOW=7200          # Fenêtre glissante en secondes (2h). Cron horaire => recouvrement, pas de trou aux bornes.
TAIL_LINES=50000     # On n'analyse que les N dernières lignes de chaque log (borne le coût sur gros sites).
                     # À augmenter si un site dépasse TAIL_LINES requêtes dans la fenêtre WINDOW.
LOCK_FILE="/run/ban_404_list.lock"
LOG_FILE="/var/log/ban_404.log"   # journal des événements (écrit par le moteur via log_line) ; lu par --stats/--summary
UPDATE_STAMP_FILE="/var/lib/ban_404/last_update"   # repère « l'updater a tourné » (écrit par update_ban_404.sh)
RUN_STAMP_FILE="/var/lib/ban_404/last_run"         # repère « le moteur a fini un run réel » (lu par --diag/--summary)
METRICS_FILE="/var/lib/ban_404/metrics"            # historique horaire load/IO/réseau/mémoire (moyennes 24 h du résumé)
IPSET_COUNTS_FILE="/var/lib/ban_404/ipset_counts"  # historique horaire du nb d'entrées par ipset (évol. + tendance 24 h du résumé)
OFFENDERS_FILE="/var/lib/ban_404/offenders"        # mémoire des récidives : « ip nb_bans epoch_fin_du_dernier_ban »
PLATFORM_VALIDATED=""   # fail-safe plateforme : vide = auto-détection (os-release distro + backend iptables/ipset) ;
                        # true = forcer l'application même sur plateforme non reconnue (l'admin assume le risque) ; false = forcer la lecture seule

# Seuils & motifs de détection (surchargeables par la conf)
BAN_THRESHOLD=10     # Ban si le score dépasse ce seuil dans la fenêtre.
HONEYPOT_SCORE=100   # Score ajouté par hit honeypot (>= ce score => ban immédiat).
HONEYPOT_BAN_TIMEOUT=604800   # Timeout du ban honeypot (s) : 7 j, plus long que BAN_TIMEOUT (flood 404).
# Bannissement gradué des IP agressives et RÉCIDIVISTES (depuis 2.3.0). Paliers de récidive (s),
# séparés par des espaces : 7 j, 14 j, 24 j. Le palier 0 de chaque circuit reste la variable
# existante (BAN_TIMEOUT pour un flood 404, HONEYPOT_BAN_TIMEOUT pour le circuit honeypot) => une
# IP vue pour la 1re fois est traitée EXACTEMENT comme avant. Vide => escalade désactivée
# (comportement historique strict). Plafond dur : 2147483 s (limite ipset), cf. ipt_ban_ip_ttl.
BAN_ESCALATION="604800 1209600 2073600"
# Période d'épreuve APRÈS LIBÉRATION (s) : au-delà de ce délai sans le moindre ban, le compteur de
# récidive de l'IP est oublié. Datée sur la FIN du ban (et non sa pose) => sens constant à tous les
# paliers. Défaut 24 j = la durée du ban maximal.
ESCALATION_MEMORY=2073600
# Score (count) au-delà duquel une IP démarre un palier plus haut dès son PREMIER ban : 500 = un
# flood de 500 x 404 dans la fenêtre, ou 5 chemins-pièges touchés (100/hit), ou ~400 POST de
# brute-force (100 forfaitaires + 1/POST). 0 => désactivé.
AGGRESSIVE_SCORE=500
HONEYPOT_PATTERN='\.env|wp-config\.php|phpmyadmin|config\.json|setup\.php|actuator|xmlrpc\.php'
NOISE_PATTERN='\.(jpg|jpeg|png|gif|webp|ico|css|js|svg|woff2?|map)$|apple-touch-icon|favicon|browserconfig\.xml|mstile|autodiscover\.xml|sitemap\.xml|robots\.txt|ads\.txt|\.well-known/(security\.txt|pki-validation)'
# Signatures sécurité testées sur la requête ($7) QUEL QUE SOIT le statut HTTP (contrairement aux
# honeypots, limités aux 404) : traversée de répertoires, sondes RCE, SQLi encodées, bots à liens
# ré-encodés, « ? » encodé dans la valeur d'un paramètre. Match => +HONEYPOT_SCORE (ban immédiat,
# timeout HONEYPOT_BAN_TIMEOUT). Vide => désactivé.
#
# CRITÈRE D'INCLUSION, strict : aucun client légitime — ni navigateur, ni crawler, NI L'APPLICATION
# ELLE-MÊME — ne produit jamais la chaîne. C'est ce critère qui a fait SORTIR du défaut, en 2.3.9,
# la signature du paramètre `resultsPerPage` dupliqué : PrestaShop empile lui-même ce paramètre dans
# les liens de facettes de son thème, donc la signature décrivait une URL que le site fabrique. Elle
# a valu un ban de 7 j à Googlebot et Bingbot (juil. 2026), colmaté à grands frais par le mécanisme
# crawler_hint, puis s'est révélée inopérante à la mesure (13 sept. 2026, les DEUX serveurs
# PrestaShop du parc) : sur l'un elle représentait 100 % des bans pour des IP n'émettant qu'UNE
# requête et ne revenant jamais — donc zéro requête empêchée — et sur l'autre elle ne se déclenchait
# pas une seule fois en 139 575 lignes. Le bon endroit pour ce cas est le serveur web, en amont de
# PHP : une déduplication 301 y coûte moins et ne blackhole personne. Réactivation possible par
# conf locale, documentée dans ban_404.conf.example.
SECURITY_PATTERN='etc(/|%2f)passwd|\.\./\.\.|%2e%2e%2f|\.\.%2f|%00|vendor/phpunit|eval-stdin\.php|union(\+|%20)select|information_schema|amp%3bamp%3b|resultsperpage=[^& ]*%3f'
# Flood POST (brute-force) : POST dont la requête matche ce motif, comptés dans la fenêtre WINDOW ;
# au-delà de POST_FLOOD_THRESHOLD => +HONEYPOT_SCORE. Défaut : login/xmlrpc WordPress. Le seuil
# tolère plusieurs utilisateurs légitimes derrière un même NAT. Motif vide => désactivé.
POST_FLOOD_PATTERN='wp-login\.php|xmlrpc\.php'
POST_FLOOD_THRESHOLD=20
# Nombre minimal de chemins DISTINCTS en 404 exigé pour un ban de VOLUME (1 => désactivé,
# comportement historique strict). Un scanner balaie des chemins VARIÉS ; un navigateur bloqué sur
# un asset manquant martèle UNE SEULE URL — 11 fois le même 404 en 56 s ont suffi à bannir 48 h
# l'IP publique d'un client légitime (incident du 20 août 2026 : fichier de langue absent du
# déploiement, réclamé par 25 templates). Ne touche NI au score (donc ni aux paliers d'escalade, ni
# aux Top 24 h), NI aux autres circuits : une IP ayant touché un honeypot, une signature
# SECURITY_PATTERN ou un flood POST reste bannie quoi qu'il arrive. Seules changent de sort les IP
# dont TOUTES les 404 portent sur une seule et même URL — exactement la classe de faux positifs
# visée. Mesuré sur le parc (5 serveurs, 21 août 2026) : aucune IP réellement bannie n'y échappe.
DISTINCT_PATH_MIN=2

# Plages d'où PEUT provenir un crawler légitime (Googlebot, Bingbot, Yandex, Baidu, Apple), sous
# forme de préfixes d'IP séparés par des espaces. PRÉ-FILTRE BON MARCHÉ, rien d'autre : il décide
# si l'on paie le FCrDNS (deux lookups DNS) sur un ban du circuit honeypot/sécurité et lors du
# balayage à froid de l'ipset. La décision reste TOUJOURS au FCrDNS (PTR + re-résolution) : cette
# liste n'épargne aucune IP par elle-même, une IP louée dans une de ces plages est bannie comme
# les autres. Née d'un cas réel (31 juil. 2026) : Googlebot et Bingbot bannis 7 j sur la signature
# « paramètre resultsPerPage dupliqué » — que PrestaShop produit lui-même dans ses liens de
# facettes — car le circuit honeypot sautait purement et simplement le contrôle crawler.
# Constante de tête : définie AVANT le sourcing de la conf, donc surchargeable localement
# (même statut que CADENCE_CALM_SECS), sans être réconciliée par l'updater.
CRAWLER_HINT_PREFIXES="66.249. 64.233. 66.102. 72.14. 74.125. 209.85. 216.239. 40.77. 13.66. 157.55. 207.46. 20.191. 52.167. 199.30. 40.88. 5.45. 37.9. 37.140. 77.88. 84.252. 87.250. 90.156. 93.158. 95.108. 141.8. 178.154. 213.180. 180.76. 220.181. 123.125. 17."
# Nb max d'IP soumises au FCrDNS lors du balayage à froid (borne le coût DNS d'un run). En pratique
# jamais atteint : sur un set de 23 694 membres, le pré-filtre ne retenait que 9 candidats.
CRAWLER_SCAN_MAX=100

# Whitelist des IPs à ne JAMAIS bannir (séparées par | ) -- correspondance EXACTE
WHITELIST_IP="127.0.0.1"

# Whitelist CIDR / sous-réseaux à ne JAMAIS bannir (séparés par | ), ex: "10.0.0.0/8|192.168.0.0/16"
WHITELIST_CIDR=""

# Vhosts à EXCLURE de l'analyse (noms de dossier sous BASE_DIR, séparés par | ),
# ex: "staging.exemple.com|interne.exemple.com". Vide => tous les vhosts sont analysés.
EXCLUDE_VHOSTS=""

# Profil de layout des logs (découverte) : auto (défaut = sonder les chemins connus) | ispconfig
# (défaut historique : ${BASE_DIR}/*/log/access.log) | cpanel (/var/log/apache2/domlogs/<domaine>) |
# directadmin (/var/log/httpd/domains/<domaine>.log) | plesk (/var/www/vhosts/<domaine>/logs/access*) |
# nginx (/var/log/nginx/*access*.log) | generic (${BASE_DIR}/**/*access*.log). Le PARSEUR (combiné
# Apache/nginx) est le même partout : seule la découverte de fichiers change. Valeur inconnue => ispconfig.
LOG_PROFILE="auto"

# Cadence d'exécution supplémentaire (opt-in) : vide = passage horaire seul (cron.hourly, défaut) ;
# entier 5-30 = le moteur tourne AUSSI toutes les N minutes ; "auto" = adaptatif — tick toutes les
# 5 min, mais intervalle EFFECTIF modulé 5→60 min selon l'activité (hystérésis), avec une
# sentinelle légère capable de forcer un run complet en ≤ 5 min sur signes d'attaque. Le fichier
# /etc/cron.d/ban_404_step est géré par le moteur (self_heal_step_cron) : créé/aligné/retiré
# selon ce réglage. Valeur invalide => ignorée (horaire seul), le run n'échoue jamais.
CRON_STEP=""
CADENCE_FILE="/var/lib/ban_404/cadence"   # état du mode auto : « intervalle epoch_dernier_ban »
CADENCE_CALM_SECS=1800     # mode auto : accalmie (s) sans ban RÉEL (hp=0, hors bruit honeypot) avant de relâcher d'un cran
CADENCE_SURGE=3            # mode auto : nb de bans RÉELS dans UN MÊME run qui fait descendre de 2 crans (au lieu d'1)
SENTINEL_LINES=2000        # lignes survolées par log par la sentinelle (mode auto, tick porté)
SAMPLE_MIN_INTERVAL=3300   # espacement mini (s) des échantillons metrics/ipset : l'historique reste
                           # ~horaire même quand CRON_STEP fait tourner le moteur toutes les 5-10 min ;
                           # en mode auto, la porte de cadence force un run dès qu'un relevé est dû
WINDOW_NOTE_SECS=72000     # note « fenêtre réelle » des blocs 24 h seulement si l'historique couvre MOINS
                           # (20 h). Pas 23 h : relevés ~horaires non calés sur l'heure du résumé => jusqu'à
                           # ~1 h perdue à chaque bout, un serveur sain oscille entre 22 h et 24 h (bruit quotidien)

# Notifications (optionnel ; vides => désactivées). Messages dans la langue BAN404_LANG.
WEBHOOK_URL=""        # POST JSON des nouveaux bans (Slack/Discord/Teams/n8n...)
WEBHOOK_CHAT_CARD=true   # Google Chat : résumé quotidien en CARTE colorée (cardsV2) ; false => texte simple sans couleur
NOTIFY_EMAIL=""       # e-mail des nouveaux bans (nécessite un MTA : mail/sendmail)
NOTIFY_FROM=""        # expéditeur e-mail (optionnel)
NOTIFY_MIN_BANS=1     # ne notifier que si AU MOINS N nouveaux bans dans le run
NOTIFY_BANS=false     # alerte à chaque run quand des IP sont bannies (true pour activer)
DAILY_SUMMARY=false   # résumé quotidien (opt-in) : --summary n'envoie que si =true ET canal configuré
SERVER_NICKNAME=""    # nom convivial ajouté au hostname dans les notifs (vide => hostname seul). Ex: "Boutique (prod)"
# Google Chat borne la taille d'un message (~4096 car.) : au-delà, l'API répond 400 et le résumé est
# PERDU. Plutôt que de dégrader, on DÉCOUPE en plusieurs messages (cf. webhook_split/send_webhook).
WEBHOOK_CHAT_MAXLEN=3800   # taille max d'un morceau (marge pour l'enveloppe JSON et le titre)
WEBHOOK_CHAT_MAXPARTS=4    # garde-fou anti-rafale : au-delà, le surplus est tronqué (jamais N messages)

# Reverse DNS (PTR) des IP affichées par --list/--stats/--summary (opt-in ; le flag --resolve force)
RESOLVE_PTR=false     # true => résoudre le PTR des IP ; borné par PTR_TIMEOUT pour ne pas bloquer
PTR_TIMEOUT=2         # délai max par lookup getent (s), borne le coût du reverse

# Signes vitaux du serveur (load, mémoire, disque, MTA, IO) dans diag et le résumé quotidien.
# Les valeurs s'affichent toujours (bloc « Signes vitaux ») ; un seuil franchi remonte en [WARN]
# (service postfix arrêté => [FAIL] : du courrier se perd activement). --no-health saute ces
# contrôles pour un run ; HEALTH_CHECKS=false les désactive durablement (la sous-commande
# « health » force toujours).
HEALTH_CHECKS=true    # false => aucun contrôle de signes vitaux (diag et résumé)
HEALTH_LOAD_WARN=2    # [WARN] si load 15 min > N x cœurs
HEALTH_MEM_WARN=10    # [WARN] si MemAvailable < N % de MemTotal
HEALTH_DISK_WARN=90   # [WARN] si espace OU inodes > N % (sur / et /var si partition distincte)
HEALTH_MAILQ_WARN=50  # [WARN] si file postfix > N messages
HEALTH_IO_WARN=25     # [WARN] si pression IO (PSI some avg60) > N %
# Seuils « critique » (rouge) : franchis => [FAIL] rouge au lieu du [WARN] orange (coloration graduée
# vert/orange/rouge des signes vitaux, 1.6.5). Doivent être STRICTEMENT au-delà du seuil WARN.
HEALTH_LOAD_CRIT=4    # [FAIL] si load 15 min > N x cœurs (> HEALTH_LOAD_WARN)
HEALTH_MEM_CRIT=5     # [FAIL] si MemAvailable < N % (< HEALTH_MEM_WARN)
HEALTH_DISK_CRIT=95   # [FAIL] si espace OU inodes > N % (> HEALTH_DISK_WARN)
HEALTH_MAILQ_CRIT=500 # [FAIL] si file postfix > N messages (> HEALTH_MAILQ_WARN)
HEALTH_IO_CRIT=50     # [FAIL] si pression IO (PSI some avg60) > N % (> HEALTH_IO_WARN)

# Graduation des triangles de tendance du bloc « Comptage ipset » (tranche = intensité |%| sur la
# valeur : rien si < flat / ▼▲ modéré / ▼▼▲▲ fort ; couleur = direction, baisse=vert, hausse=rouge).
# Constantes internes (non auto-documentées dans la conf, mais surchargeables car définies avant le
# sourcing) ; promotion en réglages documentés = suivi trivial si besoin.
TREND_FLAT_PCT=2        # |Δ 24 h| < N %  => AUCUN triangle (calme), nombre en neutre
TREND_STRONG_PCT=10     # |Δ 24 h| >= N % => triangle DOUBLE (fort)
TREND_RECENT_WINDOW=10800  # fenêtre « tendance récente » (s) = 3 h (pente des dernières heures)
TREND_RECENT_FLAT_PCT=1    # seuils plus serrés que 24 h (fenêtre courte => petits mouvements)
TREND_RECENT_STRONG_PCT=5
TREND_SPARK_MAX=8          # longueur max de la sparkline (graphe COURT ; sous-échantillonnage régulier au-delà)
# Mode de rendu des glyphes colorés : 'plain' (défaut, texte nu) / 'ansi' (posé au terminal par
# build_stats_text via [ -t 1 ]) / 'html' (réservé au lot 2, e-mail HTML). Le résumé sort en 'plain'
# (redirection fichier => non-TTY) : aucun code couleur dans le mail/webhook.
OUTPUT_MODE=plain

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

T_EN[help.usage]="Usage: %s [SUBCOMMAND] [OPTIONS]"
T_FR[help.usage]="Usage : %s [SOUS-COMMANDE] [OPTIONS]"
T_DE[help.usage]="Aufruf: %s [UNTERBEFEHL] [OPTIONEN]"
T_ES[help.usage]="Uso: %s [SUBCOMANDO] [OPCIONES]"
T_IT[help.usage]="Uso: %s [SOTTOCOMANDO] [OPZIONI]"

T_EN[help.subcommands_header]="Subcommands:"
T_FR[help.subcommands_header]="Sous-commandes :"
T_DE[help.subcommands_header]="Unterbefehle:"
T_ES[help.subcommands_header]="Subcomandos:"
T_IT[help.subcommands_header]="Sottocomandi:"

T_EN[help.compat]="  (Legacy forms --list, --stats, --diag... remain accepted.)"
T_FR[help.compat]="  (Les formes historiques --list, --stats, --diag... restent acceptées.)"
T_DE[help.compat]="  (Die historischen Formen --list, --stats, --diag... werden weiterhin akzeptiert.)"
T_ES[help.compat]="  (Las formas históricas --list, --stats, --diag... siguen aceptándose.)"
T_IT[help.compat]="  (Le forme storiche --list, --stats, --diag... restano accettate.)"

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

T_EN[help.verbose]="  --verbose        Detail the run (log search), or per-folder causes with diag/stats."
T_FR[help.verbose]="  --verbose        Détailler le run (recherche des logs), ou les dossiers avec diag/stats."
T_DE[help.verbose]="  --verbose        Den Lauf (Log-Suche) oder die Verzeichnisse mit diag/stats detaillieren."
T_ES[help.verbose]="  --verbose        Detallar el run (búsqueda de registros), o las carpetas con diag/stats."
T_IT[help.verbose]="  --verbose        Dettagliare il run (ricerca dei log), o le cartelle con diag/stats."

T_EN[help.nolog]="  --no-log         Do not write this run's events ([+]/[-]) to the log file."
T_FR[help.nolog]="  --no-log         Ne pas écrire les événements de ce run ([+]/[-]) dans le journal."
T_DE[help.nolog]="  --no-log         Die Ereignisse dieses Laufs ([+]/[-]) nicht in die Logdatei schreiben."
T_ES[help.nolog]="  --no-log         No escribir los eventos de esta ejecución ([+]/[-]) en el registro."
T_IT[help.nolog]="  --no-log         Non scrivere gli eventi di questa esecuzione ([+]/[-]) nel registro."

T_EN[help.lang]="  lang <code>      Set the language (en, fr, de, es, it) in the config and exit."
T_FR[help.lang]="  lang <code>      Définir la langue (en, fr, de, es, it) dans la config et quitter."
T_DE[help.lang]="  lang <code>      Sprache (en, fr, de, es, it) in der Konfiguration setzen und beenden."
T_ES[help.lang]="  lang <code>      Definir el idioma (en, fr, de, es, it) en la configuración y salir."
T_IT[help.lang]="  lang <code>      Impostare la lingua (en, fr, de, es, it) nella configurazione e uscire."

T_EN[help.version]="  version          Show the version and exit."
T_FR[help.version]="  version          Afficher la version et quitter."
T_DE[help.version]="  version          Version anzeigen und beenden."
T_ES[help.version]="  version          Mostrar la versión y salir."
T_IT[help.version]="  version          Mostrare la versione e uscire."

T_EN[help.help]="  help             Show this help message."
T_FR[help.help]="  help             Afficher ce message d'aide."
T_DE[help.help]="  help             Diese Hilfemeldung anzeigen."
T_ES[help.help]="  help             Mostrar este mensaje de ayuda."
T_IT[help.help]="  help             Mostrare questo messaggio di aiuto."

T_EN[err.unknown_opt]="Unknown option or subcommand: %s. Use 'help'."
T_FR[err.unknown_opt]="Option ou sous-commande inconnue : %s. Utilisez « help »."
T_DE[err.unknown_opt]="Unbekannte Option oder unbekannter Unterbefehl: %s. Verwenden Sie 'help'."
T_ES[err.unknown_opt]="Opción o subcomando desconocido: %s. Use 'help'."
T_IT[err.unknown_opt]="Opzione o sottocomando sconosciuto: %s. Usare 'help'."

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

T_EN[heal.summary_cron_syntax]="[*] Daily-summary cron rewritten (new syntax): %s"
T_FR[heal.summary_cron_syntax]="[*] Cron de résumé quotidien réécrit (nouvelle syntaxe) : %s"
T_DE[heal.summary_cron_syntax]="[*] Tageszusammenfassungs-Cron neu geschrieben (neue Syntax): %s"
T_ES[heal.summary_cron_syntax]="[*] Cron de resumen diario reescrito (nueva sintaxis): %s"
T_IT[heal.summary_cron_syntax]="[*] Cron del riepilogo giornaliero riscritto (nuova sintassi): %s"

T_EN[heal.summary_cron_removed]="[*] Daily-summary cron removed (DAILY_SUMMARY disabled): %s"
T_FR[heal.summary_cron_removed]="[*] Cron de résumé quotidien retiré (DAILY_SUMMARY désactivé) : %s"
T_DE[heal.summary_cron_removed]="[*] Tageszusammenfassungs-Cron entfernt (DAILY_SUMMARY deaktiviert): %s"
T_ES[heal.summary_cron_removed]="[*] Cron de resumen diario eliminado (DAILY_SUMMARY desactivado): %s"
T_IT[heal.summary_cron_removed]="[*] Cron del riepilogo giornaliero rimosso (DAILY_SUMMARY disattivato): %s"

T_EN[heal.summary_cron_renamed]="[*] Daily-summary cron renamed to %s (now runs after the updater)."
T_FR[heal.summary_cron_renamed]="[*] Cron de résumé quotidien renommé en %s (passe désormais après l'updater)."
T_DE[heal.summary_cron_renamed]="[*] Tageszusammenfassungs-Cron umbenannt in %s (läuft nun nach dem Updater)."
T_ES[heal.summary_cron_renamed]="[*] Cron de resumen diario renombrado a %s (ahora se ejecuta después del updater)."
T_IT[heal.summary_cron_renamed]="[*] Cron del riepilogo giornaliero rinominato in %s (ora viene eseguito dopo l'updater)."

T_EN[heal.update_triggered]="[*] cron.daily silent — updater triggered from the hourly run."
T_FR[heal.update_triggered]="[*] cron.daily muet — updater relancé depuis le passage horaire."
T_DE[heal.update_triggered]="[*] cron.daily stumm — Updater vom stündlichen Lauf ausgelöst."
T_ES[heal.update_triggered]="[*] cron.daily en silencio — updater lanzado desde la ejecución horaria."
T_IT[heal.update_triggered]="[*] cron.daily silenzioso — updater avviato dall'esecuzione oraria."

T_EN[heal.step_cron]="[*] Step cron installed: %s (CRON_STEP=%s)"
T_FR[heal.step_cron]="[*] Cron de ticks intermédiaires installé : %s (CRON_STEP=%s)"
T_DE[heal.step_cron]="[*] Zwischentakt-Cron installiert: %s (CRON_STEP=%s)"
T_ES[heal.step_cron]="[*] Cron de ticks intermedios instalado: %s (CRON_STEP=%s)"
T_IT[heal.step_cron]="[*] Cron dei tick intermedi installato: %s (CRON_STEP=%s)"

T_EN[heal.step_cron_syntax]="[*] Step cron rewritten (setting changed): %s"
T_FR[heal.step_cron_syntax]="[*] Cron de ticks intermédiaires réécrit (réglage modifié) : %s"
T_DE[heal.step_cron_syntax]="[*] Zwischentakt-Cron neu geschrieben (Einstellung geändert): %s"
T_ES[heal.step_cron_syntax]="[*] Cron de ticks intermedios reescrito (ajuste modificado): %s"
T_IT[heal.step_cron_syntax]="[*] Cron dei tick intermedi riscritto (impostazione modificata): %s"

T_EN[heal.step_cron_removed]="[*] Step cron removed (CRON_STEP disabled): %s"
T_FR[heal.step_cron_removed]="[*] Cron de ticks intermédiaires retiré (CRON_STEP désactivé) : %s"
T_DE[heal.step_cron_removed]="[*] Zwischentakt-Cron entfernt (CRON_STEP deaktiviert): %s"
T_ES[heal.step_cron_removed]="[*] Cron de ticks intermedios eliminado (CRON_STEP desactivado): %s"
T_IT[heal.step_cron_removed]="[*] Cron dei tick intermedi rimosso (CRON_STEP disattivato): %s"

T_EN[heal.logrotate_daily]="[*] Log rotation switched to daily (24 h counters no longer truncated): %s"
T_FR[heal.logrotate_daily]="[*] Rotation du journal passée en quotidien (compteurs 24 h non tronqués) : %s"
T_DE[heal.logrotate_daily]="[*] Log-Rotation auf täglich umgestellt (24-h-Zähler nicht mehr abgeschnitten): %s"
T_ES[heal.logrotate_daily]="[*] Rotación del registro cambiada a diaria (contadores de 24 h ya no truncados): %s"
T_IT[heal.logrotate_daily]="[*] Rotazione del registro passata a giornaliera (contatori 24 h non più troncati): %s"

T_EN[sentinel.triggered]="[i] Sentinel: attack signs since the last full run — full analysis forced."
T_FR[sentinel.triggered]="[i] Sentinelle : signes d'attaque depuis le dernier run complet — analyse complète forcée."
T_DE[sentinel.triggered]="[i] Wächter: Angriffszeichen seit dem letzten vollständigen Lauf — vollständige Analyse erzwungen."
T_ES[sentinel.triggered]="[i] Centinela: señales de ataque desde la última ejecución completa — análisis completo forzado."
T_IT[sentinel.triggered]="[i] Sentinella: segni di attacco dall'ultima esecuzione completa — analisi completa forzata."

T_EN[cadence.adjusted]="[i] Auto cadence: effective interval %s -> %s min"
T_FR[cadence.adjusted]="[i] Cadence auto : intervalle effectif %s -> %s min"
T_DE[cadence.adjusted]="[i] Auto-Takt: effektives Intervall %s -> %s min"
T_ES[cadence.adjusted]="[i] Cadencia auto: intervalo efectivo %s -> %s min"
T_IT[cadence.adjusted]="[i] Cadenza auto: intervallo effettivo %s -> %s min"

T_EN[platform.readonly]="[i] Unvalidated platform (unknown distro/firewall backend) — READ-ONLY mode, no firewall write. Override: PLATFORM_VALIDATED."
T_FR[platform.readonly]="[i] Plateforme non validée (distro/back-end pare-feu inconnus) — mode LECTURE SEULE, aucune écriture pare-feu. Override : PLATFORM_VALIDATED."
T_DE[platform.readonly]="[i] Nicht validierte Plattform (unbekannte Distro/Firewall-Backend) — NUR-LESE-Modus, keine Firewall-Schreibvorgänge. Override: PLATFORM_VALIDATED."
T_ES[platform.readonly]="[i] Plataforma no validada (distro/backend de firewall desconocidos) — modo SOLO LECTURA, sin escritura de firewall. Override: PLATFORM_VALIDATED."
T_IT[platform.readonly]="[i] Piattaforma non validata (distro/backend firewall sconosciuti) — modalità SOLA LETTURA, nessuna scrittura firewall. Override: PLATFORM_VALIDATED."

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

# Déban à froid : l'IP n'était plus candidate (une IP droppée n'émet plus de requêtes), elle a
# donc été rattrapée par le balayage de l'ipset — d'où l'absence de compteur de 404.
T_EN[unban.crawler_cold]="[-] Unbanning IP (legitimate crawler, cold sweep): %s (%s)"
T_FR[unban.crawler_cold]="[-] Déblocage de l'IP (crawler légitime, balayage à froid) : %s (%s)"
T_DE[unban.crawler_cold]="[-] Entsperrung der IP (legitimer Crawler, Kaltdurchlauf): %s (%s)"
T_ES[unban.crawler_cold]="[-] Desbloqueo de la IP (crawler legítimo, barrido en frío): %s (%s)"
T_IT[unban.crawler_cold]="[-] Sblocco dell'IP (crawler legittimo, scansione a freddo): %s (%s)"

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

# Variantes « escaladées » : mêmes lignes, complétées par le rang du ban et sa durée. CONTRAINTE —
# le parsing des Top 24 h relit le PREMIER nombre situé après l'IP, donc tout ajout doit rester en
# FIN de ligne, après le groupe entre parenthèses (voir build_stats_text).
T_EN[ban.add_esc]="[+] Block (ipset) of IP: %s (%s 404 errors) — ban no. %s, duration %s"
T_FR[ban.add_esc]="[+] Blocage (ipset) de l'IP : %s (%s erreurs 404) — ban n°%s, durée %s"
T_DE[ban.add_esc]="[+] Sperre (ipset) der IP: %s (%s 404-Fehler) — Sperre Nr. %s, Dauer %s"
T_ES[ban.add_esc]="[+] Bloqueo (ipset) de la IP: %s (%s errores 404) — bloqueo n.º %s, duración %s"
T_IT[ban.add_esc]="[+] Blocco (ipset) dell'IP: %s (%s errori 404) — blocco n. %s, durata %s"

T_EN[ban.honeypot_esc]="[+] IMMEDIATE block (honeypot) of IP: %s (score %s) — ban no. %s, duration %s"
T_FR[ban.honeypot_esc]="[+] Blocage IMMÉDIAT (honeypot) de l'IP : %s (score %s) — ban n°%s, durée %s"
T_DE[ban.honeypot_esc]="[+] SOFORTIGE Sperre (Honeypot) der IP: %s (Score %s) — Sperre Nr. %s, Dauer %s"
T_ES[ban.honeypot_esc]="[+] Bloqueo INMEDIATO (honeypot) de la IP: %s (puntuación %s) — bloqueo n.º %s, duración %s"
T_IT[ban.honeypot_esc]="[+] Blocco IMMEDIATO (honeypot) dell'IP: %s (punteggio %s) — blocco n. %s, durata %s"

# Ban REFUSÉ par le pare-feu (set plein, erreur ipset…). Marqueur [!] et non [+] : les compteurs
# 24 h ne lisent que [+]/[-], un ban qui n'a pas eu lieu ne doit donc jamais y entrer.
T_EN[ban.failed]="[!] Ban of IP %s REFUSED by the firewall — not applied, not counted."
T_FR[ban.failed]="[!] Bannissement de l'IP %s REFUSÉ par le pare-feu — non appliqué, non comptabilisé."
T_DE[ban.failed]="[!] Sperre der IP %s von der Firewall ABGELEHNT — nicht angewendet, nicht gezählt."
T_ES[ban.failed]="[!] Bloqueo de la IP %s RECHAZADO por el cortafuegos — no aplicado, no contabilizado."
T_IT[ban.failed]="[!] Blocco dell'IP %s RIFIUTATO dal firewall — non applicato, non conteggiato."

# Récapitulatif unique par run (et non une ligne par IP : sous un scan, le journal serait inondé).
# La chaîne « IPv6 » est volontairement présente dans les 5 langues — c'est un nom propre, et
# tests/integration.sh s'en sert comme ancre indépendante de la langue.
T_EN[ban.family_unsupported]="[i] %s candidate IPv6 address(es) ignored: this firewall backend only handles IPv4."
T_FR[ban.family_unsupported]="[i] %s adresse(s) IPv6 candidate(s) ignorée(s) : ce backend pare-feu ne gère que l'IPv4."
T_DE[ban.family_unsupported]="[i] %s IPv6-Kandidat(en) ignoriert: dieses Firewall-Backend unterstützt nur IPv4."
T_ES[ban.family_unsupported]="[i] %s dirección(es) IPv6 candidata(s) ignorada(s): este backend de cortafuegos solo gestiona IPv4."
T_IT[ban.family_unsupported]="[i] %s indirizzo/i IPv6 candidato/i ignorato/i: questo backend firewall gestisce solo IPv4."

T_EN[sim.ban_escalated]="[SIMULATION]     escalation: ban no. %s, duration %s"
T_FR[sim.ban_escalated]="[SIMULATION]     escalade : ban n°%s, durée %s"
T_DE[sim.ban_escalated]="[SIMULATION]     Eskalation: Sperre Nr. %s, Dauer %s"
T_ES[sim.ban_escalated]="[SIMULATION]     escalada: bloqueo n.º %s, duración %s"
T_IT[sim.ban_escalated]="[SIMULATION]     escalation: blocco n. %s, durata %s"

# Unités de durée (fmt_duration) — utilisées sans saut de ligne via $(t …).
T_EN[unit.hours]="h"
T_FR[unit.hours]="h"
T_DE[unit.hours]="Std."
T_ES[unit.hours]="h"
T_IT[unit.hours]="h"

T_EN[unit.days]="d"
T_FR[unit.days]="j"
T_DE[unit.days]="T"
T_ES[unit.days]="d"
T_IT[unit.days]="g"

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

T_EN[help.list]="  list             List banned IPs (timeout left), sorted by IP family."
T_FR[help.list]="  list             Lister les IP bannies (timeout restant), triées par famille d'IP."
T_DE[help.list]="  list             Gesperrte IPs auflisten (Rest-Timeout), nach IP-Familie sortiert."
T_ES[help.list]="  list             Listar las IP bloqueadas (timeout restante), ordenadas por familia de IP."
T_IT[help.list]="  list             Elencare gli IP bloccati (timeout residuo), ordinati per famiglia di IP."

T_EN[help.bytimeout]="  --by-timeout     With list: sort by remaining timeout (ascending)."
T_FR[help.bytimeout]="  --by-timeout     Avec list : trier par timeout restant (croissant)."
T_DE[help.bytimeout]="  --by-timeout     Mit list: nach verbleibendem Timeout sortieren (aufsteigend)."
T_ES[help.bytimeout]="  --by-timeout     Con list: ordenar por timeout restante (ascendente)."
T_IT[help.bytimeout]="  --by-timeout     Con list: ordinare per timeout residuo (crescente)."

T_EN[help.resolve]="  --resolve        Show reverse DNS (PTR) of IPs in list/stats/summary (opt-in)."
T_FR[help.resolve]="  --resolve        Afficher le reverse DNS (PTR) des IP dans list/stats/summary (opt-in)."
T_DE[help.resolve]="  --resolve        Reverse-DNS (PTR) der IPs in list/stats/summary anzeigen (opt-in)."
T_ES[help.resolve]="  --resolve        Mostrar el DNS inverso (PTR) de las IP en list/stats/summary (opt-in)."
T_IT[help.resolve]="  --resolve        Mostrare il reverse DNS (PTR) degli IP in list/stats/summary (opt-in)."

T_EN[help.avg]="  --avg            With stats/diag: add the 24h averages (load, I/O, network, memory)."
T_FR[help.avg]="  --avg            Avec stats/diag : ajouter les moyennes 24 h (load, IO, réseau, mémoire)."
T_DE[help.avg]="  --avg            Mit stats/diag: die 24-h-Durchschnitte hinzufügen (Last, I/O, Netzwerk, Speicher)."
T_ES[help.avg]="  --avg            Con stats/diag: añadir los promedios 24 h (carga, E/S, red, memoria)."
T_IT[help.avg]="  --avg            Con stats/diag: aggiungere le medie 24 h (carico, I/O, rete, memoria)."

T_EN[help.stats]="  stats            Show ban statistics."
T_FR[help.stats]="  stats            Afficher les statistiques de ban."
T_DE[help.stats]="  stats            Sperr-Statistiken anzeigen."
T_ES[help.stats]="  stats            Mostrar las estadísticas de bloqueo."
T_IT[help.stats]="  stats            Mostrare le statistiche di blocco."

T_EN[help.unban]="  unban <IP|all>   Remove an IP (or all) from the ban list and exit."
T_FR[help.unban]="  unban <IP|all>   Retirer une IP (ou toutes) de la liste de bannissement et quitter."
T_DE[help.unban]="  unban <IP|all>   Eine IP (oder alle) aus der Sperrliste entfernen und beenden."
T_ES[help.unban]="  unban <IP|all>   Eliminar una IP (o todas) de la lista de bloqueo y salir."
T_IT[help.unban]="  unban <IP|all>   Rimuovere un IP (o tutti) dalla lista di blocco e uscire."

T_EN[help.summary]="  summary          Send the daily summary via the configured channel (opt-in)."
T_FR[help.summary]="  summary          Envoyer le résumé quotidien via le canal configuré (opt-in)."
T_DE[help.summary]="  summary          Tägliche Zusammenfassung über den konfigurierten Kanal senden (opt-in)."
T_ES[help.summary]="  summary          Enviar el resumen diario por el canal configurado (opt-in)."
T_IT[help.summary]="  summary          Inviare il riepilogo giornaliero tramite il canale configurato (opt-in)."

T_EN[help.checknotif]="  check-notification [email|webhook|all]  Send a test notification and report the result (default: all)."
T_FR[help.checknotif]="  check-notification [email|webhook|all]  Envoyer une notification de test et afficher le résultat (défaut : all)."
T_DE[help.checknotif]="  check-notification [email|webhook|all]  Eine Testbenachrichtigung senden und das Ergebnis anzeigen (Standard: all)."
T_ES[help.checknotif]="  check-notification [email|webhook|all]  Enviar una notificación de prueba y mostrar el resultado (por defecto: all)."
T_IT[help.checknotif]="  check-notification [email|webhook|all]  Inviare una notifica di prova e mostrare il risultato (predefinito: all)."

T_EN[help.diag]="  diag             Run a read-only self-diagnostic and list any anomalies."
T_FR[help.diag]="  diag             Lancer un auto-diagnostic en lecture seule et lister les anomalies."
T_DE[help.diag]="  diag             Eine schreibgeschützte Selbstdiagnose ausführen und Anomalien auflisten."
T_ES[help.diag]="  diag             Ejecutar un autodiagnóstico de solo lectura y listar las anomalías."
T_IT[help.diag]="  diag             Eseguire un'autodiagnostica in sola lettura ed elencare le anomalie."

T_EN[help.health]="  health           Show the server's vital signs (load, memory, disk, MTA, I/O) and exit."
T_FR[help.health]="  health           Afficher les signes vitaux du serveur (load, mémoire, disque, MTA, IO) et quitter."
T_DE[help.health]="  health           Vitalwerte des Servers anzeigen (Last, Speicher, Festplatte, MTA, I/O) und beenden."
T_ES[help.health]="  health           Mostrar las constantes vitales del servidor (carga, memoria, disco, MTA, E/S) y salir."
T_IT[help.health]="  health           Mostrare i segni vitali del server (carico, memoria, disco, MTA, I/O) e uscire."

T_EN[help.nohealth]="  --no-health      Skip the vital-sign checks (with diag and the daily summary)."
T_FR[help.nohealth]="  --no-health      Sauter les contrôles de signes vitaux (avec diag et le résumé quotidien)."
T_DE[help.nohealth]="  --no-health      Die Vitalwert-Prüfungen überspringen (bei diag und der täglichen Zusammenfassung)."
T_ES[help.nohealth]="  --no-health      Omitir los controles de constantes vitales (con diag y el resumen diario)."
T_IT[help.nohealth]="  --no-health      Saltare i controlli dei segni vitali (con diag e il riepilogo giornaliero)."

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

T_EN[diag.completion_pkg]="Package bash-completion not installed — Tab completion cannot work (apt install bash-completion)."
T_FR[diag.completion_pkg]="Paquet bash-completion non installé — la complétion Tab ne peut pas fonctionner (apt install bash-completion)."
T_DE[diag.completion_pkg]="Paket bash-completion nicht installiert — Tab-Vervollständigung kann nicht funktionieren (apt install bash-completion)."
T_ES[diag.completion_pkg]="Paquete bash-completion no instalado — el autocompletado Tab no puede funcionar (apt install bash-completion)."
T_IT[diag.completion_pkg]="Pacchetto bash-completion non installato — il completamento Tab non può funzionare (apt install bash-completion)."

T_EN[diag.cron_noexec]="Present but NOT executable: %s (run-parts silently skips it)"
T_FR[diag.cron_noexec]="Présent mais NON exécutable : %s (run-parts l'ignore en silence)"
T_DE[diag.cron_noexec]="Vorhanden, aber NICHT ausführbar: %s (run-parts überspringt sie stillschweigend)"
T_ES[diag.cron_noexec]="Presente pero NO ejecutable: %s (run-parts lo omite en silencio)"
T_IT[diag.cron_noexec]="Presente ma NON eseguibile: %s (run-parts lo salta in silenzio)"

T_EN[diag.engine_fresh]="Engine ran recently (hourly cron active)."
T_FR[diag.engine_fresh]="Moteur exécuté récemment (cron horaire actif)."
T_DE[diag.engine_fresh]="Engine kürzlich gelaufen (stündlicher Cron aktiv)."
T_ES[diag.engine_fresh]="Motor ejecutado recientemente (cron horario activo)."
T_IT[diag.engine_fresh]="Motore eseguito di recente (cron orario attivo)."

T_EN[diag.engine_stale]="No completed engine run for %s hour(s) — cron.hourly down or stuck lock?"
T_FR[diag.engine_stale]="Aucun run complet du moteur depuis %s heure(s) — cron.hourly en panne ou verrou bloqué ?"
T_DE[diag.engine_stale]="Kein vollständiger Engine-Lauf seit %s Stunde(n) — cron.hourly defekt oder Sperre blockiert?"
T_ES[diag.engine_stale]="Ningún run completo del motor desde hace %s hora(s) — ¿cron.hourly caído o candado bloqueado?"
T_IT[diag.engine_stale]="Nessuna esecuzione completa del motore da %s ora/e — cron.hourly fermo o lock bloccato?"

T_EN[diag.engine_never]="No completed engine run recorded (normal within 1 h of an install/update; otherwise check cron.hourly)."
T_FR[diag.engine_never]="Aucun run complet du moteur tracé (normal < 1 h après install/MAJ ; sinon vérifier cron.hourly)."
T_DE[diag.engine_never]="Kein vollständiger Engine-Lauf verzeichnet (normal < 1 h nach Installation/Update; sonst cron.hourly prüfen)."
T_ES[diag.engine_never]="Ningún run completo del motor registrado (normal < 1 h tras instalar/actualizar; si no, revisar cron.hourly)."
T_IT[diag.engine_never]="Nessuna esecuzione completa del motore registrata (normale < 1 h dopo installazione/aggiornamento; altrimenti verificare cron.hourly)."

T_EN[diag.lock_stuck]="Lock %s held with no recent completed run — a stuck run is blocking every hourly pass."
T_FR[diag.lock_stuck]="Verrou %s tenu alors qu'aucun run récent n'a abouti — un run bloqué neutralise chaque passage horaire."
T_DE[diag.lock_stuck]="Sperre %s gehalten, aber kein kürzlich abgeschlossener Lauf — ein hängender Lauf blockiert jeden stündlichen Durchgang."
T_ES[diag.lock_stuck]="Candado %s retenido sin ninguna ejecución reciente completada — una ejecución colgada bloquea cada pasada horaria."
T_IT[diag.lock_stuck]="Lock %s detenuto senza alcuna esecuzione recente completata — un'esecuzione bloccata ferma ogni passaggio orario."

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

T_EN[diag.step_cron_invalid]="Invalid CRON_STEP (%s): expected 5-30 or auto — ignored, hourly runs only."
T_FR[diag.step_cron_invalid]="CRON_STEP invalide (%s) : attendu 5-30 ou auto — ignoré, passages horaires seuls."
T_DE[diag.step_cron_invalid]="Ungültiges CRON_STEP (%s): erwartet 5-30 oder auto — ignoriert, nur stündliche Läufe."
T_ES[diag.step_cron_invalid]="CRON_STEP no válido (%s): se esperaba 5-30 o auto — ignorado, solo ejecuciones horarias."
T_IT[diag.step_cron_invalid]="CRON_STEP non valido (%s): atteso 5-30 o auto — ignorato, solo esecuzioni orarie."

T_EN[diag.step_cron_ok]="Step cron present (CRON_STEP=%s min)."
T_FR[diag.step_cron_ok]="Cron de ticks intermédiaires présent (CRON_STEP=%s min)."
T_DE[diag.step_cron_ok]="Zwischentakt-Cron vorhanden (CRON_STEP=%s min)."
T_ES[diag.step_cron_ok]="Cron de ticks intermedios presente (CRON_STEP=%s min)."
T_IT[diag.step_cron_ok]="Cron dei tick intermedi presente (CRON_STEP=%s min)."

T_EN[diag.step_cron_ok_auto]="Step cron present (CRON_STEP=auto, current effective interval: %s min)."
T_FR[diag.step_cron_ok_auto]="Cron de ticks intermédiaires présent (CRON_STEP=auto, intervalle effectif courant : %s min)."
T_DE[diag.step_cron_ok_auto]="Zwischentakt-Cron vorhanden (CRON_STEP=auto, aktuelles effektives Intervall: %s min)."
T_ES[diag.step_cron_ok_auto]="Cron de ticks intermedios presente (CRON_STEP=auto, intervalo efectivo actual: %s min)."
T_IT[diag.step_cron_ok_auto]="Cron dei tick intermedi presente (CRON_STEP=auto, intervallo effettivo attuale: %s min)."

T_EN[diag.step_cron_missing_wanted]="Step cron missing although CRON_STEP is set — normal for <1 h after enabling (self-heals on the next real run)."
T_FR[diag.step_cron_missing_wanted]="Cron de ticks intermédiaires absent alors que CRON_STEP est posé — normal < 1 h après activation (auto-guérison au prochain run réel)."
T_DE[diag.step_cron_missing_wanted]="Zwischentakt-Cron fehlt, obwohl CRON_STEP gesetzt ist — normal < 1 h nach Aktivierung (Selbstheilung beim nächsten echten Lauf)."
T_ES[diag.step_cron_missing_wanted]="Cron de ticks intermedios ausente aunque CRON_STEP está definido — normal < 1 h tras la activación (autocuración en la próxima ejecución real)."
T_IT[diag.step_cron_missing_wanted]="Cron dei tick intermedi assente benché CRON_STEP sia impostato — normale < 1 h dopo l'attivazione (autoguarigione alla prossima esecuzione reale)."

T_EN[diag.step_cron_orphan]="Step cron present although CRON_STEP is disabled — will be removed on the next hourly run."
T_FR[diag.step_cron_orphan]="Cron de ticks intermédiaires présent alors que CRON_STEP est désactivé — sera retiré au prochain passage horaire."
T_DE[diag.step_cron_orphan]="Zwischentakt-Cron vorhanden, obwohl CRON_STEP deaktiviert ist — wird beim nächsten stündlichen Lauf entfernt."
T_ES[diag.step_cron_orphan]="Cron de ticks intermedios presente aunque CRON_STEP está desactivado — se eliminará en la próxima ejecución horaria."
T_IT[diag.step_cron_orphan]="Cron dei tick intermedi presente benché CRON_STEP sia disattivato — sarà rimosso alla prossima esecuzione oraria."

T_EN[diag.platform_ok]="Platform: %s (supported)."
T_FR[diag.platform_ok]="Plateforme : %s (supportée)."
T_DE[diag.platform_ok]="Plattform: %s (unterstützt)."
T_ES[diag.platform_ok]="Plataforma: %s (compatible)."
T_IT[diag.platform_ok]="Piattaforma: %s (supportata)."

T_EN[diag.platform_readonly]="Platform: %s — UNVALIDATED, READ-ONLY mode (no firewall write; force with PLATFORM_VALIDATED)."
T_FR[diag.platform_readonly]="Plateforme : %s — NON VALIDÉE, mode LECTURE SEULE (aucune écriture pare-feu ; forcer avec PLATFORM_VALIDATED)."
T_DE[diag.platform_readonly]="Plattform: %s — NICHT VALIDIERT, NUR-LESE-Modus (keine Firewall-Schreibvorgänge; mit PLATFORM_VALIDATED erzwingen)."
T_ES[diag.platform_readonly]="Plataforma: %s — NO VALIDADA, modo SOLO LECTURA (sin escritura de firewall; forzar con PLATFORM_VALIDATED)."
T_IT[diag.platform_readonly]="Piattaforma: %s — NON VALIDATA, modalità SOLA LETTURA (nessuna scrittura firewall; forzare con PLATFORM_VALIDATED)."

T_EN[diag.fw_backend]="Firewall: backend in use = %s; available: %s."
T_FR[diag.fw_backend]="Pare-feu : backend utilisé = %s ; disponibles : %s."
T_DE[diag.fw_backend]="Firewall: verwendetes Backend = %s; verfügbar: %s."
T_ES[diag.fw_backend]="Firewall: backend en uso = %s; disponibles: %s."
T_IT[diag.fw_backend]="Firewall: backend in uso = %s; disponibili: %s."

T_EN[diag.fw_none]="none (read-only)"
T_FR[diag.fw_none]="aucun (lecture seule)"
T_DE[diag.fw_none]="keines (nur lesen)"
T_ES[diag.fw_none]="ninguno (solo lectura)"
T_IT[diag.fw_none]="nessuno (sola lettura)"

T_EN[fw.migrated]="[i] Firewall backend migrated: %s -> %s (bans transferred, old artefacts removed)."
T_FR[fw.migrated]="[i] Backend pare-feu migré : %s -> %s (bans transférés, anciens artefacts retirés)."
T_DE[fw.migrated]="[i] Firewall-Backend migriert: %s -> %s (Sperren übertragen, alte Artefakte entfernt)."
T_ES[fw.migrated]="[i] Backend de firewall migrado: %s -> %s (bloqueos transferidos, artefactos antiguos eliminados)."
T_IT[fw.migrated]="[i] Backend firewall migrato: %s -> %s (blocchi trasferiti, vecchi artefatti rimossi)."

T_EN[fw.migrate_abort]="[i] Firewall backend switch aborted: %s not ready — staying on the current backend (no protection gap)."
T_FR[fw.migrate_abort]="[i] Bascule de backend pare-feu annulée : %s pas prêt — on reste sur le backend courant (aucun trou de protection)."
T_DE[fw.migrate_abort]="[i] Firewall-Backend-Wechsel abgebrochen: %s nicht bereit — aktuelles Backend bleibt (keine Schutzlücke)."
T_ES[fw.migrate_abort]="[i] Cambio de backend de firewall cancelado: %s no está listo — se mantiene el backend actual (sin brecha de protección)."
T_IT[fw.migrate_abort]="[i] Cambio del backend firewall annullato: %s non pronto — si resta sul backend attuale (nessuna falla di protezione)."

T_EN[diag.fw_set_ok]="Firewall set %s present (%s members)."
T_FR[diag.fw_set_ok]="Set pare-feu %s présent (%s membres)."
T_DE[diag.fw_set_ok]="Firewall-Set %s vorhanden (%s Einträge)."
T_ES[diag.fw_set_ok]="Set del firewall %s presente (%s miembros)."
T_IT[diag.fw_set_ok]="Set del firewall %s presente (%s membri)."

T_EN[diag.escalation_on]="Graduated ban active: tiers %s, %s probation — %s IP(s) tracked, %s repeat offender(s)."
T_FR[diag.escalation_on]="Ban gradué actif : paliers %s, épreuve %s — %s IP suivie(s), %s récidiviste(s)."
T_DE[diag.escalation_on]="Gestufte Sperre aktiv: Stufen %s, Bewährung %s — %s IP(s) erfasst, %s Wiederholungstäter."
T_ES[diag.escalation_on]="Bloqueo graduado activo: niveles %s, prueba %s — %s IP monitorizada(s), %s reincidente(s)."
T_IT[diag.escalation_on]="Blocco graduale attivo: livelli %s, prova %s — %s IP monitorate, %s recidivi."

T_EN[diag.escalation_off]="Graduated ban disabled (BAN_ESCALATION empty) — fixed durations only."
T_FR[diag.escalation_off]="Ban gradué désactivé (BAN_ESCALATION vide) — durées fixes uniquement."
T_DE[diag.escalation_off]="Gestufte Sperre deaktiviert (BAN_ESCALATION leer) — nur feste Dauern."
T_ES[diag.escalation_off]="Bloqueo graduado desactivado (BAN_ESCALATION vacío) — solo duraciones fijas."
T_IT[diag.escalation_off]="Blocco graduale disattivato (BAN_ESCALATION vuoto) — solo durate fisse."

T_EN[diag.fw_set_missing]="Firewall set %s missing — no bans are enforced."
T_FR[diag.fw_set_missing]="Set pare-feu %s absent — aucun ban n'est appliqué."
T_DE[diag.fw_set_missing]="Firewall-Set %s fehlt — keine Sperren aktiv."
T_ES[diag.fw_set_missing]="Set del firewall %s ausente — no se aplica ningún bloqueo."
T_IT[diag.fw_set_missing]="Set del firewall %s assente — nessun blocco applicato."

T_EN[diag.fw_rule_ok]="Firewall DROP rule present."
T_FR[diag.fw_rule_ok]="Règle DROP du pare-feu présente."
T_DE[diag.fw_rule_ok]="DROP-Regel der Firewall vorhanden."
T_ES[diag.fw_rule_ok]="Regla DROP del firewall presente."
T_IT[diag.fw_rule_ok]="Regola DROP del firewall presente."

T_EN[diag.fw_rule_missing]="Firewall DROP rule missing — bans are not enforced."
T_FR[diag.fw_rule_missing]="Règle DROP du pare-feu absente — les bans ne sont pas appliqués."
T_DE[diag.fw_rule_missing]="DROP-Regel der Firewall fehlt — Sperren werden nicht durchgesetzt."
T_ES[diag.fw_rule_missing]="Regla DROP del firewall ausente — los bloqueos no se aplican."
T_IT[diag.fw_rule_missing]="Regola DROP del firewall assente — i blocchi non vengono applicati."

T_EN[diag.persist_ok]="Firewall persistence present."
T_FR[diag.persist_ok]="Persistance du pare-feu présente."
T_DE[diag.persist_ok]="Firewall-Persistenz vorhanden."
T_ES[diag.persist_ok]="Persistencia del firewall presente."
T_IT[diag.persist_ok]="Persistenza del firewall presente."

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

T_EN[diag.log_profile]="Log discovery profile: %s."
T_FR[diag.log_profile]="Profil de découverte des logs : %s."
T_DE[diag.log_profile]="Log-Erkennungsprofil: %s."
T_ES[diag.log_profile]="Perfil de descubrimiento de logs: %s."
T_IT[diag.log_profile]="Profilo di scoperta dei log: %s."

T_EN[diag.logs_found]="%s log file(s) found for analysis."
T_FR[diag.logs_found]="%s fichier(s) de log trouvé(s) pour l'analyse."
T_DE[diag.logs_found]="%s Log-Datei(en) für die Analyse gefunden."
T_ES[diag.logs_found]="%s archivo(s) de log encontrado(s) para el análisis."
T_IT[diag.logs_found]="%s file di log trovati per l'analisi."

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

# --- Signes vitaux du serveur (sous-commande health ; inclus dans diag et le résumé) ---
T_EN[health.header]="=[ server vital signs ]="
T_FR[health.header]="=[ Signes vitaux du serveur ]="
T_DE[health.header]="=[ Vitalwerte des Servers ]="
T_ES[health.header]="=[ Constantes vitales del servidor ]="
T_IT[health.header]="=[ Segni vitali del server ]="

T_EN[stats.health_vitals]="Vital signs"
T_FR[stats.health_vitals]="Signes vitaux"
T_DE[stats.health_vitals]="Vitalwerte"
T_ES[stats.health_vitals]="Constantes vitales"
T_IT[stats.health_vitals]="Segni vitali"

T_EN[diag.health_load]="Load: %s %s %s (%s core(s)) · uptime %s"
T_FR[diag.health_load]="Charge (load) : %s %s %s (%s cœur(s)) · uptime %s"
T_DE[diag.health_load]="Last: %s %s %s (%s Kern(e)) · Uptime %s"
T_ES[diag.health_load]="Carga (load): %s %s %s (%s núcleo(s)) · uptime %s"
T_IT[diag.health_load]="Carico (load): %s %s %s (%s core) · uptime %s"

T_EN[diag.health_load_high]="HIGH load: %s %s %s (%s core(s), threshold %s x cores) · uptime %s"
T_FR[diag.health_load_high]="Charge ÉLEVÉE : %s %s %s (%s cœur(s), seuil %s x cœurs) · uptime %s"
T_DE[diag.health_load_high]="HOHE Last: %s %s %s (%s Kern(e), Schwelle %s x Kerne) · Uptime %s"
T_ES[diag.health_load_high]="Carga ALTA: %s %s %s (%s núcleo(s), umbral %s x núcleos) · uptime %s"
T_IT[diag.health_load_high]="Carico ELEVATO: %s %s %s (%s core, soglia %s x core) · uptime %s"

T_EN[diag.health_mem]="Memory: %s%% available (%s of %s MB) · swap used: %s%%"
T_FR[diag.health_mem]="Mémoire : %s %% disponible (%s sur %s Mo) · swap utilisé : %s %%"
T_DE[diag.health_mem]="Speicher: %s %% verfügbar (%s von %s MB) · Swap belegt: %s %%"
T_ES[diag.health_mem]="Memoria: %s %% disponible (%s de %s MB) · swap usado: %s %%"
T_IT[diag.health_mem]="Memoria: %s %% disponibile (%s di %s MB) · swap usato: %s %%"

T_EN[diag.health_mem_low]="LOW memory: %s%% available (%s of %s MB, threshold %s%%) · swap used: %s%%"
T_FR[diag.health_mem_low]="Mémoire BASSE : %s %% disponible (%s sur %s Mo, seuil %s %%) · swap utilisé : %s %%"
T_DE[diag.health_mem_low]="WENIG Speicher: %s %% verfügbar (%s von %s MB, Schwelle %s %%) · Swap belegt: %s %%"
T_ES[diag.health_mem_low]="Memoria BAJA: %s %% disponible (%s de %s MB, umbral %s %%) · swap usado: %s %%"
T_IT[diag.health_mem_low]="Memoria BASSA: %s %% disponibile (%s di %s MB, soglia %s %%) · swap usato: %s %%"

T_EN[diag.health_disk]="Disk %s: %s%% space used, %s%% inodes used"
T_FR[diag.health_disk]="Disque %s : %s %% d'espace occupé, %s %% d'inodes"
T_DE[diag.health_disk]="Festplatte %s: %s %% Platz belegt, %s %% Inodes"
T_ES[diag.health_disk]="Disco %s: %s %% de espacio ocupado, %s %% de inodos"
T_IT[diag.health_disk]="Disco %s: %s %% di spazio occupato, %s %% di inode"

T_EN[diag.health_disk_full]="Disk %s NEARLY FULL: %s%% space, %s%% inodes (threshold %s%%)"
T_FR[diag.health_disk_full]="Disque %s PRESQUE PLEIN : %s %% d'espace, %s %% d'inodes (seuil %s %%)"
T_DE[diag.health_disk_full]="Festplatte %s FAST VOLL: %s %% Platz, %s %% Inodes (Schwelle %s %%)"
T_ES[diag.health_disk_full]="Disco %s CASI LLENO: %s %% de espacio, %s %% de inodos (umbral %s %%)"
T_IT[diag.health_disk_full]="Disco %s QUASI PIENO: %s %% di spazio, %s %% di inode (soglia %s %%)"

T_EN[diag.health_mta]="Postfix running · mail queue: %s message(s)"
T_FR[diag.health_mta]="Postfix actif · file d'attente : %s message(s)"
T_DE[diag.health_mta]="Postfix läuft · Mail-Warteschlange: %s Nachricht(en)"
T_ES[diag.health_mta]="Postfix activo · cola de correo: %s mensaje(s)"
T_IT[diag.health_mta]="Postfix attivo · coda di posta: %s messaggio(i)"

T_EN[diag.health_mta_queue]="Postfix running but mail queue is LARGE: %s messages (threshold %s) — check deliverability."
T_FR[diag.health_mta_queue]="Postfix actif mais file d'attente ÉLEVÉE : %s messages (seuil %s) — vérifier la délivrabilité."
T_DE[diag.health_mta_queue]="Postfix läuft, aber Mail-Warteschlange ist GROSS: %s Nachrichten (Schwelle %s) — Zustellbarkeit prüfen."
T_ES[diag.health_mta_queue]="Postfix activo pero cola de correo ALTA: %s mensajes (umbral %s) — verifique la entregabilidad."
T_IT[diag.health_mta_queue]="Postfix attivo ma coda di posta ELEVATA: %s messaggi (soglia %s) — verificare la recapitabilità."

T_EN[diag.health_mta_down]="Postfix service STOPPED (queue: %s message(s)) — outgoing mail is piling up or being lost."
T_FR[diag.health_mta_down]="Service postfix ARRÊTÉ (file : %s message(s)) — le courrier sortant s'accumule ou se perd."
T_DE[diag.health_mta_down]="Postfix-Dienst GESTOPPT (Warteschlange: %s Nachricht(en)) — ausgehende Mails stauen sich oder gehen verloren."
T_ES[diag.health_mta_down]="Servicio postfix DETENIDO (cola: %s mensaje(s)) — el correo saliente se acumula o se pierde."
T_IT[diag.health_mta_down]="Servizio postfix FERMO (coda: %s messaggio(i)) — la posta in uscita si accumula o va persa."

T_EN[diag.health_mta_none]="No MTA detected (postfix not installed) — mail check skipped."
T_FR[diag.health_mta_none]="Aucun MTA détecté (postfix non installé) — contrôle du courrier sauté."
T_DE[diag.health_mta_none]="Kein MTA erkannt (postfix nicht installiert) — Mail-Prüfung übersprungen."
T_ES[diag.health_mta_none]="Ningún MTA detectado (postfix no instalado) — control de correo omitido."
T_IT[diag.health_mta_none]="Nessun MTA rilevato (postfix non installato) — controllo della posta saltato."

T_EN[diag.health_io]="I/O pressure (PSI some avg60): %s%%"
T_FR[diag.health_io]="Pression IO (PSI some avg60) : %s %%"
T_DE[diag.health_io]="I/O-Druck (PSI some avg60): %s %%"
T_ES[diag.health_io]="Presión de E/S (PSI some avg60): %s %%"
T_IT[diag.health_io]="Pressione I/O (PSI some avg60): %s %%"

T_EN[diag.health_io_high]="HIGH I/O pressure (PSI some avg60): %s%% (threshold %s%%) — tasks are stalling on disk."
T_FR[diag.health_io_high]="Pression IO ÉLEVÉE (PSI some avg60) : %s %% (seuil %s %%) — des tâches attendent le disque."
T_DE[diag.health_io_high]="HOHER I/O-Druck (PSI some avg60): %s %% (Schwelle %s %%) — Prozesse warten auf die Festplatte."
T_ES[diag.health_io_high]="Presión de E/S ALTA (PSI some avg60): %s %% (umbral %s %%) — hay tareas esperando el disco."
T_IT[diag.health_io_high]="Pressione I/O ELEVATA (PSI some avg60): %s %% (soglia %s %%) — processi in attesa del disco."

T_EN[diag.health_io_na]="I/O pressure not measurable (PSI unavailable on this kernel)."
T_FR[diag.health_io_na]="Pression IO non mesurable (PSI indisponible sur ce noyau)."
T_DE[diag.health_io_na]="I/O-Druck nicht messbar (PSI auf diesem Kernel nicht verfügbar)."
T_ES[diag.health_io_na]="Presión de E/S no medible (PSI no disponible en este kernel)."
T_IT[diag.health_io_na]="Pressione I/O non misurabile (PSI non disponibile su questo kernel)."

T_EN[diag.health_net]="Network %s: RX %s/s · TX %s/s (1 s sample)"
T_FR[diag.health_net]="Réseau %s : RX %s/s · TX %s/s (échantillon 1 s)"
T_DE[diag.health_net]="Netzwerk %s: RX %s/s · TX %s/s (1-s-Messung)"
T_ES[diag.health_net]="Red %s: RX %s/s · TX %s/s (muestra de 1 s)"
T_IT[diag.health_net]="Rete %s: RX %s/s · TX %s/s (campione di 1 s)"

T_EN[diag.health_units]="systemd: %s failed unit(s): %s"
T_FR[diag.health_units]="systemd : %s unité(s) en échec : %s"
T_DE[diag.health_units]="systemd: %s fehlgeschlagene Unit(s): %s"
T_ES[diag.health_units]="systemd: %s unidad(es) en fallo: %s"
T_IT[diag.health_units]="systemd: %s unità in errore: %s"

T_EN[diag.health_reboot]="Reboot required (/var/run/reboot-required present — pending kernel/libc update)."
T_FR[diag.health_reboot]="Redémarrage requis (/var/run/reboot-required présent — MAJ noyau/libc en attente)."
T_DE[diag.health_reboot]="Neustart erforderlich (/var/run/reboot-required vorhanden — Kernel-/libc-Update ausstehend)."
T_ES[diag.health_reboot]="Reinicio requerido (/var/run/reboot-required presente — actualización de kernel/libc pendiente)."
T_IT[diag.health_reboot]="Riavvio richiesto (/var/run/reboot-required presente — aggiornamento kernel/libc in sospeso)."

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

T_EN[help.conf_log_profile]="  LOG_PROFILE      Log layout: auto (default) | ispconfig | cpanel | directadmin | plesk | nginx | generic."
T_FR[help.conf_log_profile]="  LOG_PROFILE      Layout des logs : auto (défaut) | ispconfig | cpanel | directadmin | plesk | nginx | generic."
T_DE[help.conf_log_profile]="  LOG_PROFILE      Log-Layout: auto (Standard) | ispconfig | cpanel | directadmin | plesk | nginx | generic."
T_ES[help.conf_log_profile]="  LOG_PROFILE      Disposición de logs: auto (por defecto) | ispconfig | cpanel | directadmin | plesk | nginx | generic."
T_IT[help.conf_log_profile]="  LOG_PROFILE      Layout dei log: auto (predefinito) | ispconfig | cpanel | directadmin | plesk | nginx | generic."

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
T_EN[help.conf_distinct]="  DISTINCT_PATH_MIN  Distinct 404 paths required for a volume ban (default 2; 1 disables)."
T_FR[help.conf_distinct]="  DISTINCT_PATH_MIN  Chemins 404 distincts exigés pour un ban de volume (défaut 2 ; 1 => désactivé)."
T_DE[help.conf_distinct]="  DISTINCT_PATH_MIN  Verschiedene 404-Pfade für eine Mengensperre nötig (Standard 2; 1 = aus)."
T_ES[help.conf_distinct]="  DISTINCT_PATH_MIN  Rutas 404 distintas exigidas para un bloqueo por volumen (por defecto 2; 1 = desactivado)."
T_IT[help.conf_distinct]="  DISTINCT_PATH_MIN  Percorsi 404 distinti richiesti per un blocco di volume (predefinito 2; 1 = disattivato)."

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

T_EN[help.conf_ban_escalation]="  BAN_ESCALATION   Repeat-offence tiers in seconds, space separated (default \"604800 1209600 2073600\"); empty disables."
T_FR[help.conf_ban_escalation]="  BAN_ESCALATION   Paliers de récidive en secondes, séparés par des espaces (défaut « 604800 1209600 2073600 ») ; vide => désactivé."
T_DE[help.conf_ban_escalation]="  BAN_ESCALATION   Wiederholungsstufen in Sekunden, durch Leerzeichen getrennt (Standard \"604800 1209600 2073600\"); leer = aus."
T_ES[help.conf_ban_escalation]="  BAN_ESCALATION   Niveles de reincidencia en segundos, separados por espacios (por defecto «604800 1209600 2073600»); vacío = desactivado."
T_IT[help.conf_ban_escalation]="  BAN_ESCALATION   Livelli di recidiva in secondi, separati da spazi (predefinito «604800 1209600 2073600»); vuoto = disattivato."

T_EN[help.conf_escalation_memory]="  ESCALATION_MEMORY  Probation after release (s): no ban for that long resets the counter (default 2073600 = 24 days)."
T_FR[help.conf_escalation_memory]="  ESCALATION_MEMORY  Épreuve après libération (s) : sans ban pendant ce délai, le compteur repart de zéro (défaut 2073600 = 24 j)."
T_DE[help.conf_escalation_memory]="  ESCALATION_MEMORY  Bewährung nach Freigabe (s): ohne Sperre in dieser Zeit wird der Zähler zurückgesetzt (Standard 2073600 = 24 Tage)."
T_ES[help.conf_escalation_memory]="  ESCALATION_MEMORY  Prueba tras la liberación (s): sin bloqueo durante ese plazo, el contador vuelve a cero (por defecto 2073600 = 24 días)."
T_IT[help.conf_escalation_memory]="  ESCALATION_MEMORY  Prova dopo il rilascio (s): senza blocchi per tale periodo, il contatore riparte da zero (predefinito 2073600 = 24 giorni)."

T_EN[help.conf_aggressive_score]="  AGGRESSIVE_SCORE  Score from which an IP starts one tier higher on its first ban (default 500; 0 disables)."
T_FR[help.conf_aggressive_score]="  AGGRESSIVE_SCORE  Score à partir duquel une IP démarre un palier plus haut dès son 1er ban (défaut 500 ; 0 => désactivé)."
T_DE[help.conf_aggressive_score]="  AGGRESSIVE_SCORE  Score, ab dem eine IP schon bei der ersten Sperre eine Stufe höher startet (Standard 500; 0 = aus)."
T_ES[help.conf_aggressive_score]="  AGGRESSIVE_SCORE  Puntuación a partir de la cual una IP empieza un nivel más alto en su primer bloqueo (por defecto 500; 0 = desactivado)."
T_IT[help.conf_aggressive_score]="  AGGRESSIVE_SCORE  Punteggio dal quale un IP parte da un livello più alto già al primo blocco (predefinito 500; 0 = disattivato)."

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

T_EN[help.conf_chatcard]="  WEBHOOK_CHAT_CARD  Google Chat only: daily summary as a colored card (cardsV2); default true, false = plain text."
T_FR[help.conf_chatcard]="  WEBHOOK_CHAT_CARD  Google Chat uniquement : résumé quotidien en carte colorée (cardsV2) ; défaut true, false = texte simple."
T_DE[help.conf_chatcard]="  WEBHOOK_CHAT_CARD  Nur Google Chat: tägliche Zusammenfassung als farbige Karte (cardsV2); Standard true, false = einfacher Text."
T_ES[help.conf_chatcard]="  WEBHOOK_CHAT_CARD  Solo Google Chat: resumen diario como tarjeta con color (cardsV2); por defecto true, false = texto simple."
T_IT[help.conf_chatcard]="  WEBHOOK_CHAT_CARD  Solo Google Chat: riepilogo giornaliero come scheda colorata (cardsV2); predefinito true, false = testo semplice."

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

T_EN[help.conf_cron_step]="  CRON_STEP        Extra runs via /etc/cron.d (managed): empty = hourly only (default), 5-30 = every N min, auto = adaptive 5-60 min with attack sentinel."
T_FR[help.conf_cron_step]="  CRON_STEP        Passages supplémentaires via /etc/cron.d (géré) : vide = horaire seul (défaut), 5-30 = toutes les N min, auto = adaptatif 5-60 min avec sentinelle d'attaque."
T_DE[help.conf_cron_step]="  CRON_STEP        Zusätzliche Läufe über /etc/cron.d (verwaltet): leer = nur stündlich (Standard), 5-30 = alle N min, auto = adaptiv 5-60 min mit Angriffswächter."
T_ES[help.conf_cron_step]="  CRON_STEP        Ejecuciones adicionales vía /etc/cron.d (gestionado): vacío = solo horaria (por defecto), 5-30 = cada N min, auto = adaptativo 5-60 min con centinela de ataques."
T_IT[help.conf_cron_step]="  CRON_STEP        Esecuzioni aggiuntive via /etc/cron.d (gestito): vuoto = solo oraria (predefinito), 5-30 = ogni N min, auto = adattivo 5-60 min con sentinella di attacco."

T_EN[help.conf_fw_backend]="  FW_BACKEND       Firewall backend: auto (default = prefer iptables+ipset for coexistence) | iptables | nftables. Switching migrates existing bans."
T_FR[help.conf_fw_backend]="  FW_BACKEND       Backend pare-feu : auto (défaut = préférer iptables+ipset pour la coexistence) | iptables | nftables. La bascule migre les bans existants."
T_DE[help.conf_fw_backend]="  FW_BACKEND       Firewall-Backend: auto (Standard = iptables+ipset bevorzugen, Koexistenz) | iptables | nftables. Der Wechsel migriert bestehende Sperren."
T_ES[help.conf_fw_backend]="  FW_BACKEND       Backend de firewall: auto (por defecto = preferir iptables+ipset por coexistencia) | iptables | nftables. El cambio migra los bloqueos existentes."
T_IT[help.conf_fw_backend]="  FW_BACKEND       Backend firewall: auto (predefinito = preferire iptables+ipset per coesistenza) | iptables | nftables. Il cambio migra i blocchi esistenti."

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

T_EN[help.conf_postflood]="  POST_FLOOD_THRESHOLD  Ban when more than N monitored POSTs in the window (default 20)."
T_FR[help.conf_postflood]="  POST_FLOOD_THRESHOLD  Ban au-delà de N POST surveillés dans la fenêtre (défaut 20)."
T_DE[help.conf_postflood]="  POST_FLOOD_THRESHOLD  Sperre bei mehr als N überwachten POSTs im Zeitfenster (Standard 20)."
T_ES[help.conf_postflood]="  POST_FLOOD_THRESHOLD  Bloqueo al superar N POST vigilados en la ventana (por defecto 20)."
T_IT[help.conf_postflood]="  POST_FLOOD_THRESHOLD  Blocco oltre N POST sorvegliati nella finestra (predefinito 20)."

T_EN[help.conf_health]="  HEALTH_*         Vital-sign thresholds (WARN=orange, CRIT=red): LOAD (x cores, 2/4), MEM (%% avail., 10/5), DISK (%%, 90/95), MAILQ (50/500), IO (PSI %%, 25/50); HEALTH_CHECKS=false disables."
T_FR[help.conf_health]="  HEALTH_*         Seuils des signes vitaux (WARN=orange, CRIT=rouge) : LOAD (x cœurs, 2/4), MEM (%% dispo, 10/5), DISK (%%, 90/95), MAILQ (50/500), IO (PSI %%, 25/50) ; HEALTH_CHECKS=false désactive."
T_DE[help.conf_health]="  HEALTH_*         Vitalwert-Schwellen (WARN=orange, CRIT=rot): LOAD (x Kerne, 2/4), MEM (%% verfügbar, 10/5), DISK (%%, 90/95), MAILQ (50/500), IO (PSI %%, 25/50); HEALTH_CHECKS=false deaktiviert."
T_ES[help.conf_health]="  HEALTH_*         Umbrales de constantes vitales (WARN=naranja, CRIT=rojo): LOAD (x núcleos, 2/4), MEM (%% disp., 10/5), DISK (%%, 90/95), MAILQ (50/500), IO (PSI %%, 25/50); HEALTH_CHECKS=false desactiva."
T_IT[help.conf_health]="  HEALTH_*         Soglie dei segni vitali (WARN=arancione, CRIT=rosso): LOAD (x core, 2/4), MEM (%% disp., 10/5), DISK (%%, 90/95), MAILQ (50/500), IO (PSI %%, 25/50); HEALTH_CHECKS=false disattiva."

T_EN[help.conf_advanced]="  Advanced: HONEYPOT_PATTERN / NOISE_PATTERN / SECURITY_PATTERN / POST_FLOOD_PATTERN (awk regex) — override with care."
T_FR[help.conf_advanced]="  Avancé : HONEYPOT_PATTERN / NOISE_PATTERN / SECURITY_PATTERN / POST_FLOOD_PATTERN (regex awk) — surcharger avec prudence."
T_DE[help.conf_advanced]="  Erweitert: HONEYPOT_PATTERN / NOISE_PATTERN / SECURITY_PATTERN / POST_FLOOD_PATTERN (awk-Regex) — mit Bedacht ändern."
T_ES[help.conf_advanced]="  Avanzado: HONEYPOT_PATTERN / NOISE_PATTERN / SECURITY_PATTERN / POST_FLOOD_PATTERN (regex awk) — sobrescribir con cuidado."
T_IT[help.conf_advanced]="  Avanzato: HONEYPOT_PATTERN / NOISE_PATTERN / SECURITY_PATTERN / POST_FLOOD_PATTERN (regex awk) — sovrascrivere con cautela."

T_EN[help.conf_example_pointer]="  See ban_404.conf.example for full documentation and defaults."
T_FR[help.conf_example_pointer]="  Voir ban_404.conf.example pour la doc complète et les valeurs par défaut."
T_DE[help.conf_example_pointer]="  Siehe ban_404.conf.example für vollständige Doku und Standardwerte."
T_ES[help.conf_example_pointer]="  Vea ban_404.conf.example para la documentación completa y los valores por defecto."
T_IT[help.conf_example_pointer]="  Vedere ban_404.conf.example per la documentazione completa e i valori predefiniti."

T_EN[heal.ipset_grown]="[i] ipset %s enlarged (maxelem %s -> 1048576), existing bans preserved."
T_FR[heal.ipset_grown]="[i] ipset %s agrandi (maxelem %s -> 1048576), bans existants conservés."
T_DE[heal.ipset_grown]="[i] ipset %s vergrößert (maxelem %s -> 1048576), bestehende Sperren erhalten."
T_ES[heal.ipset_grown]="[i] ipset %s ampliado (maxelem %s -> 1048576), bloqueos existentes conservados."
T_IT[heal.ipset_grown]="[i] ipset %s ampliato (maxelem %s -> 1048576), blocchi esistenti conservati."

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

T_EN[stats.cadence_auto]="Cadence: CRON_STEP=auto — current effective interval: %s min (adaptive 5-60)"
T_FR[stats.cadence_auto]="Cadence : CRON_STEP=auto — intervalle effectif courant : %s min (adaptatif 5-60)"
T_DE[stats.cadence_auto]="Takt: CRON_STEP=auto — aktuelles effektives Intervall: %s min (adaptiv 5-60)"
T_ES[stats.cadence_auto]="Cadencia: CRON_STEP=auto — intervalo efectivo actual: %s min (adaptativo 5-60)"
T_IT[stats.cadence_auto]="Cadenza: CRON_STEP=auto — intervallo effettivo attuale: %s min (adattivo 5-60)"

T_EN[stats.cadence_fixed]="Cadence: extra run every %s min (fixed CRON_STEP)"
T_FR[stats.cadence_fixed]="Cadence : passage supplémentaire toutes les %s min (CRON_STEP fixe)"
T_DE[stats.cadence_fixed]="Takt: zusätzlicher Lauf alle %s min (festes CRON_STEP)"
T_ES[stats.cadence_fixed]="Cadencia: ejecución adicional cada %s min (CRON_STEP fijo)"
T_IT[stats.cadence_fixed]="Cadenza: esecuzione aggiuntiva ogni %s min (CRON_STEP fisso)"

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

T_EN[stats.avg24_header]="24h averages"
T_FR[stats.avg24_header]="Moyennes 24 h"
T_DE[stats.avg24_header]="24-h-Durchschnitte"
T_ES[stats.avg24_header]="Promedios 24 h"
T_IT[stats.avg24_header]="Medie 24 h"

T_EN[stats.avg24_load]="Load (15 min): avg %s (peak %s)"
T_FR[stats.avg24_load]="Charge (load 15 min) : moy %s (pic %s)"
T_DE[stats.avg24_load]="Last (15 min): Ø %s (Spitze %s)"
T_ES[stats.avg24_load]="Carga (load 15 min): med %s (pico %s)"
T_IT[stats.avg24_load]="Carico (load 15 min): media %s (picco %s)"

T_EN[stats.avg24_io]="I/O pressure (PSI): avg %s%% (peak %s%%)"
T_FR[stats.avg24_io]="Pression IO (PSI) : moy %s %% (pic %s %%)"
T_DE[stats.avg24_io]="I/O-Druck (PSI): Ø %s %% (Spitze %s %%)"
T_ES[stats.avg24_io]="Presión de E/S (PSI): med %s %% (pico %s %%)"
T_IT[stats.avg24_io]="Pressione I/O (PSI): media %s %% (picco %s %%)"

T_EN[stats.avg24_net]="Network %s: RX avg %s/s (peak %s/s) · TX avg %s/s (peak %s/s)"
T_FR[stats.avg24_net]="Réseau %s : RX moy %s/s (pic %s/s) · TX moy %s/s (pic %s/s)"
T_DE[stats.avg24_net]="Netzwerk %s: RX Ø %s/s (Spitze %s/s) · TX Ø %s/s (Spitze %s/s)"
T_ES[stats.avg24_net]="Red %s: RX med %s/s (pico %s/s) · TX med %s/s (pico %s/s)"
T_IT[stats.avg24_net]="Rete %s: RX media %s/s (picco %s/s) · TX media %s/s (picco %s/s)"

T_EN[stats.avg24_mem]="Available memory: avg %s%% (min %s%%)"
T_FR[stats.avg24_mem]="Mémoire dispo : moy %s %% (min %s %%)"
T_DE[stats.avg24_mem]="Verfügbarer Speicher: Ø %s %% (min %s %%)"
T_ES[stats.avg24_mem]="Memoria disponible: med %s %% (mín %s %%)"
T_IT[stats.avg24_mem]="Memoria disponibile: media %s %% (min %s %%)"

T_EN[stats.avg24_window]="(actual window: %s)"
T_FR[stats.avg24_window]="(fenêtre réelle : %s)"
T_DE[stats.avg24_window]="(tatsächliches Fenster: %s)"
T_ES[stats.avg24_window]="(ventana real: %s)"
T_IT[stats.avg24_window]="(finestra reale: %s)"

T_EN[stats.avg24_insufficient]="24h averages: insufficient data (window %s)"
T_FR[stats.avg24_insufficient]="Moyennes 24 h : données insuffisantes (fenêtre %s)"
T_DE[stats.avg24_insufficient]="24-h-Durchschnitte: unzureichende Daten (Fenster %s)"
T_ES[stats.avg24_insufficient]="Promedios 24 h: datos insuficientes (ventana %s)"
T_IT[stats.avg24_insufficient]="Medie 24 h: dati insufficienti (finestra %s)"

T_EN[stats.ipset_header]="ipset counts (24h trend)"
T_FR[stats.ipset_header]="Comptage ipset (évol. 24 h)"
T_DE[stats.ipset_header]="ipset-Zählung (24-h-Trend)"
T_ES[stats.ipset_header]="Recuento ipset (tendencia 24 h)"
T_IT[stats.ipset_header]="Conteggio ipset (andamento 24 h)"

T_EN[stats.ipset_total_label]="Total"
T_FR[stats.ipset_total_label]="Total"
T_DE[stats.ipset_total_label]="Gesamt"
T_ES[stats.ipset_total_label]="Total"
T_IT[stats.ipset_total_label]="Totale"

T_EN[stats.ipset_hdr_count]="Entries"
T_FR[stats.ipset_hdr_count]="Entrées"
T_DE[stats.ipset_hdr_count]="Einträge"
T_ES[stats.ipset_hdr_count]="Entradas"
T_IT[stats.ipset_hdr_count]="Voci"

T_EN[stats.ipset_hdr_var]="24h change"
T_FR[stats.ipset_hdr_var]="Variation 24 h"
T_DE[stats.ipset_hdr_var]="Änderung 24 h"
T_ES[stats.ipset_hdr_var]="Variación 24 h"
T_IT[stats.ipset_hdr_var]="Variazione 24 h"

T_EN[stats.ipset_hdr_evo]="Trend 8h"
T_FR[stats.ipset_hdr_evo]="Évolution 8 h"
T_DE[stats.ipset_hdr_evo]="Verlauf 8 h"
T_ES[stats.ipset_hdr_evo]="Evolución 8 h"
T_IT[stats.ipset_hdr_evo]="Andamento 8 h"

T_EN[stats.ipset_new]="new"
T_FR[stats.ipset_new]="nouveau"
T_DE[stats.ipset_new]="neu"
T_ES[stats.ipset_new]="nuevo"
T_IT[stats.ipset_new]="nuovo"

T_EN[stats.ipset_stable]="stable"
T_FR[stats.ipset_stable]="stable"
T_DE[stats.ipset_stable]="stabil"
T_ES[stats.ipset_stable]="estable"
T_IT[stats.ipset_stable]="stabile"

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

# Part des bans déclenchés par UNE SEULE requête signalée (score = HONEYPOT_SCORE pile). Une part
# écrasante révèle une détection qui tire sur un signal isolé : si l'IP ne revient jamais, le ban
# arrive après coup et n'empêche rien. Le « %% » est un pourcentage littéral (doublé pour printf).
T_EN[stats.floor_bans]="Bans from a single flagged request: %s of %s (%s %%)"
T_FR[stats.floor_bans]="Bans sur une seule requête signalée : %s sur %s (%s %%)"
T_DE[stats.floor_bans]="Sperren durch eine einzige markierte Anfrage: %s von %s (%s %%)"
T_ES[stats.floor_bans]="Bloqueos por una sola petición señalada: %s de %s (%s %%)"
T_IT[stats.floor_bans]="Blocchi per una sola richiesta segnalata: %s su %s (%s %%)"

T_EN[stats.bans_only]="New bans: %s"
T_FR[stats.bans_only]="Nouveaux bans : %s"
T_DE[stats.bans_only]="Neue Sperren: %s"
T_ES[stats.bans_only]="Nuevos bloqueos: %s"
T_IT[stats.bans_only]="Nuovi blocchi: %s"

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

T_EN[stats.top_item]="%s — %s errors"
T_FR[stats.top_item]="%s — %s erreurs"
T_DE[stats.top_item]="%s — %s Fehler"
T_ES[stats.top_item]="%s — %s errores"
T_IT[stats.top_item]="%s — %s errori"

T_EN[stats.top_item_rdns]="%s — %s errors  [%s]"
T_FR[stats.top_item_rdns]="%s — %s erreurs  [%s]"
T_DE[stats.top_item_rdns]="%s — %s Fehler  [%s]"
T_ES[stats.top_item_rdns]="%s — %s errores  [%s]"
T_IT[stats.top_item_rdns]="%s — %s errori  [%s]"

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

# Bloc « Récidivistes » : lu dans OFFENDERS_FILE (donc insensible à la rotation du journal).
T_EN[stats.recidivists_header]="Repeat offenders (%s probation)"
T_FR[stats.recidivists_header]="Récidivistes (épreuve %s)"
T_DE[stats.recidivists_header]="Wiederholungstäter (Bewährung %s)"
T_ES[stats.recidivists_header]="Reincidentes (prueba %s)"
T_IT[stats.recidivists_header]="Recidivi (prova %s)"

T_EN[stats.recidivist_item]="%s — %s bans, latest until %s"
T_FR[stats.recidivist_item]="%s — %s bans, dernier jusqu'au %s"
T_DE[stats.recidivist_item]="%s — %s Sperren, letzte bis %s"
T_ES[stats.recidivist_item]="%s — %s bloqueos, el último hasta %s"
T_IT[stats.recidivist_item]="%s — %s blocchi, l'ultimo fino al %s"

T_EN[stats.recidivist_item_rdns]="%s — %s bans, latest until %s  [%s]"
T_FR[stats.recidivist_item_rdns]="%s — %s bans, dernier jusqu'au %s  [%s]"
T_DE[stats.recidivist_item_rdns]="%s — %s Sperren, letzte bis %s  [%s]"
T_ES[stats.recidivist_item_rdns]="%s — %s bloqueos, el último hasta %s  [%s]"
T_IT[stats.recidivist_item_rdns]="%s — %s blocchi, l'ultimo fino al %s  [%s]"

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

T_EN[crawler.sim_cold_unban]="[SIMULATION] [-] IP %s would be UNBANNED (legitimate crawler: %s)."
T_FR[crawler.sim_cold_unban]="[SIMULATION] [-] L'IP %s aurait été DÉBANNIE (crawler légitime : %s)."
T_DE[crawler.sim_cold_unban]="[SIMULATION] [-] IP %s würde ENTSPERRT (legitimer Crawler: %s)."
T_ES[crawler.sim_cold_unban]="[SIMULATION] [-] La IP %s sería DESBLOQUEADA (crawler legítimo: %s)."
T_IT[crawler.sim_cold_unban]="[SIMULATION] [-] L'IP %s verrebbe SBLOCCATO (crawler legittimo: %s)."

T_EN[crawler.scan_capped]="    (cold crawler sweep stopped at %s IPs — DNS cost cap)"
T_FR[crawler.scan_capped]="    (balayage crawler à froid arrêté à %s IP — plafond de coût DNS)"
T_DE[crawler.scan_capped]="    (Kalter Crawler-Durchlauf bei %s IPs gestoppt — DNS-Kostengrenze)"
T_ES[crawler.scan_capped]="    (barrido en frío de crawlers detenido en %s IP — límite de coste DNS)"
T_IT[crawler.scan_capped]="    (scansione a freddo dei crawler fermata a %s IP — limite di costo DNS)"

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

# Amnistie accordée à une IP absente du set mais encore inscrite dans la mémoire de récidive
# (ban expiré, ou jamais posé faute de support de la famille d'adresse).
T_EN[unban.forgotten]="[i] Repeat-offence record of IP %s cleared (probation ended by admin)."
T_FR[unban.forgotten]="[i] Passé de récidiviste de l'IP %s effacé (épreuve levée par l'admin)."
T_DE[unban.forgotten]="[i] Wiederholungstäter-Eintrag der IP %s gelöscht (Bewährung vom Admin aufgehoben)."
T_ES[unban.forgotten]="[i] Historial de reincidencia de la IP %s borrado (periodo de prueba levantado por el admin)."
T_IT[unban.forgotten]="[i] Storico di recidiva dell'IP %s cancellato (periodo di prova revocato dall'admin)."

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

# Sujet FLAGGÉ quand le résumé contient au moins une anomalie (WARN/FAIL) : %s = hôte, %s = nombre.
# Le préfixe [WARN] rend l'alerte visible d'un coup d'œil (boîte mail + 1re ligne du webhook).
T_EN[summary.subject_warn]="[WARN] ban-404 [%s]: daily summary (%s issue(s))"
T_FR[summary.subject_warn]="[WARN] ban-404 [%s] : résumé quotidien (%s anomalie(s))"
T_DE[summary.subject_warn]="[WARN] ban-404 [%s]: tägliche Zusammenfassung (%s Problem(e))"
T_ES[summary.subject_warn]="[WARN] ban-404 [%s]: resumen diario (%s anomalía(s))"
T_IT[summary.subject_warn]="[WARN] ban-404 [%s]: riepilogo giornaliero (%s anomalia/e)"

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

# Journalisation UNIFIÉE par le moteur (depuis 1.4.28) : le moteur écrit LUI-MÊME ses
# ÉVÉNEMENTS ([+] bans, [-] débans, [i] réparations, verrou occupé) dans LOG_FILE, horodatés —
# que le run soit cron ou manuel (avant 1.4.28, seul le wrapper cron journalisait : les bans
# des runs manuels échappaient aux compteurs de --stats/--summary). Le wrapper cron n'est plus
# qu'un lanceur muet (cf. self_heal_hourly_cron). --no-log coupe l'écriture ; le dry-run ne
# journalise JAMAIS (les lignes [SIMULATION] [+] contiennent le marqueur [+] et fausseraient
# les compteurs). Les messages non événementiels (--help, --list, --diag, verbose...) ne vont
# jamais au journal.
log_line() {  # $1 = ligne déjà formatée
    [ "$LOG_EVENTS" = true ] || return 0
    { printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG_FILE"; } 2>/dev/null
    return 0
}
t_log() {  # comme t, mais duplique la ligne (horodatée) dans LOG_FILE
    local m; m=$(t "$@")
    printf '%s\n' "$m"
    log_line "$m"
}

# Plateforme supportée pour l'APPLICATION des règles ? Sinon le run bascule en LECTURE SEULE (voir le
# fail-safe avant le verrou). Override explicite PLATFORM_VALIDATED (l'admin assume le risque) ; sinon
# détection : distro connue (os-release debian/ubuntu, sourcé en SOUS-SHELL pour ne rien polluer) +
# backend iptables/ipset présent. Sera étendu au fil de l'universalisation (nft, autres distros/panels).
platform_supported() {
    case "${PLATFORM_VALIDATED:-}" in
        true|1|yes|on)  return 0 ;;
        false|0|no|off) return 1 ;;
    esac
    local ids
    ids=$( . /etc/os-release 2>/dev/null; printf ' %s %s ' "${ID:-}" "${ID_LIKE:-}" )
    case "$ids" in *debian*|*ubuntu*) ;; *) return 1 ;; esac
    fw_backend_usable   # le backend résolu (iptables+ipset OU nftables) doit avoir ses outils
}

# ============================================================================
#  Abstraction du backend pare-feu (fw_*) — universalisation 2.1.0
# ----------------------------------------------------------------------------
#  DEUX backends : « iptables » (iptables + ipset, DÉFAUT — le comportement du
#  parc, extrait VERBATIM ici, garanti non régressé par la CI) et « nftables »
#  (opt-in, ou auto-choisi si iptables/ipset absents). Chaque fw_<op> dispatche
#  sur $FW_ACTIVE vers ipt_<op> / nft_<op> ; FW_ACTIVE est figé par fw_init une
#  fois la conf sourcée. COEXISTENCE (règle absolue) : ban-404 n'insère QUE sa
#  propre règle / sa propre table nft namespacée, ne FLUSH jamais le pare-feu et
#  ne touche jamais un artefact tiers — sur nft, notre table « inet ban_404 » est
#  isolée au niveau netfilter (chaînes base multiples autorisées sur un hook).
# ============================================================================
NFT_TABLE_FAMILY="inet"; NFT_TABLE="ban_404"; NFT_CHAIN="input"
NFT_SAVE_FILE="/etc/nftables/ban_404.conf"   # persistance dédiée (notre table SEULE, rechargée par l'unité ci-dessous)
NFT_UNIT="/etc/systemd/system/ban_404-nft.service"   # unité systemd isolée : restaure UNIQUEMENT notre table au boot (aucun flush global)
IPT_BIN="/sbin/iptables"; IPT_SAVE_BIN="/sbin/iptables-save"; NFT_BIN="/usr/sbin/nft"  # résolus par fw_init

fw_have_ipset()    { command -v ipset >/dev/null 2>&1; }
fw_have_iptables() { command -v iptables >/dev/null 2>&1 || [ -x /sbin/iptables ]; }
fw_have_nft()      { command -v nft >/dev/null 2>&1 || [ -x /usr/sbin/nft ]; }

# Backend EFFECTIF (echo iptables|nftables) selon FW_BACKEND + présence des outils.
# auto = PRÉFÉRER iptables+ipset (coexistence avec les scripts iptables déjà en place) ;
# nft seulement si iptables/ipset absents. Un choix explicite est honoré tel quel.
fw_resolve_backend() {
    case "${FW_BACKEND:-auto}" in
        iptables|ipset)  printf 'iptables' ;;
        nft|nftables)    printf 'nftables' ;;
        *) if fw_have_ipset && fw_have_iptables; then printf 'iptables'
           elif fw_have_nft; then printf 'nftables'
           else printf 'iptables'; fi ;;   # repli : platform_supported tranchera (lecture seule)
    esac
}
# Le backend résolu a-t-il ses outils utilisables ? (base du fail-safe plateforme)
fw_backend_usable() {
    case "$(fw_resolve_backend)" in
        nftables) fw_have_nft ;;
        *)        fw_have_ipset && fw_have_iptables ;;
    esac
}
# Fige FW_ACTIVE + les chemins des binaires (cron peut ne pas avoir /sbin dans le PATH).
fw_init() {
    FW_ACTIVE=$(fw_resolve_backend)
    IPT_BIN=$(command -v iptables 2>/dev/null || echo /sbin/iptables)
    IPT_SAVE_BIN=$(command -v iptables-save 2>/dev/null || echo /sbin/iptables-save)
    NFT_BIN=$(command -v nft 2>/dev/null || echo /usr/sbin/nft)
}
fw_backend_label() { case "$FW_ACTIVE" in nftables) printf 'nftables' ;; *) printf 'iptables+ipset' ;; esac; }

# ---------- Backend iptables + ipset (DÉFAUT, comportement historique verbatim) ----------
# LIMITE DURE d'ipset : le timeout (du set comme d'une entrée) est stocké en millisecondes sur
# 31 bits => toute valeur > 2147483 s (~24 j 20 h) fait ÉCHOUER la commande. Un ipset add refusé
# ne bannit PAS l'IP, et l'échec est silencieux dans le flux du moteur : un HONEYPOT_BAN_TIMEOUT
# de 30 j posé en conf locale suffisait à ne plus bannir un seul honeypot. On borne donc à la
# source. Limite propre à ipset : le backend nftables n'en a pas.
IPSET_MAX_TIMEOUT=2147483
ipt_ttl_clamp() {  # $1 = ttl(s) ; echo la valeur bornée (non numérique => BAN_TIMEOUT)
    case "${1:-}" in ''|*[!0-9]*) printf '%s' "$BAN_TIMEOUT"; return ;; esac
    if [ "$1" -gt "$IPSET_MAX_TIMEOUT" ]; then printf '%s' "$IPSET_MAX_TIMEOUT"; else printf '%s' "$1"; fi
}
ipt_set_exists()       { ipset list "$IPSET_NAME" &>/dev/null; }
ipt_is_banned()        { ipset test "$IPSET_NAME" "$1" &>/dev/null; }        # $1=ip
ipt_ban_ip()           { ipset -exist add "$IPSET_NAME" "$1"; }              # $1=ip (timeout du set)
ipt_ban_ip_ttl()       { ipset -exist add "$IPSET_NAME" "$1" timeout "$(ipt_ttl_clamp "$2")"; } # $1=ip $2=ttl(s)
ipt_unban_ip()         { ipset del "$IPSET_NAME" "$1" 2>/dev/null; }         # $1=ip
ipt_flush()            { ipset flush "$IPSET_NAME" 2>/dev/null; }
ipt_list_members()     { ipset list "$IPSET_NAME" 2>/dev/null | awk '/^Members:/{m=1;next} m&&NF{print $1}'; }
ipt_list_members_raw() { ipset list "$IPSET_NAME" 2>/dev/null | awk '/^Members:/{m=1;next} m&&NF{print}'; }
ipt_count()            { ipset_count_members "$1"; }                          # $1=setname
ipt_list_sets()        { ipset list -n 2>/dev/null | grep -vxF "${IPSET_NAME}_grow"; }
ipt_persist()          { mkdir -p "$(dirname "$IPSET_SAVE_FILE")"; ipset save > "$IPSET_SAVE_FILE"; }
ipt_rule_present()     { "$IPT_BIN" -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP &>/dev/null; }
ipt_persist_present()  { [ -f "$IPSET_SAVE_FILE" ] && [ -f "$IPTABLES_RULES_FILE" ]; }
# Auto-agrandissement (one-shot) des sets pré-1.4.26 (maxelem 65536 -> 1048576) : copie + swap
# atomique, bans conservés. Sans objet en nft (set dynamique à size fixée). Verbatim d'origine.
ipt_grow_set() {
    local cur_max tmp_set
    cur_max=$(ipset list "$IPSET_NAME" -t 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="maxelem"){print $(i+1); exit}}')
    if [ -n "$cur_max" ] && [ "$cur_max" -lt 1048576 ]; then
        tmp_set="${IPSET_NAME}_grow"
        ipset destroy "$tmp_set" 2>/dev/null
        if ipset create "$tmp_set" hash:ip timeout "$(ipt_ttl_clamp "$BAN_TIMEOUT")" maxelem 1048576 hashsize 65536 2>/dev/null; then
            ipset save "$IPSET_NAME" 2>/dev/null | awk -v t="$tmp_set" '/^add /{$2=t; print}' | ipset restore -exist 2>/dev/null
            if ipset swap "$tmp_set" "$IPSET_NAME" 2>/dev/null; then
                ipset destroy "$tmp_set" 2>/dev/null
                ipset save > "$IPSET_SAVE_FILE"
                t_log heal.ipset_grown "$IPSET_NAME" "$cur_max"
            else
                ipset destroy "$tmp_set" 2>/dev/null
            fi
        fi
    fi
}
ipt_ensure_infra() {
    if ! ipset list "$IPSET_NAME" &>/dev/null; then
        ipset create "$IPSET_NAME" hash:ip timeout "$(ipt_ttl_clamp "$BAN_TIMEOUT")" maxelem 1048576 hashsize 65536
    else
        ipt_grow_set
    fi
    if ! "$IPT_BIN" -C INPUT -m set --match-set "$IPSET_NAME" src -j DROP &>/dev/null; then
        "$IPT_BIN" -I INPUT -m set --match-set "$IPSET_NAME" src -j DROP
        mkdir -p "$(dirname "$IPTABLES_RULES_FILE")"
        "$IPT_SAVE_BIN" > "$IPTABLES_RULES_FILE"
    fi
}

# ---------- Backend nftables (opt-in ; table « inet ban_404 » NAMESPACÉE, coexistence-safe) ----------
# Set ipv4_addr à timeout par défaut (parité avec l'ipset hash:ip timeout=BAN_TIMEOUT) ; les bans
# honeypot reçoivent un timeout par élément plus long. Test d'appartenance en O(1) via « get element »
# (nft ≥ 0.9.3, Debian 11+/Ubuntu 20.04+ ; le backend nft cible des installs modernes) — bien moins
# coûteux qu'un grep du dump complet à chaque IP candidate de la boucle de ban. La règle « ip saddr
# @set drop » vit dans NOTRE chaîne base ; les autres tables (firewalld/ufw...) restent évaluées =>
# pas de prise de contrôle. IPv4 uniquement, comme l'ipset actuel.
nft_set_exists() { "$NFT_BIN" list set "$NFT_TABLE_FAMILY" "$NFT_TABLE" "$IPSET_NAME" &>/dev/null; }
nft_is_banned()  { "$NFT_BIN" get element "$NFT_TABLE_FAMILY" "$NFT_TABLE" "$IPSET_NAME" "{ $1 }" &>/dev/null; }
nft_ban_ip()     { "$NFT_BIN" add element "$NFT_TABLE_FAMILY" "$NFT_TABLE" "$IPSET_NAME" "{ $1 }" 2>/dev/null; }
nft_ban_ip_ttl() { "$NFT_BIN" add element "$NFT_TABLE_FAMILY" "$NFT_TABLE" "$IPSET_NAME" "{ $1 timeout ${2}s }" 2>/dev/null; }
nft_unban_ip()   { "$NFT_BIN" delete element "$NFT_TABLE_FAMILY" "$NFT_TABLE" "$IPSET_NAME" "{ $1 }" 2>/dev/null; }
nft_flush()      { "$NFT_BIN" flush set "$NFT_TABLE_FAMILY" "$NFT_TABLE" "$IPSET_NAME" 2>/dev/null; }
nft_list_members() { "$NFT_BIN" list set "$NFT_TABLE_FAMILY" "$NFT_TABLE" "$IPSET_NAME" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'; }
nft_count() { "$NFT_BIN" list set "$NFT_TABLE_FAMILY" "$NFT_TABLE" "$1" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l | tr -d ' '; }
nft_list_sets()  { nft_set_exists && printf '%s\n' "$IPSET_NAME"; }   # portée = NOTRE table (pas d'inventaire des tables tierces)
# expires nft humain (1d23h59m30s812ms) -> secondes (pour le tri de « list ») ; '?' si illisible.
# Le « m » d'un « <n>ms » (millisecondes) est distingué du « m » des minutes en regardant le
# caractère suivant : « ms » => on jette la fraction (pas de sous-seconde), sinon minutes.
nft_dur_to_secs() {
    printf '%s' "${1:-}" | awk '{ s=0; n=""; ok=0
        for(i=1;i<=length($0);i++){ c=substr($0,i,1)
            if(c ~ /[0-9]/){n=n c}
            else if(c=="d"){s+=n*86400;n="";ok=1} else if(c=="h"){s+=n*3600;n="";ok=1}
            else if(c=="m"){ if(substr($0,i+1,1)=="s"){n="";i++} else {s+=n*60;n="";ok=1} }
            else if(c=="s"){s+=n;n="";ok=1} }
        if(ok) print s; else print "?" }'
}
# Membres « bruts » façon ipset (« ip timeout <secs_résiduelles> ») pour do_list ET la bascule
# inverse nft->iptables (transfert des bans). La variable awk s'appelle « ev » (JAMAIS « exp » :
# c'est une fonction intégrée de gawk => « exp= » est une erreur de syntaxe sous gawk, silencieuse
# sous mawk — incident constaté en production). On retire la fraction « <n>ms » de la durée
# « expires » avant conversion (sinon le « m » de « ms » serait compté comme des minutes).
nft_list_members_raw() {
    "$NFT_BIN" list set "$NFT_TABLE_FAMILY" "$NFT_TABLE" "$IPSET_NAME" 2>/dev/null | tr ',' '\n' \
        | awk '{ ip=""; ev=""
            for(i=1;i<=NF;i++){ if($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/) ip=$i; if($i=="expires") ev=$(i+1) }
            if(ip!="") print ip, ev }' \
        | while read -r ip ev; do printf '%s timeout %s\n' "$ip" "$(nft_dur_to_secs "$ev")"; done
}
nft_rule_present()    { "$NFT_BIN" list chain "$NFT_TABLE_FAMILY" "$NFT_TABLE" "$NFT_CHAIN" 2>/dev/null | grep -q "@$IPSET_NAME drop"; }
nft_persist_present() { [ -f "$NFT_SAVE_FILE" ]; }
nft_grow_set()        { return 0; }   # sans objet en nft (set dynamique)
nft_ensure_infra() {
    "$NFT_BIN" list table "$NFT_TABLE_FAMILY" "$NFT_TABLE" &>/dev/null \
        || "$NFT_BIN" add table "$NFT_TABLE_FAMILY" "$NFT_TABLE" 2>/dev/null
    nft_set_exists \
        || "$NFT_BIN" add set "$NFT_TABLE_FAMILY" "$NFT_TABLE" "$IPSET_NAME" \
             "{ type ipv4_addr; flags timeout; timeout ${BAN_TIMEOUT}s; size 1048576; }" 2>/dev/null
    "$NFT_BIN" list chain "$NFT_TABLE_FAMILY" "$NFT_TABLE" "$NFT_CHAIN" &>/dev/null \
        || "$NFT_BIN" add chain "$NFT_TABLE_FAMILY" "$NFT_TABLE" "$NFT_CHAIN" \
             "{ type filter hook input priority 0; policy accept; }" 2>/dev/null
    nft_rule_present \
        || "$NFT_BIN" add rule "$NFT_TABLE_FAMILY" "$NFT_TABLE" "$NFT_CHAIN" ip saddr "@$IPSET_NAME" drop 2>/dev/null
}
# Persistance nft — COEXISTENCE-SAFE. Fichier dédié à NOTRE table (idiome « create+delete+define » =
# rechargeable, vérifié `nft -f`), restauré au boot par une **unité systemd DÉDIÉE** qui charge
# UNIQUEMENT ce fichier (`nft -f`), SANS aucun « flush ruleset » global. On n'active JAMAIS le service
# nftables global et on n'édite JAMAIS /etc/nftables.conf : sur un serveur qui persiste via
# netfilter-persistent (iptables) avec une nftables.conf en `flush ruleset` (cas courant Debian/Ubuntu),
# activer ce service viderait au boot les tables tierces — dont les chaînes fail2ban de `ip filter`.
# Notre unité isolée ne touche donc que `inet ban_404`. Idempotent ; best-effort (systemd absent => on
# écrit juste le fichier). Nettoyée par la bascule inverse (fw_migrate_if_needed).
nft_persist() {
    mkdir -p "$(dirname "$NFT_SAVE_FILE")"
    { printf 'table %s %s\ndelete table %s %s\n' "$NFT_TABLE_FAMILY" "$NFT_TABLE" "$NFT_TABLE_FAMILY" "$NFT_TABLE"
      "$NFT_BIN" list table "$NFT_TABLE_FAMILY" "$NFT_TABLE" 2>/dev/null
    } > "$NFT_SAVE_FILE"
    command -v systemctl >/dev/null 2>&1 || return 0
    [ -d /etc/systemd/system ] || return 0
    local want
    want="[Unit]
Description=ban-404 nftables table restore (isolated, no global flush)
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$NFT_BIN -f $NFT_SAVE_FILE
[Install]
WantedBy=multi-user.target"
    if [ ! -f "$NFT_UNIT" ] || [ "$(cat "$NFT_UNIT" 2>/dev/null)" != "$want" ]; then
        printf '%s\n' "$want" > "$NFT_UNIT" 2>/dev/null || return 0
        systemctl daemon-reload >/dev/null 2>&1
        systemctl enable ban_404-nft.service >/dev/null 2>&1
    fi
    return 0
}

# ---------- Dispatchers fw_* (interface unique consommée par le moteur) ----------
fw_ensure_infra()     { case "$FW_ACTIVE" in nftables) nft_ensure_infra ;; *) ipt_ensure_infra ;; esac; }
fw_set_exists()       { case "$FW_ACTIVE" in nftables) nft_set_exists ;; *) ipt_set_exists ;; esac; }
fw_is_banned()        { case "$FW_ACTIVE" in nftables) nft_is_banned "$1" ;; *) ipt_is_banned "$1" ;; esac; }
fw_ban_ip()           { case "$FW_ACTIVE" in nftables) nft_ban_ip "$1" ;; *) ipt_ban_ip "$1" ;; esac; }
fw_ban_ip_ttl()       { case "$FW_ACTIVE" in nftables) nft_ban_ip_ttl "$1" "$2" ;; *) ipt_ban_ip_ttl "$1" "$2" ;; esac; }
fw_unban_ip()         { case "$FW_ACTIVE" in nftables) nft_unban_ip "$1" ;; *) ipt_unban_ip "$1" ;; esac; }
fw_flush()            { case "$FW_ACTIVE" in nftables) nft_flush ;; *) ipt_flush ;; esac; }
fw_list_members()     { case "$FW_ACTIVE" in nftables) nft_list_members ;; *) ipt_list_members ;; esac; }
fw_list_members_raw() { case "$FW_ACTIVE" in nftables) nft_list_members_raw ;; *) ipt_list_members_raw ;; esac; }
fw_list_sets()        { case "$FW_ACTIVE" in nftables) nft_list_sets ;; *) ipt_list_sets ;; esac; }
fw_count()            { case "$FW_ACTIVE" in nftables) nft_count "$1" ;; *) ipt_count "$1" ;; esac; }
fw_persist()          { case "$FW_ACTIVE" in nftables) nft_persist ;; *) ipt_persist ;; esac; }
fw_rule_present()     { case "$FW_ACTIVE" in nftables) nft_rule_present ;; *) ipt_rule_present ;; esac; }
fw_persist_present()  { case "$FW_ACTIVE" in nftables) nft_persist_present ;; *) ipt_persist_present ;; esac; }

# Le backend sait-il STOCKER cette adresse ? Les deux backends sont IPv4 uniquement : l'ipset est
# créé « family inet » (le défaut) et le set nftables est un ipv4_addr. Passer une IPv6 à
# `ipset add` ÉCHOUE — et l'échec passait inaperçu : la ligne [+] partait au journal, la mémoire
# de récidive était alimentée, mais l'IP n'était JAMAIS bloquée ; `ipset test` la disant libre, le
# passage suivant la « re-bannissait ». Sur le parc, deux IPv6 avaient accumulé 25 et 26 bans
# fictifs (constaté le 13 sept. 2026 — elles trônaient en tête du bloc Récidivistes, loin devant
# le meilleur IPv4 à 4 bans, ce qui est la signature du ban qui ne s'applique pas).
# Le vrai support IPv6 (second set family inet6 + ip6tables, persistance rules.v6) est une
# FONCTIONNALITÉ à part entière, hors de ce correctif : ici on cesse seulement de mentir.
fw_addr_supported() { case "$1" in *:*) return 1 ;; *) return 0 ;; esac; }

# Bascule migratoire de backend (one-shot, détectée au run). FAIL-SAFE : on ne retire les artefacts
# de l'ancien backend qu'APRÈS avoir vérifié que le nouveau applique bien sa règle — sinon on ne
# touche à RIEN (aucun trou de protection). Jamais de flush du pare-feu. Réversible (les deux sens).
fw_migrate_if_needed() {
    if [ "$FW_ACTIVE" = nftables ] && fw_have_ipset && ipset list "$IPSET_NAME" &>/dev/null; then
        # iptables/ipset -> nftables
        nft_ensure_infra
        nft_rule_present || { t_log fw.migrate_abort "nftables"; return 0; }
        ipset save "$IPSET_NAME" 2>/dev/null | awk '/^add /{ to=0; for(i=1;i<=NF;i++) if($i=="timeout") to=$(i+1); print $3, to }' \
            | while read -r ip to; do
                  [ -z "$ip" ] && continue
                  if [ "${to:-0}" -gt 0 ] 2>/dev/null; then nft_ban_ip_ttl "$ip" "$to"; else nft_ban_ip "$ip"; fi
              done
        nft_persist
        if fw_have_iptables; then
            "$IPT_BIN" -D INPUT -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null
            mkdir -p "$(dirname "$IPTABLES_RULES_FILE")"; "$IPT_SAVE_BIN" > "$IPTABLES_RULES_FILE" 2>/dev/null
        fi
        ipset destroy "$IPSET_NAME" 2>/dev/null
        [ -f "$IPSET_SAVE_FILE" ] && ipset save > "$IPSET_SAVE_FILE" 2>/dev/null
        t_log fw.migrated "iptables+ipset" "nftables"
    elif [ "$FW_ACTIVE" != nftables ] && fw_have_nft && "$NFT_BIN" list table "$NFT_TABLE_FAMILY" "$NFT_TABLE" &>/dev/null; then
        # nftables -> iptables/ipset
        ipt_ensure_infra
        ipt_rule_present || { t_log fw.migrate_abort "iptables+ipset"; return 0; }
        nft_list_members_raw | while read -r ip _to_kw to; do
            [ -z "$ip" ] && continue
            if [ "${to:-0}" -gt 0 ] 2>/dev/null; then ipt_ban_ip_ttl "$ip" "$to"; else ipt_ban_ip "$ip"; fi
        done
        ipt_persist
        "$NFT_BIN" delete table "$NFT_TABLE_FAMILY" "$NFT_TABLE" 2>/dev/null
        [ -f "$NFT_SAVE_FILE" ] && rm -f "$NFT_SAVE_FILE"
        # Retrait de l'unité de restauration dédiée (posée par nft_persist).
        if [ -f "$NFT_UNIT" ] && command -v systemctl >/dev/null 2>&1; then
            systemctl disable ban_404-nft.service >/dev/null 2>&1; rm -f "$NFT_UNIT"; systemctl daemon-reload >/dev/null 2>&1
        fi
        t_log fw.migrated "nftables" "iptables+ipset"
    fi
}

fw_init   # fige FW_ACTIVE + les chemins des binaires (conf déjà sourcée ci-dessus)

# Initialisation des options
DRY_RUN=false
SHOW_BLOCKED=false
VERBOSE=false
DO_LIST=false
DO_STATS=false
DO_DIAG=false
DO_HEALTH=false
LIST_BY_TIMEOUT=false
SHOW_AVG24=false     # --avg : ajoute le sous-bloc « Moyennes 24 h » à diag/stats (toujours dans le résumé)
RECID_PTR=false      # résumé : PTR du bloc « Récidivistes » (≤ 10 IP) même sans RESOLVE_PTR
LOG_EVENTS=true      # écriture des événements dans LOG_FILE (--no-log ou dry-run => false)

show_help() {
    t version.line "$BAN404_VERSION"
    t version.author
    t help.usage "$0"
    echo ""
    t help.subcommands_header
    t help.list
    t help.stats
    t help.diag
    t help.health
    t help.summary
    t help.unban
    t help.checknotif
    t help.lang
    t help.version
    t help.help
    t help.compat
    echo ""
    t help.options_header
    t help.dryrun
    t help.showblocked
    t help.verbose
    t help.nolog
    t help.bytimeout
    t help.resolve
    t help.avg
    t help.nohealth
    echo ""
    t help.conf_header "$CONF_FILE"
    t help.conf_repo_raw
    t help.conf_whitelist_ip
    t help.conf_whitelist_cidr
    t help.conf_exclude_vhosts
    t help.conf_log_profile
    t help.conf_lang
    t help.conf_window
    t help.conf_ban_timeout
    t help.conf_tail
    t help.conf_threshold
    t help.conf_distinct
    t help.conf_honeypot_score
    t help.conf_honeypot_timeout
    t help.conf_ban_escalation
    t help.conf_escalation_memory
    t help.conf_aggressive_score
    t help.conf_nickname
    t help.conf_webhook
    t help.conf_chatcard
    t help.conf_email
    t help.conf_from
    t help.conf_min_bans
    t help.conf_notify_bans
    t help.conf_daily
    t help.conf_cron_step
    t help.conf_fw_backend
    t help.conf_resolve
    t help.conf_ptr_timeout
    t help.conf_postflood
    t help.conf_health
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
# Perf : les IP EXACTES sont retirées par `ipset del` DIRECT (O(whitelist)), SANS énumérer le
# set. On ne balaie les membres (O(membres)) QUE s'il existe au moins un CIDR whitelisté — seul
# cas où l'appartenance ne se teste pas par simple égalité. Sur un gros set post-incident
# (ex-cible de botnet : ~106k entrées, WHITELIST_CIDR vide), l'ancien balayage systématique coûtait
# ~30 min À CHAQUE passage horaire ; désormais il ne tourne plus du tout dans ce cas.
enforce_whitelist_unban() {
    local ip removed=false w
    # 1) IP exactes : retrait DIRECT (ipset del est un no-op silencieux si l'IP n'est pas bannie).
    if [ -n "$WHITELIST_IP" ]; then
        local -a wips=()
        IFS='|' read -r -a wips <<< "$WHITELIST_IP"
        for w in "${wips[@]}"; do
            [ -z "$w" ] && continue
            if [ "$DRY_RUN" = true ]; then
                fw_is_banned "$w" && t wl.sim_unban "$w"
            elif fw_unban_ip "$w"; then
                t_log wl.unban "$w"; removed=true
                escalation_forget "$w"   # whitelistée => son passé de récidiviste n'a plus de sens
            fi
        done
    fi
    # 2) CIDR : l'appartenance à une plage impose d'énumérer les membres. Balayage réservé au cas
    #    où au moins un CIDR est whitelisté (sinon tout a été traité en 1) sans le moindre parcours).
    if [ -n "$WHITELIST_CIDR" ]; then
        while read -r ip; do
            [ -z "$ip" ] && continue
            in_whitelist_cidr "$ip" || continue
            if [ "$DRY_RUN" = true ]; then
                t wl.sim_unban "$ip"
            elif fw_unban_ip "$ip"; then
                t_log wl.unban "$ip"; removed=true
                escalation_forget "$ip"
            fi
        done < <(fw_list_members)
    fi
    if [ "$removed" = true ]; then
        fw_persist
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
# Échappe &<> pour insérer du texte dans du HTML (mail HTML du résumé). Via sed : la substitution
# bash ${var//x/&...} traite le & comme le texte CAPTURÉ depuis bash 5.2 (≠ 5.1) => non portable ;
# sed a un comportement constant (& = capture, \& = & littéral) sur toutes les versions.
html_escape() {
    printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
}
# Texte brut -> HTML PROPORTIONNEL (pas de <pre>) : échappe &<> puis \n -> <br>. Les alignements par
# espaces multiples sont perdus (police proportionnelle assumée), mais les sections du résumé hors
# bloc ipset sont du label:valeur / des listes -> se lisent bien ainsi.
html_text() {
    local s; s=$(html_escape "$1"); s="${s//$'\n'/<br>}"; printf '%s' "$s"
}
# Texte brut -> sous-ensemble de tags de la CARTE Google Chat (widget textParagraph : <b>/<br>/<font>
# ; pas de <div>/<table>). Échappe &<>, met en GRAS les lignes d'en-tête « ── … ── », \n -> <br>.
# Traitement ligne par ligne via glob bash (pas de sed multi-octets) : robuste sur les filets UTF-8
# — si le glob ne matchait pas, la ligne resterait simplement non grasse (jamais d'erreur).
card_text() {
    local out="" line first=1
    while IFS= read -r line || [ -n "$line" ]; do
        [ "$first" = 1 ] || out+="<br>"; first=0
        line=$(html_escape "$line")
        case "$line" in
            "── "*" ──") out+="<b>$line</b>" ;;
            *)           out+="$line" ;;
        esac
    done <<< "$1"
    printf '%s' "$out"
}
# En-tête de mail encodé RFC 2047 (base64 UTF-8) SI le texte contient du non-ASCII : un « Résumé »
# accentué émis brut 8 bits dans un Subject: n'est pas conforme => mojibake possible. ASCII pur =>
# renvoyé tel quel (pas d'encodage inutile). Détection en LC_ALL=C ([^ -~] = hors ASCII imprimable).
encode_header() {
    if printf '%s' "$1" | LC_ALL=C grep -q '[^ -~]'; then
        printf '=?UTF-8?B?%s?=' "$(printf '%s' "$1" | base64 | tr -d '\n')"
    else
        printf '%s' "$1"
    fi
}
# Construit le corps JSON du webhook selon le service. $1 = texte brut (plain, tous services) ;
# $2 = corps CARTE (optionnel, sous-ensemble <b>/<br>/<font>) ; $3 = titre de carte (optionnel).
# Carte cardsV2 UNIQUEMENT pour Google Chat quand WEBHOOK_CHAT_CARD est actif ET $2 fourni — seule
# la carte accepte la couleur (<font color>), le message {text} n'en accepte aucune. Sinon texte
# simple : Google Chat n'accepte QUE "text" (rejet 400 des champs inconnus) ; les autres services
# (Slack/Mattermost/n8n/Discord/Teams) acceptent "text" et "content".
build_webhook_payload() {
    case "$WEBHOOK_URL" in
        *chat.googleapis.com*)
            # Le dépassement de taille est traité EN AMONT par send_webhook (découpe en plusieurs
            # messages) ; la garde ci-dessous n'est qu'un filet pour un appel direct (check_webhook) :
            # un corps carte trop long partirait en {text}, sans couleur mais sans 400 silencieux.
            if [ -n "${2:-}" ] && [ "${#2}" -le "${WEBHOOK_CHAT_MAXLEN:-3800}" ] && diag_is_on "${WEBHOOK_CHAT_CARD:-true}"; then
                printf '{"cardsV2":[{"cardId":"ban404","card":{"header":{"title":"%s"},"sections":[{"widgets":[{"textParagraph":{"text":"%s"}}]}]}}]}' \
                       "$(json_escape "${3:-$(server_label)}")" "$(json_escape "$2")"
            else
                printf '{"text":"%s"}' "$(json_escape "$1")"
            fi ;;
        *) local esc; esc=$(json_escape "$1"); printf '{"text":"%s","content":"%s"}' "$esc" "$esc" ;;
    esac
}
# Découpe un corps en morceaux d'au plus $2 caractères, résultat dans le tableau global SPLIT_PARTS
# (les fonctions bash ne renvoient pas de tableau — même idiome que HEALTH_LINES/IPSET_PROSE).
# La coupe se fait TOUJOURS sur une frontière de ligne ($3 = « <br> » pour la carte, saut de ligne
# pour le texte) : on n'ampute donc jamais une balise, car card_text/vitals_card/ipset_card ouvrent
# ET ferment chaque <font>/<b> à l'intérieur d'une même ligne. Accumulation gloutonne => nombre de
# morceaux minimal. Une ligne plus longue que la limite (cas théorique) part seule. Au-delà de
# WEBHOOK_CHAT_MAXPARTS morceaux, on ARRÊTE d'accumuler (garde-fou anti-rafale : mieux vaut un
# résumé tronqué qu'une avalanche de messages ; jamais atteint par un résumé normal).
webhook_split() {  # $1 = corps, $2 = limite, $3 = séparateur de lignes
    local body="$1" lim="$2" sep="$3" cur="" line max
    max=${WEBHOOK_CHAT_MAXPARTS:-4}
    SPLIT_PARTS=()
    [ -z "$body" ] && return 0
    while [ -n "$body" ]; do
        case "$body" in
            *"$sep"*) line="${body%%"$sep"*}"; body="${body#*"$sep"}" ;;
            *)        line="$body"; body="" ;;
        esac
        if [ -z "$cur" ]; then
            cur="$line"
        elif [ "$(( ${#cur} + ${#sep} + ${#line} ))" -le "$lim" ]; then
            cur+="$sep$line"
        else
            SPLIT_PARTS+=("$cur"); cur="$line"
            [ "${#SPLIT_PARTS[@]}" -ge "$max" ] && { cur=""; break; }   # cap atteint : on jette le reste
        fi
    done
    [ -n "$cur" ] && SPLIT_PARTS+=("$cur")
    return 0
}
webhook_post() { curl -fsS -m 15 -H 'Content-Type: application/json; charset=UTF-8' -X POST -d "$1" "$WEBHOOK_URL" >/dev/null 2>&1 || true; }
send_webhook() {  # $1 = texte plain ; $2 = corps carte (optionnel) ; $3 = titre carte (optionnel)
    [ -z "$WEBHOOK_URL" ] && return 0
    command -v curl >/dev/null 2>&1 || return 0
    local i n title
    case "$WEBHOOK_URL" in
        *chat.googleapis.com*)
            # Google Chat rejette (400) un message trop long : on DÉCOUPE plutôt que de perdre le
            # résumé — en cartes si elles sont actives (couleur préservée sur TOUS les morceaux, le
            # titre porte « (i/n) »), en texte simple sinon. Envois séquentiels => ordre respecté.
            if [ -n "${2:-}" ] && diag_is_on "${WEBHOOK_CHAT_CARD:-true}"; then
                webhook_split "$2" "${WEBHOOK_CHAT_MAXLEN:-3800}" '<br>'
                n=${#SPLIT_PARTS[@]}
                for ((i=0; i<n; i++)); do
                    title="${3:-$(server_label)}"; [ "$n" -gt 1 ] && title="$title ($((i+1))/$n)"
                    webhook_post "$(build_webhook_payload "$1" "${SPLIT_PARTS[i]}" "$title")"
                done
            else
                webhook_split "$1" "${WEBHOOK_CHAT_MAXLEN:-3800}" $'\n'
                for ((i=0; i<${#SPLIT_PARTS[@]}; i++)); do
                    webhook_post "$(build_webhook_payload "${SPLIT_PARTS[i]}")"
                done
            fi
            SPLIT_PARTS=() ;;
        *) webhook_post "$(build_webhook_payload "$1" "${2:-}" "${3:-}")" ;;
    esac
}
send_email() {  # $1 = sujet, $2 = corps texte, $3 = corps HTML (optionnel)
    [ -z "$NOTIFY_EMAIL" ] && return 0
    local bnd
    if [ -n "$3" ] && command -v sendmail >/dev/null 2>&1 && command -v base64 >/dev/null 2>&1; then
        # multipart/alternative (texte + HTML) : le client choisit ; mobile/Gmail => HTML (tables +
        # triangles colorés). sendmail -t : en-têtes maîtrisés, portable (fourni par tout MTA). Repli
        # mail/plain plus bas si sendmail (ou base64) absent.
        # Les DEUX parties sont émises en Content-Transfer-Encoding: base64. Sans CTE, le corps 8 bits
        # (accents UTF-8) partait sur UNE ligne géante (html_text => tout en <br>) : le MTA la repliait
        # à 76 colonnes, et le pli, rendu comme un espace en HTML, cassait le contenu (« év ol. »,
        # « < br> »). base64 : le décodeur ignore tout saut inséré => reconstruction exacte. Le Subject
        # accentué passe par encode_header (RFC 2047), sinon mojibake dans l'objet.
        bnd="b404_$(date +%s)_$$"
        {
            printf 'To: %s\n' "$NOTIFY_EMAIL"
            [ -n "$NOTIFY_FROM" ] && printf 'From: %s\n' "$NOTIFY_FROM"
            printf 'Subject: %s\nMIME-Version: 1.0\n' "$(encode_header "$1")"
            printf 'Content-Type: multipart/alternative; boundary="%s"\n\n' "$bnd"
            printf -- '--%s\n' "$bnd"
            printf 'Content-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: base64\n\n'
            printf '%s' "$2" | base64
            printf -- '--%s\n' "$bnd"
            printf 'Content-Type: text/html; charset=UTF-8\nContent-Transfer-Encoding: base64\n\n'
            printf '%s' "$3" | base64
            printf -- '--%s--\n' "$bnd"
        } | sendmail -t 2>/dev/null || true
    elif command -v mail >/dev/null 2>&1; then
        if [ -n "$NOTIFY_FROM" ]; then printf '%s\n' "$2" | mail -s "$1" -r "$NOTIFY_FROM" "$NOTIFY_EMAIL" 2>/dev/null || true
        else printf '%s\n' "$2" | mail -s "$1" "$NOTIFY_EMAIL" 2>/dev/null || true; fi
    elif command -v sendmail >/dev/null 2>&1; then
        { printf 'To: %s\n' "$NOTIFY_EMAIL"; [ -n "$NOTIFY_FROM" ] && printf 'From: %s\n' "$NOTIFY_FROM"
          printf 'Subject: %s\n\n%s\n' "$(encode_header "$1")" "$2"; } | sendmail -t 2>/dev/null || true
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
notify() {  # $1 = sujet, $2 = corps texte (webhook plain + text/plain mail), $3 = corps HTML (mail), $4 = corps CARTE (Google Chat)
    # Webhook = texte brut (prose) SAUF si $4 fourni ET Google Chat + WEBHOOK_CHAT_CARD => carte colorée
    # (le sujet devient le titre de carte). Mail = multipart texte + HTML (tableau) quand $3 est fourni.
    send_webhook "$1"$'\n'"$2" "${4:-}" "$1"
    send_email "$1" "$2" "${3:-}"
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

# Durée en secondes => forme humaine courte (« 7h 12m », « 3h », « 45m »), pour la note de fenêtre.
metrics_fmt_span() { awk -v s="${1:-0}" 'BEGIN{ s=int(s); h=int(s/3600); m=int((s%3600)/60); if(h>0){ if(m>0) printf "%dh %dm", h, m; else printf "%dh", h } else printf "%dm", m }'; }

# Sous-bloc « Moyennes 24 h » (load, IO, réseau, mémoire), calculé depuis METRICS_FILE (échantillons
# horaires posés par metrics_sample). Auto-portant : calcule ET imprime. Appelé par build_stats_text
# (résumé + stats --avg) et do_diag (diag --avg). IO/réseau = delta de compteurs cumulatifs par
# intervalle (les intervalles en baisse — reboot/wrap — sont SAUTÉS) ; load/mémoire = relevés
# discrets moyennés. Pic pour load/IO/réseau, minimum (pire dispo) pour la mémoire. Historique
# insuffisant (< 2 échantillons) ou fenêtre < WINDOW_NOTE_SECS => message / note dédiés (pas de valeur trompeuse).
build_metrics_averages() {
    local now cut out n span la lmx ioa iomx rxa txa rxm txm ma mmn iface
    now=$(date +%s); cut=$((now - 86400))
    if [ ! -r "$METRICS_FILE" ]; then
        t stats.avg24_insufficient "$(metrics_fmt_span 0)"
        return 0
    fi
    out=$(awk -v cut="$cut" '
        $1 ~ /^[0-9]+$/ && ($1+0) >= cut {
            n++; if (first=="") first=$1; last=$1
            if ($2 ~ /^[0-9.]+$/) { lsum+=$2; lcnt++; if (lmax=="" || $2+0>lmax) lmax=$2+0 }
            if ($6 ~ /^[0-9]+$/)  { msum+=$6; mcnt++; if (mmin=="" || $6+0<mmin) mmin=$6+0 }
            if ($3 ~ /^[0-9]+$/) {
                if (pio!="") { dt=$1-pt; if (dt>0 && $3+0>=pio) { d=$3-pio; iosum+=d; iodt+=dt; r=d/(dt*10000); if (iomax=="" || r>iomax) iomax=r } }
                pio=$3; pt=$1
            }
            if ($4 ~ /^[0-9]+$/ && $5 ~ /^[0-9]+$/) {
                if (prx!="") { dn=$1-ptn; if (dn>0 && $4+0>=prx && $5+0>=ptx) { rxs+=$4-prx; txs+=$5-ptx; ndt+=dn; rr=($4-prx)/dn; tr=($5-ptx)/dn; if (rxmax=="" || rr>rxmax) rxmax=rr; if (txmax=="" || tr>txmax) txmax=tr } }
                prx=$4; ptx=$5; ptn=$1
            }
        }
        END {
            span=(first!="" ? last-first : 0)
            la =(lcnt>0 ? sprintf("%.2f", lsum/lcnt) : "na"); lmx=(lcnt>0 ? sprintf("%.2f", lmax) : "na")
            ioa=(iodt>0 ? sprintf("%.1f", iosum/(iodt*10000)) : "na"); iomx=(iodt>0 ? sprintf("%.1f", iomax) : "na")
            rxa=(ndt>0 ? sprintf("%.0f", rxs/ndt) : "na"); txa=(ndt>0 ? sprintf("%.0f", txs/ndt) : "na")
            rxm=(ndt>0 ? sprintf("%.0f", rxmax) : "na"); txm=(ndt>0 ? sprintf("%.0f", txmax) : "na")
            ma =(mcnt>0 ? sprintf("%d", int(msum/mcnt+0.5)) : "na"); mmn=(mcnt>0 ? sprintf("%d", mmin) : "na")
            printf "%d %d %s %s %s %s %s %s %s %s %s %s\n", n+0, span, la, lmx, ioa, iomx, rxa, txa, rxm, txm, ma, mmn
        }' "$METRICS_FILE" 2>/dev/null)
    read -r n span la lmx ioa iomx rxa txa rxm txm ma mmn <<< "$out"
    if [ -z "$n" ] || [ "$n" -lt 2 ] 2>/dev/null; then
        t stats.avg24_insufficient "$(metrics_fmt_span "${span:-0}")"
        return 0
    fi
    printf '\n── %s ──\n' "$(t stats.avg24_header)"
    [ "$la" != na ] && t stats.avg24_load "$la" "$lmx"
    [ "$ioa" != na ] && t stats.avg24_io "$ioa" "$iomx"
    if [ "$rxa" != na ]; then
        iface=$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
        t stats.avg24_net "${iface:-?}" "$(health_rate "$rxa")" "$(health_rate "$rxm")" "$(health_rate "$txa")" "$(health_rate "$txm")"
    fi
    [ "$ma" != na ] && t stats.avg24_mem "$ma" "$mmn"
    [ "$span" -lt "$WINDOW_NOTE_SECS" ] 2>/dev/null && printf '   %s\n' "$(t stats.avg24_window "$(metrics_fmt_span "$span")")"
    return 0
}
# Compte les entrées d'un ipset SANS dumper les membres : `ipset list -t` (terse = en-tête seul,
# déjà utilisé pour lire maxelem) donne « Number of entries: N ». Crucial pour un set saturé
# (des dizaines de milliers d'IP) relevé à chaque passage horaire. Repli sur l'idiome « Members: »
# du projet si le terse ne fournit pas le champ (vieux ipset). Écho l'entier (0 par défaut).
ipset_count_members() {
    local c
    c=$(ipset list -t "$1" 2>/dev/null | awk -F': ' '/^Number of entries:/{gsub(/[^0-9]/,"",$2); print $2; exit}')
    [ -z "$c" ] && c=$(ipset list "$1" 2>/dev/null | awk '/^Members:/{m=1;next} m&&NF{c++} END{print c+0}')
    printf '%s' "${c:-0}"
}

# Formate un delta signé : « +15 » si positif, sinon la valeur telle quelle (« -4 », « 0 »).
fmt_signed() { if [ "$1" -gt 0 ] 2>/dev/null; then printf '+%s' "$1"; else printf '%s' "$1"; fi; }

# Sparkline (tendance) d'une série d'entiers séparés par des espaces → ▁▂▃▄▅▆▇█. Pur Bash (aucune
# dépendance awk multi-octets). Vide si < 2 points (rien à tracer) ; série plate → niveau médian.
sparkline() {
    # Largeur FIXE = TREND_SPARK_MAX (graphe COURT : sous-échantillonnage régulier au-delà, padding
    # gauche en deçà => bord droit / récent aligné). < 2 points => colonne de largeur max en espaces.
    # La fusion verticale entre lignes est évitée par un saut de ligne au rendu (pas par un plafond de hauteur).
    local glyphs=(▁ ▂ ▃ ▄ ▅ ▆ ▇ █) out="" v mn mx range lvl n max=${TREND_SPARK_MAX:-8} pad
    set -- $1; n=$#
    if [ "$n" -lt 2 ]; then printf '%*s' "$max" ""; return 0; fi
    [ "$n" -gt "$max" ] && { shift "$(( n - max ))"; n=$max; }   # garde les max DERNIERS points (fenêtre récente)
    mn=$1; mx=$1
    for v in "$@"; do [ "$v" -lt "$mn" ] 2>/dev/null && mn=$v; [ "$v" -gt "$mx" ] 2>/dev/null && mx=$v; done
    range=$((mx - mn))
    for v in "$@"; do
        if [ "$range" -le 0 ]; then lvl=3; else lvl=$(( (v - mn) * 7 / range )); fi
        out="$out${glyphs[$lvl]}"
    done
    pad=$(( max - n )); [ "$pad" -gt 0 ] && printf '%*s' "$pad" ""   # padding gauche => bord droit (récent) aligné
    printf '%s' "$out"
}

# paint <glyphe> <up|down|flat> : colore le glyphe selon OUTPUT_MODE. baisse=vert, hausse=rouge,
# plat=neutre. 'ansi' (terminal) seulement ; 'plain' (résumé/webhook) => glyphe nu, aucun code
# couleur parasite dans le mail. Les codes ANSI ne contiennent aucun % (traversent printf '%s').
paint() {  # colore un glyphe au terminal (ANSI). Mail/chat n'utilisent PAS paint (tableau HTML / prose).
    if [ "$OUTPUT_MODE" = ansi ]; then
        case "$2" in
            up)   printf '\033[31m%s\033[0m' "$1" ;;   # hausse => rouge
            down) printf '\033[32m%s\033[0m' "$1" ;;   # baisse => vert
            *)    printf '%s' "$1" ;;                    # plat => neutre
        esac
    else
        printf '%s' "$1"
    fi
}

# Coloration d'un texte selon la GRAVITÉ d'un signe vital : vert=OK, orange=élevé, rouge=critique.
# sev_ansi : terminal (OUTPUT_MODE=ansi) seulement ; sinon texte nu (résumé/webhook). sev_hex :
# #RRGGBB FIXE, pour le mail HTML ET la carte Google Chat (couleurs identiques clair/sombre — un
# <font color> de carte ne s'adapte pas au thème du client). Les codes ANSI ne contiennent aucun %.
sev_ansi() {  # $1 = ok|warn|crit ; $2 = texte
    if [ "$OUTPUT_MODE" = ansi ]; then
        case "$1" in
            crit) printf '\033[31m%s\033[0m' "$2" ;;   # critique => rouge
            warn) printf '\033[33m%s\033[0m' "$2" ;;   # élevé    => orange
            ok)   printf '\033[32m%s\033[0m' "$2" ;;   # OK       => vert
            *)    printf '%s' "$2" ;;
        esac
    else
        printf '%s' "$2"
    fi
}
sev_hex() {  # $1 = ok|warn|crit => #RRGGBB (mail HTML + carte chat)
    case "$1" in crit) printf '#cc3333' ;; warn) printf '#d97a00' ;; ok) printf '#2e9e44' ;; *) printf '' ;; esac
}
# Gravité de COULEUR de l'intervalle effectif (mode auto) : lâche (>= 40 min) = calme => vert (ok) ;
# serré (<= 10 min) = sous pression => rouge (crit) ; 20 = neutre (aucune couleur). Même sémantique
# que le reste (vert = calme, rouge = activité). Sert à colorer la SEULE valeur de la ligne cadence.
cadence_sev() {  # $1 = intervalle effectif (min)
    [ "${1:-}" -ge 40 ] 2>/dev/null && { printf ok; return; }
    [ "${1:-}" -le 10 ] 2>/dev/null && { printf crit; return; }
    printf ''   # 20 => neutre
}

# fmt_pct <pour-mille signé> : évolution en % à une décimale, virgule française (« -0,8 % », « +12,5 % »).
fmt_pct() {
    local pm=$1 s a
    if   [ "$pm" -gt 0 ] 2>/dev/null; then s="+"
    elif [ "$pm" -lt 0 ] 2>/dev/null; then s="-"
    else s=""; fi
    a=${pm#-}
    printf '%s%d,%d %%' "$s" "$((a/10))" "$((a%10))"
}

# tri_slot <pour-mille signé> <flat_pct> <strong_pct> : slot de tendance de LARGEUR FIXE 2 (pour
# l'alignement en colonnes), en clair (non coloré — le coloriage se fait ensuite via paint+dir_of).
# « ␣␣ » si calme (< flat_pct), « ␣▼/␣▲ » modéré (< strong_pct), « ▼▼/▲▲ » fort (>=). Triangles pleins,
# bien plus visibles qu'une flèche fine (surtout sur mobile).
tri_slot() {
    local pm=$1 a=${1#-}
    [ "$a" -lt "$(( $2 * 10 ))" ] 2>/dev/null && { printf '  '; return; }
    if [ "$pm" -gt 0 ] 2>/dev/null; then
        [ "$a" -lt "$(( $3 * 10 ))" ] 2>/dev/null && printf ' ▲' || printf '▲▲'
    else
        [ "$a" -lt "$(( $3 * 10 ))" ] 2>/dev/null && printf ' ▼' || printf '▼▼'
    fi
}

# dir_of <pour-mille signé> <flat_pct> : direction pour COLORER le nombre — up/down si |évolution| >=
# flat_pct, sinon « flat » (neutre : un petit mouvement n'est pas coloré, pas de contradiction).
dir_of() {
    local pm=$1 a=${1#-}
    [ "$a" -lt "$(( $2 * 10 ))" ] 2>/dev/null && { printf 'flat'; return; }
    [ "$pm" -gt 0 ] 2>/dev/null && printf 'up' || printf 'down'
}

# series_recent_pm <série d'entiers séparés par espaces> : évolution en pour-mille sur les
# TREND_SPARK_MAX DERNIERS points (1er vs dernier de la même fenêtre que la sparkline). Vide si < 2
# points ou base <= 0. Sert au triangle « récent » posé après la sparkline (même fenêtre => cohérent).
series_recent_pm() {
    set -- $1; local n=$# si b l
    [ "$n" -lt 2 ] && return 0
    si=$(( n > TREND_SPARK_MAX ? n - TREND_SPARK_MAX + 1 : 1 ))
    b=${!si}; l=${!n}
    [ "$b" -gt 0 ] 2>/dev/null || return 0
    printf '%s' "$(( (l - b) * 1000 / b ))"
}

# Représentations du bloc ipset POUR LES NOTIFICATIONS (dérivées des tableaux N/C/D/P/M de
# build_ipset_counts — visibles ici par PORTÉE DYNAMIQUE bash, l'appelant est build_ipset_counts).
# La sparkline (jolie au terminal, grossière en mail/chat) est OMISE. PROSE = chat (aucune chasse
# fixe) + partie text/plain du mail ; HTML = tableau stylé pour la partie text/html du mail
# (couleur : baisse=vert, hausse=rouge). Triangle 24 h en clair, pas de slot d'alignement.
ipset_summary_prose() {
    local i tri pr
    IPSET_PROSE=$'\n── '"$(t stats.ipset_header)"' ──'   # \n initial => ligne vide avant le titre (comme les autres sections)
    for ((i=0; i<${#N[@]}; i++)); do
        if [ -n "${M[i]}" ]; then
            tri=$(tri_slot "${M[i]}" "$TREND_FLAT_PCT" "$TREND_STRONG_PCT"); tri="${tri// /}"
            if [ -n "$tri" ]; then pr="${D[i]} (${P[i]}) $tri"
            else pr="${D[i]} (${P[i]}) ● $(t stats.ipset_stable)"; fi   # calme => marqueur stable (nu, sans couleur en prose)
        else pr=$(t stats.ipset_new); fi
        IPSET_PROSE+=$'\n'"• ${N[i]} : ${C[i]}  ·  $pr"
    done
    if [ -n "$base_epoch" ]; then local sp=$((now - base_epoch)); [ "$sp" -lt "$WINDOW_NOTE_SECS" ] 2>/dev/null && IPSET_PROSE+=$'\n'"  $(t stats.avg24_window "$(metrics_fmt_span "$sp")")"; fi
}
ipset_summary_html() {
    local i tri col vr nm rows="" hc hv
    hc=$(t stats.ipset_hdr_count); hv=$(t stats.ipset_hdr_var)
    for ((i=0; i<${#N[@]}; i++)); do
        if [ -n "${M[i]}" ]; then
            case "$(dir_of "${M[i]}" "$TREND_FLAT_PCT")" in
                up)   col="color:#cc3333" ;;   # hausse => rouge
                down) col="color:#2e9e44" ;;   # baisse => vert
                *)    col="" ;;                 # calme => neutre (marqueur ● stable)
            esac
            tri=$(tri_slot "${M[i]}" "$TREND_FLAT_PCT" "$TREND_STRONG_PCT"); tri="${tri// /}"
            if [ -n "$tri" ]; then vr="${D[i]} (${P[i]}) $tri"
            else vr="${D[i]} (${P[i]}) ● $(t stats.ipset_stable)"; fi
        else col=""; vr=$(t stats.ipset_new); fi
        nm=$(html_escape "${N[i]}")
        rows+="<tr><td style=\"padding:3px 12px;border-bottom:1px solid #eee\">$nm</td><td style=\"padding:3px 12px;text-align:right;border-bottom:1px solid #eee\">${C[i]}</td><td style=\"padding:3px 12px;text-align:right;border-bottom:1px solid #eee;$col\">$(html_escape "$vr")</td></tr>"
    done
    IPSET_HTML="<div style=\"margin:12px 0 4px;font-weight:bold\">$(html_escape "$(t stats.ipset_header)")</div>"
    IPSET_HTML+="<table style=\"border-collapse:collapse;font-family:sans-serif;font-size:13px;color:#1a1a1a\">"
    IPSET_HTML+="<tr><th style=\"text-align:left;padding:3px 12px;border-bottom:2px solid #ccc\"></th>"
    IPSET_HTML+="<th style=\"text-align:right;padding:3px 12px;border-bottom:2px solid #ccc\">$(html_escape "$hc")</th>"
    IPSET_HTML+="<th style=\"text-align:right;padding:3px 12px;border-bottom:2px solid #ccc\">$(html_escape "$hv")</th></tr>$rows</table>"
    if [ -n "$base_epoch" ]; then local sp=$((now - base_epoch)); [ "$sp" -lt "$WINDOW_NOTE_SECS" ] 2>/dev/null && IPSET_HTML+="<div style=\"font-size:12px;color:#888;margin-top:3px\">$(html_escape "$(t stats.avg24_window "$(metrics_fmt_span "$sp")")")</div>"; fi
}

# Représentations du bloc « Signes vitaux » POUR LES NOTIFICATIONS (dérivées de HEALTH_LINES +
# HEALTH_SEV). PLAIN = neutre (chat + partie text/plain du mail) ; HTML = lignes colorées par
# gravité (vert=OK, orange=élevé, rouge=critique) pour la partie text/html du mail. Même mécanique
# de jeton que le bloc ipset (voir build_stats_text / do_summary).
vitals_prose() {
    local i
    VITALS_PLAIN=$'\n── '"$(t stats.health_vitals)"' ──'   # \n initial => ligne vide avant le titre
    for ((i=0; i<${#HEALTH_LINES[@]}; i++)); do VITALS_PLAIN+=$'\n'"${HEALTH_LINES[i]}"; done
}
vitals_html() {
    local i col rows=""
    for ((i=0; i<${#HEALTH_LINES[@]}; i++)); do
        col=$(sev_hex "${HEALTH_SEV[i]:-ok}")
        rows+="<div><span style=\"color:$col\">●</span> $(html_escape "${HEALTH_LINES[i]}")</div>"
    done
    VITALS_HTML="<div style=\"margin:12px 0 4px;font-weight:bold\">$(html_escape "$(t stats.health_vitals)")</div>$rows"
}
# Variantes CARTE Google Chat (sous-ensemble <b>/<br>/<font>) : couleurs HEX FIXES via sev_hex/dir.
vitals_card() {
    local i col
    VITALS_CARD="<br><b>$(html_escape "$(t stats.health_vitals)")</b>"
    for ((i=0; i<${#HEALTH_LINES[@]}; i++)); do
        col=$(sev_hex "${HEALTH_SEV[i]:-ok}")
        VITALS_CARD+="<br><font color=\"$col\">●</font> $(html_escape "${HEALTH_LINES[i]}")"   # résultat seul en couleur : ● coloré, texte neutre
    done
}
ipset_card() {  # utilise N/C/D/P/M/base_epoch/now par portée dynamique (appel depuis build_ipset_counts)
    local i tri col vr
    IPSET_CARD="<br><b>$(html_escape "$(t stats.ipset_header)")</b>"
    for ((i=0; i<${#N[@]}; i++)); do
        if [ -n "${M[i]}" ]; then
            case "$(dir_of "${M[i]}" "$TREND_FLAT_PCT")" in
                up)   col="#cc3333" ;;   # hausse => rouge
                down) col="#2e9e44" ;;   # baisse => vert
                *)    col="" ;;          # calme => neutre (marqueur ● stable)
            esac
            tri=$(tri_slot "${M[i]}" "$TREND_FLAT_PCT" "$TREND_STRONG_PCT"); tri="${tri// /}"
            if [ -n "$tri" ]; then vr="${D[i]} (${P[i]}) $tri"
            else vr="${D[i]} (${P[i]}) ● $(t stats.ipset_stable)"; fi
            vr="${col:+<font color=\"$col\">}$(html_escape "$vr")${col:+</font>}"
        else vr=$(html_escape "$(t stats.ipset_new)"); fi
        IPSET_CARD+="<br>• $(html_escape "${N[i]} : ${C[i]}  ·  ")$vr"
    done
    if [ -n "$base_epoch" ]; then local sp=$((now - base_epoch)); [ "$sp" -lt "$WINDOW_NOTE_SECS" ] 2>/dev/null && IPSET_CARD+="<br>  $(html_escape "$(t stats.avg24_window "$(metrics_fmt_span "$sp")")")"; fi
}

# Sous-bloc « Comptage ipset (évol. + tendance 24 h) » : pour CHAQUE ipset de la machine + un total,
# le nb d'entrées COURANT (mesuré live), son évolution sur 24 h (+X/-Y) et une sparkline de tendance.
# Historique horaire dans IPSET_COUNTS_FILE (posé par ipset_counts_sample, comme les métriques). La
# base 24 h = plus ancien échantillon dans la fenêtre now-86400 (fichier chronologique → 1er epoch
# >= cut, partagé par toutes les listes). Set neuf (absent de la base) => marqueur « nouveau », pas
# de delta trompeur ; total en clair seulement si toutes les listes ont une base. Vide (non-root /
# aucune ipset) => bloc absent. Le set transitoire ${IPSET_NAME}_grow (redimensionnement) est écarté.
build_ipset_counts() {
    local sets now cut base_epoch name cur base series pm i wN=0 wC=0 wD=0 wP=0 wV vplain vpad numf trec dir span hc hv he
    local tot_cur=0 tot_base=0 have_all_base=1
    local -a N=() C=() D=() P=() M=() R=() S=()   # colonnes : nom, compte, delta, %, pm 24h, pm récent, sparkline
    sets=$(fw_list_sets)
    [ -z "$sets" ] && return 0
    now=$(date +%s); cut=$((now - 86400)); base_epoch=""
    [ -r "$IPSET_COUNTS_FILE" ] && base_epoch=$(awk -v cut="$cut" '$1 ~ /^[0-9]+$/ && ($1+0)>=cut {print $1; exit}' "$IPSET_COUNTS_FILE" 2>/dev/null)
    # ---- Passe 1 : valeurs par set (+ accumulation du total). La « série » = échantillons 24 h + live ;
    #      elle sert À LA FOIS à la sparkline (qui garde ses TREND_SPARK_MAX derniers points) et au
    #      triangle récent (series_recent_pm sur la même fenêtre => cohérent). ----
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        cur=$(fw_count "$name"); tot_cur=$((tot_cur + cur))
        base=""; [ -n "$base_epoch" ] && base=$(awk -v e="$base_epoch" -v s="$name" '$1==e && $2==s {print $3; exit}' "$IPSET_COUNTS_FILE" 2>/dev/null)
        series=""; [ -r "$IPSET_COUNTS_FILE" ] && series=$(awk -v cut="$cut" -v s="$name" '$1 ~ /^[0-9]+$/ && ($1+0)>=cut && $2==s {printf "%s ", $3}' "$IPSET_COUNTS_FILE" 2>/dev/null)
        series="$series$cur"
        N+=("$name"); C+=("$cur"); S+=("$(sparkline "$series")"); R+=("$(series_recent_pm "$series")")
        if [ -n "$base" ] && [ "$base" -gt 0 ] 2>/dev/null; then
            tot_base=$((tot_base + base)); pm=$(( (cur - base) * 1000 / base ))
            D+=("$(fmt_signed $((cur - base)))"); P+=("$(fmt_pct "$pm")"); M+=("$pm")
        else D+=("$(t stats.ipset_new)"); P+=(""); M+=(""); have_all_base=0; fi
    done <<< "$sets"
    # ---- Ligne Total (dernier élément des colonnes) ----
    series=""; [ -r "$IPSET_COUNTS_FILE" ] && series=$(awk -v cut="$cut" '$1 ~ /^[0-9]+$/ && ($1+0)>=cut { if ($1 != e) { if (e!="") printf "%s ", s; e=$1; s=0 } s+=$3 } END { if (e!="") printf "%s ", s }' "$IPSET_COUNTS_FILE" 2>/dev/null)
    series="$series$tot_cur"
    N+=("$(t stats.ipset_total_label)"); C+=("$tot_cur"); S+=("$(sparkline "$series")"); R+=("$(series_recent_pm "$series")")
    if [ "$have_all_base" -eq 1 ] && [ -n "$base_epoch" ] && [ "$tot_base" -gt 0 ]; then
        pm=$(( (tot_cur - tot_base) * 1000 / tot_base ))
        D+=("$(fmt_signed $((tot_cur - tot_base)))"); P+=("$(fmt_pct "$pm")"); M+=("$pm")
    else D+=("$(t stats.ipset_new)"); P+=(""); M+=(""); fi
    # ---- Mode NOTIFICATION : on ne rend pas le tableau texte ; on produit prose + HTML (via les
    #      tableaux ci-dessus) et on n'imprime qu'un JETON, remplacé par do_summary selon le canal. ----
    if [ "${SUMMARY_NOTIFY:-}" = 1 ]; then
        ipset_summary_prose; ipset_summary_html; ipset_card
        printf '\001IPSETBLOCK\002\n'
        return 0
    fi
    # ---- Largeurs de colonnes (nom/compte/delta/% = ASCII => ${#} fiable) ----
    for ((i=0; i<${#N[@]}; i++)); do
        [ "${#N[i]}" -gt "$wN" ] && wN=${#N[i]}; [ "${#C[i]}" -gt "$wC" ] && wC=${#C[i]}
        [ "${#D[i]}" -gt "$wD" ] && wD=${#D[i]}; [ "${#P[i]}" -gt "$wP" ] && wP=${#P[i]}
    done
    hc=$(t stats.ipset_hdr_count); hv=$(t stats.ipset_hdr_var); he=$(t stats.ipset_hdr_evo)
    [ "${#hc}" -gt "$wC" ] && wC=${#hc}                 # la colonne compte doit contenir son en-tête
    wV=$(( wD + wP + 6 ))                               # largeur visuelle de « delta (%) tri24 » (delta ␣( pct )␣pad␣ tri)
    [ "${#hv}" -gt "$wV" ] && wV=${#hv}
    # ---- Rendu : en-tête de colonnes, puis une ligne par liste avec une LIGNE VIDE entre chaque
    #      graphe (évite la fusion verticale des sparklines). Triangle 24 h COLLÉ à la variation. ----
    printf '\n── %s ──\n' "$(t stats.ipset_header)"
    printf '  %-*s  %*s   %-*s  %s\n' "$wN" "" "$wC" "$hc" "$wV" "$hv" "$he"
    for ((i=0; i<${#N[@]}; i++)); do
        [ "$i" -gt 0 ] && printf '\n'
        if [ -n "${M[i]}" ]; then                       # variation 24 h : « delta (%) tri24 » colorée, paddée à wV
            dir=$(dir_of "${M[i]}" "$TREND_FLAT_PCT")
            if [ "$dir" = flat ]; then                  # calme => marqueur stable ● NEUTRE (rouge=hausse / neutre=stable / vert=baisse)
                numf="$(printf '%*s (%*s) ' "$wD" "${D[i]}" "$wP" "${P[i]}")●"
                vpad=$(( wV - (wD + wP + 5) )); [ "$vpad" -gt 0 ] && numf="$numf$(printf '%*s' "$vpad" "")"
            else
                vplain="$(printf '%*s (%*s) ' "$wD" "${D[i]}" "$wP" "${P[i]}")$(tri_slot "${M[i]}" "$TREND_FLAT_PCT" "$TREND_STRONG_PCT")"   # delta + (% aligné à droite) + tri24
                numf=$(paint "$vplain" "$dir")
                vpad=$(( wV - (wD + wP + 6) )); [ "$vpad" -gt 0 ] && numf="$numf$(printf '%*s' "$vpad" "")"
            fi
        else numf=$(printf '%-*s' "$wV" "${D[i]}"); fi   # « nouveau », neutre
        if [ -n "${R[i]}" ]; then trec=$(paint "$(tri_slot "${R[i]}" "$TREND_RECENT_FLAT_PCT" "$TREND_RECENT_STRONG_PCT")" "$(dir_of "${R[i]}" "$TREND_RECENT_FLAT_PCT")"); else trec='  '; fi
        printf '  %-*s  %*s   %s  %s %s\n' "$wN" "${N[i]}" "$wC" "${C[i]}" "$numf" "${S[i]}" "$trec"
    done
    # Note de fenêtre réelle si l'historique couvre < WINDOW_NOTE_SECS (pas de fausse impression de 24 h pleines).
    if [ -n "$base_epoch" ]; then
        span=$((now - base_epoch))
        [ "$span" -lt "$WINDOW_NOTE_SECS" ] 2>/dev/null && printf '   %s\n' "$(t stats.avg24_window "$(metrics_fmt_span "$span")")"
    fi
    return 0
}
# --- Flux de lecture du journal pour les compteurs 24 h -------------------------------------
# logrotate ouvre un fichier NEUF : le matin d'une rotation, $LOG_FILE ne couvre plus que les heures
# écoulées depuis minuit, et tout ce qui compte sur 24 h (Nouveaux bans, Débans, les deux Top) est
# amputé d'autant — SANS le dire. Le bloc « Comptage ipset », lui, lit IPSET_COUNTS_FILE que
# logrotate ne touche pas : la contradiction saute alors aux yeux dans le résumé (incident du
# 26 juil. 2026 : « Nouveaux bans : 52 » pour 1327 bans réels, face à un delta ipset de +1251).
# On préfixe donc le flux avec le rotaté le plus récent (.1, ou .1.gz si compress) DÈS QUE la
# première ligne du log courant est postérieure au début de la fenêtre. Ordre chronologique
# conservé (rotaté puis courant) ; le filtre de date de l'appelant fait le reste. Sans objet quand
# aucune rotation n'a coupé la fenêtre : on lit alors le seul log courant, comme avant.
stats_log_cat() {  # $1 = journal (rotaté ou non) => contenu sur stdout, décompressé au besoin
    case "$1" in
        *.gz) zcat -- "$1" 2>/dev/null ;;    # compress (notre conf logrotate)
        *)    cat  -- "$1" 2>/dev/null ;;    # delaycompress / conf personnalisée
    esac
}
stats_log_rotated() {  # journaux rotatés du PLUS RÉCENT au plus ancien, quel que soit le nommage
    local i f
    for ((i = 1; i <= 5; i++)); do          # suffixe numérique (défaut logrotate) : .1, .1.gz, .2…
        for f in "${LOG_FILE}.$i" "${LOG_FILE}.$i.gz"; do [ -r "$f" ] && { printf '%s\n' "$f"; break; }; done
    done
    # dateext (« ban_404.log-20260725[.gz] », actif par défaut sur certaines distros) : la date est
    # dans le nom, donc un tri décroissant donne bien du plus récent au plus ancien.
    ls -1 "${LOG_FILE}"-* 2>/dev/null | sort -r
}
stats_log_stream() {   # $1 = début de fenêtre « AAAA-MM-JJ HH:MM:SS »
    local first rot f older=()
    [ -r "$LOG_FILE" ] || return 0
    first=$(head -n 1 "$LOG_FILE" 2>/dev/null | cut -c1-19)
    # Log courant VIDE : il ne couvre RIEN. Cas tout sauf théorique — la rotation tombe à minuit
    # (timer systemd) et le résumé part à 06:25 : un serveur sans le moindre événement dans cette
    # tranche aurait, sinon, affiché des compteurs à zéro en ignorant le rotaté qui porte la journée
    # entière. On force donc la remontée en partant de « maintenant ». Idem pour un rotaté vide :
    # on continue de remonter (la liste des candidats est bornée, donc la boucle termine).
    [ -n "$first" ] || first=$(date '+%Y-%m-%d %H:%M:%S')
    if [ -n "$1" ]; then
        # Tant que le plus ancien fichier retenu DÉBUTE après le début de la fenêtre, il manque des
        # lignes : on remonte d'un rotaté. S'arrête dès la couverture atteinte (cas courant : un seul
        # rotaté, souvent aucun) ; borné par stats_log_rotated (5 index + dateext).
        while [[ "$first" > "$1" ]]; do
            rot=$(stats_log_rotated | awk -v n="${#older[@]}" 'NR == n+1 { print; exit }')
            [ -n "$rot" ] || break
            older=("$rot" "${older[@]}")     # plus ancien en tête => ordre chronologique à l'émission
            f=$(stats_log_cat "$rot" | head -n 1 | cut -c1-19)
            [ -n "$f" ] && first="$f"        # rotaté vide => borne inchangée, on remonte d'un cran de plus
        done
    fi
    for rot in "${older[@]}"; do stats_log_cat "$rot"; done
    cat -- "$LOG_FILE" 2>/dev/null
}
# --- Bloc « Récidivistes » ---------------------------------------------------------------------
# Top 10 des IP par nombre de bans mémorisés, lu DIRECTEMENT dans OFFENDERS_FILE : contrairement
# aux Top 24 h (qui relisent le journal), ce bloc est insensible à la rotation de logrotate et
# couvre toute la période d'épreuve, pas 24 h. Design d'alerte comme le bloc ipset : le bloc est
# ABSENT tant qu'aucune IP n'a au moins 2 bans — muet au calme, visible dès qu'un habitué s'installe.
# PTR : contrairement aux Top 24 h et à --list (opt-in RESOLVE_PTR/--resolve, car --list peut porter
# des milliers d'IP), le RÉSUMÉ force ici la résolution (drapeau RECID_PTR posé par do_summary) : le
# bloc est plafonné à 10 IP et chaque lookup est borné par PTR_TIMEOUT, donc le coût reste borné —
# et savoir QUI est l'habitué (hébergeur, exit Tor, plage cloud) est le premier réflexe de lecture.
# TRI : nb de bans décroissant, puis FIN DU DERNIER BAN décroissante (le plus récemment actif
# d'abord), puis l'IP en dernier recours. Départager par l'IP -- ce que faisait la 2.3.0 -- rendait
# le bloc inerte dès qu'une majorité d'habitués partage le même nombre de bans : sur un serveur à
# 126 récidivistes dont 125 à 2 bans, les 10 places allaient aux IP numériquement les plus BASSES,
# toujours les mêmes, pendant que les scanners actifs du jour restaient invisibles.
build_recidivists() {
    [ -r "$OFFENDERS_FILE" ] || return 0
    local rows n ip exp rdns endts
    rows=$(awk -v cut="$(date +%s)" -v mem="${ESCALATION_MEMORY:-0}" '
        NF>=3 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $2+0 >= 2 && $3+mem >= cut { print $2+0, $1, $3 }
    ' "$OFFENDERS_FILE" 2>/dev/null | sort -k1,1nr -k3,3nr -k2,2V | head -n 10)
    [ -n "$rows" ] || return 0
    printf '\n── %s ──\n' "$(t stats.recidivists_header "$(fmt_duration "${ESCALATION_MEMORY:-0}")")"
    while read -r n ip exp; do
        [ -z "$ip" ] && continue
        endts=$(date -d "@$exp" '+%Y-%m-%d %H:%M' 2>/dev/null) || endts="$exp"
        rdns=""; if resolve_ptr_on || [ "$RECID_PTR" = true ]; then rdns=$(reverse_dns "$ip"); fi
        [ -n "$rdns" ] && t stats.recidivist_item_rdns "$ip" "$n" "$endts" "$rdns" \
                       || t stats.recidivist_item      "$ip" "$n" "$endts"
    done <<< "$rows"
    return 0
}

build_stats_text() {
    local bans unbans evt cutoff24 cnt ip rdns updater upd_ver issue div kind sc top_raw top404 tophp
    # Couleur ANSI des triangles seulement au terminal ([ -t 1 ]) ; sinon 'plain'. Le résumé notifié
    # ne colore pas via le terminal : le mail a son propre HTML coloré, le chat sort en prose neutre.
    if [ -t 1 ]; then OUTPUT_MODE=ansi; else OUTPUT_MODE=plain; fi
    printf -v div '─%.0s' {1..30}        # filet sous le titre (largeur fixe)
    cutoff24=$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    bans=0; unbans=0
    if [ -r "$LOG_FILE" ] && [ -n "$cutoff24" ]; then
        # Un SEUL passage pour TOUS les compteurs (le flux peut inclure un rotaté compressé).
        # On compte aussi les bans du circuit honeypot dont le score vaut EXACTEMENT
        # HONEYPOT_SCORE : le score étant cumulatif (+100 par chemin-piège ou signature, +1 par
        # 404 ordinaire), le plancher signifie « UNE seule requête signalée, et rien d'autre ».
        # Une part écrasante de bans au plancher = la détection tire sur un signal isolé, ce qui
        # n'empêche rien quand l'IP ne revient jamais (cf. stats.floor_bans plus bas). Le score est
        # relu comme dans les Top 24 h : PREMIER nombre après l'IP, robuste aux 5 langues.
        evt=$(stats_log_stream "$cutoff24" | awk -v c="$cutoff24" -v floor="${HONEYPOT_SCORE:-100}" '
            ($1" "$2) >= c {
                if (/\[\+\]/) {
                    b++
                    if ($0 ~ /[Hh]oneypot/) {
                        ipi=0
                        for (i=3; i<=NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { ipi=i; break }
                        if (ipi) for (i=ipi+1; i<=NF; i++) if ($i ~ /[0-9]/) {
                            s=$i; gsub(/[^0-9]/, "", s)
                            if (s != "") { if (s+0 == floor+0) fl++; break }
                        }
                    }
                } else if (/\[-\]/) u++
            }
            END { printf "%d %d %d\n", b+0, u+0, fl+0 }')
        read -r bans unbans floor_bans <<< "$evt"
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
    # Cadence CRON_STEP : statut visible dans le rapport ET le résumé quotidien (sinon, au vert,
    # seul diag la montrait). L'ÉVOLUTION, elle, vit au journal (cadence.adjusted via t_log).
    case "$(cron_step_mode)" in
        auto)
            # « Bulle » de statut : un ● coloré préfixe la ligne (comme les signes vitaux) ; la valeur
            # reste neutre. Couleur = lâche (>=40)=vert / 20=neutre / serré (<=10)=rouge. En notif, le ●
            # est un placeholder \001CVAL\002 (survit à html_escape/card_text), coloré par do_summary
            # selon le canal via CADENCE_HEX ; au terminal, ● coloré inline (sev_ansi).
            local _cds; CADENCE_VAL=$(cadence_read); _cds=$(cadence_sev "$CADENCE_VAL"); CADENCE_HEX=$(sev_hex "$_cds")
            if [ "${SUMMARY_NOTIFY:-}" = 1 ]; then
                printf '%s %s\n' $'\001CVAL\002' "$(t stats.cadence_auto "$CADENCE_VAL")"
            else
                printf '%s %s\n' "$(sev_ansi "$_cds" '●')" "$(t stats.cadence_auto "$CADENCE_VAL")"
            fi ;;
        fixed) t stats.cadence_fixed "$CRON_STEP" ;;
    esac
    # --- Santé : uniquement les WARN/FAIL des contrôles de diagnostic (réseau inclus) ---
    DIAG_QUIET=true; DIAG_PROBLEMS=0; DIAG_ISSUES=()
    run_diag_checks            # remplit DIAG_ISSUES sans rien imprimer
    DIAG_QUIET=false
    if [ "${#DIAG_ISSUES[@]}" -eq 0 ]; then
        t stats.health_ok                       # ligne inline « Santé : aucune anomalie détectée. »
    else
        t stats.health_header                   # « Santé (anomalies) : »
        for issue in "${DIAG_ISSUES[@]}"; do   # déjà préfixé [WARN]/[FAIL] + localisé ; colorées au terminal (alertes)
            case "$issue" in
                "[FAIL]"*) printf '  %s\n' "$(sev_ansi crit "$issue")" ;;
                "[WARN]"*) printf '  %s\n' "$(sev_ansi warn "$issue")" ;;
                *)         printf '  %s\n' "$issue" ;;
            esac
        done
    fi
    # --- Signes vitaux : TOUJOURS affichés (valeurs mesurées par run_diag_checks ci-dessus via
    # run_health_checks ; aucune re-mesure — l'échantillon réseau 1 s n'a tourné qu'une fois).
    # Vide (--no-health / HEALTH_CHECKS=false) => le bloc disparaît proprement. ---
    if [ "${#HEALTH_LINES[@]}" -gt 0 ]; then
        if [ "${SUMMARY_NOTIFY:-}" = 1 ]; then
            # Notification : jeton remplacé par do_summary selon le canal (VITALS_PLAIN neutre pour
            # text/plain, VITALS_HTML coloré pour le mail HTML, VITALS_CARD coloré pour la carte chat).
            vitals_prose; vitals_html; vitals_card
            printf '\001VITALSBLOCK\002\n'
        else
            printf '\n── %s ──\n' "$(t stats.health_vitals)"
            # Résultat SEUL en couleur : un ● coloré par gravité (vert=OK / orange=élevé / rouge=critique),
            # le texte reste neutre — colorer toute la ligne nuisait à la lisibilité. sev_ansi ne colore
            # qu'en OUTPUT_MODE=ansi (terminal) ; en 'plain' le ● sort nu.
            local _hi
            for ((_hi = 0; _hi < ${#HEALTH_LINES[@]}; _hi++)); do
                printf '%s %s\n' "$(sev_ansi "${HEALTH_SEV[_hi]:-ok}" '●')" "${HEALTH_LINES[_hi]}"
            done
        fi
    fi
    # --- Moyennes 24 h (opt-in --avg ; forcé dans le résumé via do_summary) : reflète l'activité
    # RÉELLE des dernières 24 h, là où les signes vitaux ci-dessus ne montrent que l'instant. ---
    [ "$SHOW_AVG24" = true ] && build_metrics_averages
    # --- Comptage ipset (évol. + tendance 24 h) : toutes les listes + total, TOUJOURS affiché ---
    build_ipset_counts
    # --- Statistiques (24h) --- (« Actuellement bannies » retiré : doublon du bloc ipset ci-dessus.
    # « Nouveaux bans » = bans BRUTS loggés (≠ delta NET du bloc ipset). Débans (retraits whitelist/
    # manuels loggés [-] ; les expirations par timeout ne le sont pas) : masqué quand 0 pour ne pas
    # afficher une ligne toujours nulle. ---
    printf '\n── %s ──\n' "$(t stats.sec_stats)"
    if [ "$unbans" -gt 0 ] 2>/dev/null; then t stats.bans_unbans "$bans" "$unbans"; else t stats.bans_only "$bans"; fi
    # Bans au score PLANCHER : muet tant que ce n'est pas massif — design d'alerte, comme les
    # Récidivistes ou les Débans. Seuils volontairement hauts (>= 20 bans ET >= 50 %) : un serveur
    # sain qui bannit trois scanners dans la journée n'a rien à signaler. Mesuré sur le parc le
    # 13 sept. 2026 : 100 % sur le serveur où la détection tirait à vide, 0 % sur l'autre.
    if [ "${floor_bans:-0}" -ge 20 ] 2>/dev/null && [ "${bans:-0}" -gt 0 ] 2>/dev/null; then
        local floor_pct=$(( 100 * floor_bans / bans ))
        [ "$floor_pct" -ge 50 ] && t stats.floor_bans "$floor_bans" "$bans" "$floor_pct"
    fi
    # --- Top 404 (24h) PUIS Top honeypot (24h) : deux classements distincts ; débans exclus ---
    if [ -r "$LOG_FILE" ] && [ -n "$cutoff24" ]; then
        # awk émet « kind score ip » : kind r = ban classique (score = nb de 404) ; kind h = honeypot
        # (score pondéré = 100/hit-honeypot + 1/autre-404 ; 0 sur les vieilles lignes sans score). Le
        # nombre est relu entre parenthèses après l'IP (« (48 … » ou « (score 250) »), robuste aux 5
        # langues ; honeypot reconnu par le mot « honeypot » (présent tel quel dans les 5 langues).
        top_raw=$(stats_log_stream "$cutoff24" | awk -v c="$cutoff24" '
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
        ')
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
    # --- Récidivistes (fenêtre d'épreuve, source = fichier d'état) : muet s'il n'y en a aucun ---
    build_recidivists
}
do_list() {
    local members ip rest to_raw to fam key ipkey
    members=$(fw_list_members_raw)
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
    local host tmp body body_plain body_html body_card subj vtok itok seg; host=$(server_label)
    # Résumé DESTINÉ À L'ENVOI : on neutralise --verbose afin que le détail par dossier
    # (lignes verbose de run_diag_checks, rejoué par build_stats_text) ne soit PAS injecté dans
    # le corps notifié. L'affichage direct de --stats (sans cette neutralisation) le conserve.
    VERBOSE=false
    # Moyennes 24 h affichées PAR DÉFAUT dans le résumé (sauf santé désactivée : cohérent avec le
    # bloc « Signes vitaux »). En interactif, stats/diag exigent --avg ; ici on force le flag.
    diag_is_on "${HEALTH_CHECKS:-true}" && SHOW_AVG24=true
    # Récidivistes : PTR forcé (bloc borné à 10 IP, lookups bornés par PTR_TIMEOUT) — identifier
    # l'habitué vaut son coût sur un envoi quotidien. Les Top 24 h restent en opt-in RESOLVE_PTR.
    RECID_PTR=true
    # On construit le corps via REDIRECTION fichier (pas $(...)) : build_stats_text tourne alors dans
    # le shell COURANT et laisse DIAG_PROBLEMS/DIAG_ISSUES renseignés (une command substitution les
    # perdrait dans son sous-shell). On peut ainsi FLAGGER le sujet — mail ET webhook, ce dernier
    # recevant « sujet\ncorps » (cf. notify) — quand le résumé contient au moins un [WARN]/[FAIL].
    DIAG_PROBLEMS=0
    SUMMARY_NOTIFY=1; IPSET_PROSE=""; IPSET_HTML=""; IPSET_CARD=""; VITALS_PLAIN=""; VITALS_HTML=""; VITALS_CARD=""; CADENCE_VAL=""; CADENCE_HEX=""  # build_stats_text => jetons + variantes
    tmp=$(mktemp 2>/dev/null) || tmp=""
    if [ -n "$tmp" ]; then
        build_stats_text > "$tmp"; body=$(cat "$tmp"); rm -f "$tmp"
    else
        body=$(build_stats_text)          # repli : sous-shell => sujet non flaggé ET variantes PROSE/HTML perdues (dégradation propre)
    fi
    SUMMARY_NOTIFY=
    vtok=$'\001VITALSBLOCK\002'; itok=$'\001IPSETBLOCK\002'
    # text/plain (+ chat) : chaque jeton => sa variante PROSE (vide si non produite => jeton retiré proprement).
    body_plain="${body//$vtok/$VITALS_PLAIN}"; body_plain="${body_plain//$itok/$IPSET_PROSE}"
    # text/html : on découpe le corps autour des jetons (ordre d'apparition VITALS puis IPSET) et on
    # intercale les blocs HTML colorés ; les segments de texte passent par html_text (proportionnel).
    seg="$body"
    body_html="<!DOCTYPE html><html><body style=\"font-family:sans-serif;font-size:13px;color:#1a1a1a;margin:8px\">"
    if [ -n "$VITALS_HTML" ] && [[ "$seg" == *"$vtok"* ]]; then
        body_html+="<div>$(html_text "${seg%%"$vtok"*}")</div>$VITALS_HTML"; seg="${seg#*"$vtok"}"
    fi
    if [ -n "$IPSET_HTML" ] && [[ "$seg" == *"$itok"* ]]; then
        body_html+="<div>$(html_text "${seg%%"$itok"*}")</div>$IPSET_HTML"; seg="${seg#*"$itok"}"
    fi
    seg="${seg//$vtok/}"; seg="${seg//$itok/}"                    # filet : purge tout jeton résiduel (repli sous-shell) avant html_text
    body_html+="<div>$(html_text "$seg")</div></body></html>"
    # Carte Google Chat : même découpe autour des jetons, blocs colorés <font> intercalés, reste via
    # card_text (sous-ensemble <b>/<br>). Construit inconditionnellement (léger) ; build_webhook_payload
    # ne l'utilise que pour Google Chat + WEBHOOK_CHAT_CARD actif.
    seg="$body"; body_card=""
    if [ -n "$VITALS_CARD" ] && [[ "$seg" == *"$vtok"* ]]; then
        body_card+="$(card_text "${seg%%"$vtok"*}")$VITALS_CARD"; seg="${seg#*"$vtok"}"
    fi
    if [ -n "$IPSET_CARD" ] && [[ "$seg" == *"$itok"* ]]; then
        body_card+="$(card_text "${seg%%"$itok"*}")$IPSET_CARD"; seg="${seg#*"$itok"}"
    fi
    seg="${seg//$vtok/}"; seg="${seg//$itok/}"
    body_card+="$(card_text "$seg")"
    # Bulle ● de la cadence : le placeholder \001CVAL\002 (posé par build_stats_text en mode auto)
    # survit à html_escape/card_text ; on le remplace ici par un ● coloré selon le canal (neutre => ● nu).
    local cval=$'\001CVAL\002'
    body_plain="${body_plain//$cval/●}"
    body_html="${body_html//$cval/${CADENCE_HEX:+<span style=\"color:$CADENCE_HEX\">}●${CADENCE_HEX:+</span>}}"
    body_card="${body_card//$cval/${CADENCE_HEX:+<font color=\"$CADENCE_HEX\">}●${CADENCE_HEX:+</font>}}"
    if [ "${DIAG_PROBLEMS:-0}" -gt 0 ]; then
        subj=$(t summary.subject_warn "$host" "$DIAG_PROBLEMS")
    else
        subj=$(t summary.subject "$host")
    fi
    notify "$subj" "$body_plain" "$body_html" "$body_card"   # chat = carte colorée si activée, sinon prose ; mail = multipart texte + tableau HTML
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
    local cbody; cbody=$(t check.body "$host")   # passe aussi le corps en CARTE : le test live montre la carte quand WEBHOOK_CHAT_CARD est actif
    code=$(curl -sS -m 15 -o "${tmp:-/dev/null}" -w '%{http_code}' -H 'Content-Type: application/json; charset=UTF-8' \
                -X POST -d "$(build_webhook_payload "$cbody" "$cbody" "$host")" "$WEBHOOK_URL" 2>/dev/null); rc=$?
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
          printf 'Subject: %s\n\n%s\n' "$(encode_header "$subj")" "$body"; } | sendmail -t 2>"${tmp:-/dev/null}"; rc=$?
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

# ---------- Cadence adaptative (CRON_STEP) ----------
# CRON_STEP="" (défaut) : passage horaire seul. Entier 5-30 : le cron.d géré (self_heal_step_cron)
# lance le moteur toutes les N minutes, chaque tick analyse. "auto" : le cron.d tourne toutes les
# 5 min (plancher) mais le moteur module lui-même l'intervalle EFFECTIF sur l'échelle
# 5→10→20→40→60 min : la « porte » (posée juste après le verrou) saute les ticks arrivés trop tôt,
# et une sentinelle légère peut forcer un run complet en ≤ 5 min sur signes d'attaque. Hystérésis :
# détections => un cran plus serré (signature/honeypot => plancher direct) ; run calme => un cran
# plus lâche. Plafond 60 min : la fenêtre WINDOW (2 h) impose un recouvrement, et le cron.hourly
# (porteur des self-heals) tourne de toute façon.

cron_step_mode() {   # -> off | fixed | auto (toute valeur invalide => off, sans casser le run)
    case "${CRON_STEP:-}" in
        auto) echo auto ;;
        *)
            if [[ "${CRON_STEP:-}" =~ ^[0-9]+$ ]] && [ "$CRON_STEP" -ge 5 ] && [ "$CRON_STEP" -le 30 ]; then
                echo fixed
            else
                echo off
            fi ;;
    esac
}

# Intervalle effectif courant du mode auto (minutes) : 1er champ du fichier d'état (le 2e,
# epoch du dernier ban, ne sert qu'à cadence_adjust). Fichier absent/corrompu => plafond (60) :
# un serveur calme ne paie jamais un excès de zèle par défaut.
cadence_read() {
    local v
    v=$(head -n 1 "$CADENCE_FILE" 2>/dev/null)
    v=${v%% *}
    case "$v" in 5|10|20|40|60) printf '%s' "$v" ;; *) printf '%s' 60 ;; esac
}

# Ajustement d'hystérésis, appelé en fin de run COMPLET (finish_run, donc jamais en dry-run) :
# $1 = nb de bans « RÉELS » du run = floods volume-404 (hp=0) UNIQUEMENT. Les bans du circuit
# honeypot (hp=1 : honeypot + signatures SECURITY/POST-flood) ne comptent PAS ici (cf. finish_run) :
# le bruit de scan d'un mutualisé bannit une nouvelle IP honeypot toutes les ~10-15 min et clouait
# la cadence au plancher en permanence (l'accalmie de CADENCE_CALM_SECS n'était jamais atteinte).
# La réaction rapide aux attaques reste assurée par la SENTINELLE (sentinel_hit force un run complet
# <= 5 min sur toute signature SECURITY ou IP > BAN_THRESHOLD), pas par le resserrement du planning.
# Descente : un cran plus serré par run avec ban réel ; DEUX crans si >= CADENCE_SURGE bans réels
# dans le même run (attaque multi-IP caractérisée — descente graduée plutôt que plancher brutal).
# Remontée : un cran plus lâche SEULEMENT si aucun ban réel depuis CADENCE_CALM_SECS (accalmie
# constatée, pas simple run calme — sinon dents de scie 5<->10 permanentes, ~150 changements/jour
# observés sur un mutualisé, juil. 2026). L'epoch du dernier ban réel (2e champ de CADENCE_FILE) se
# rafraîchit à CHAQUE run avec ban réel, même à intervalle inchangé (sinon la relâche démarrerait
# trop tôt) ; ancien format à 1 champ => 0.
cadence_adjust() {
    [ "$(cron_step_mode)" = auto ] || return 0
    local now line cur last new dir tmp
    now=$(date +%s)
    cur=$(cadence_read)
    line=$(head -n 1 "$CADENCE_FILE" 2>/dev/null)
    last=${line#* }
    [ "$last" = "$line" ] && last=""                            # pas d'espace : ancien format 1 champ
    case "$last" in ''|*[!0-9]*) last=0 ;; esac
    if [ "${1:-0}" -gt 0 ] 2>/dev/null; then
        if [ "${1:-0}" -ge "$CADENCE_SURGE" ] 2>/dev/null; then
            case "$cur" in 60) new=20 ;; 40) new=10 ;; *) new=5 ;; esac   # attaque massive : 2 crans
        else
            case "$cur" in 60) new=40 ;; 40) new=20 ;; 20) new=10 ;; *) new=5 ;; esac
        fi
        last=$now
    elif [ $(( now - last )) -ge "$CADENCE_CALM_SECS" ]; then
        case "$cur" in 5) new=10 ;; 10) new=20 ;; 20) new=40 ;; *) new=60 ;; esac
        [ "$new" = "$cur" ] && return 0                         # déjà au plafond : rien à écrire
    else
        return 0                                                # calme, mais accalmie pas encore acquise
    fi
    # Journalisé [i] (pas seulement --verbose) : la suite des montées/descentes dans
    # /var/log/ban_404.log raconte les attaques ; les compteurs de stats ne lisent que [+]/[-].
    [ "$new" != "$cur" ] && t_log cadence.adjusted "$cur" "$new"
    dir=$(dirname "$CADENCE_FILE"); mkdir -p "$dir" 2>/dev/null
    tmp=$(mktemp "$dir/.cadence.XXXXXX" 2>/dev/null) || return 0
    printf '%s %s\n' "$new" "$last" > "$tmp" 2>/dev/null
    chmod 644 "$tmp" 2>/dev/null
    mv -f "$tmp" "$CADENCE_FILE" 2>/dev/null || rm -f "$tmp" 2>/dev/null
    return 0
}

# --- Bannissement gradué : mémoire des récidives (depuis 2.3.0) -------------------------------
# Fichier d'état OFFENDERS_FILE : une ligne par IP, « ip nb_bans epoch_fin_du_dernier_ban ». Même
# patron que metrics_sample / ipset_counts_sample / cadence_adjust : purge-on-write, écriture
# atomique mktemp + mv, return 0 EN TOUTES CIRCONSTANCES — ce fichier ne doit JAMAIS faire échouer
# un run (il ne porte qu'un raffinement de durée, la protection elle-même n'en dépend pas).
#
# Une entrée est PÉRIMÉE quand « epoch_fin + ESCALATION_MEMORY < maintenant » : la période
# d'épreuve court donc à partir de la LIBÉRATION de l'IP, pas de la pose du ban. Datée sur la pose,
# une mémoire égale au ban maximal remettrait le compteur à zéro à l'instant précis où l'IP sort du
# set — le pire récidiviste redeviendrait primo-délinquant grâce au ban qu'il a mérité.
#
# Défini ICI (et non près de metrics_sample) parce que escalation_forget est appelée par do_unban,
# lui-même invoqué DEPUIS la boucle de parsing des arguments : les définitions doivent la précéder.

# Nb de bans déjà mémorisés pour les IP passées sur stdin (une par ligne). Émet « ip nb_bans » pour
# les seules IP connues ET non périmées. UN SEUL passage awk quel que soit le nombre de candidates
# (pas de grep par IP, pas de chargement du fichier entier en tableau Bash).
escalation_lookup() {
    [ -r "$OFFENDERS_FILE" ] || return 0
    awk -v cut="$(date +%s)" -v mem="${ESCALATION_MEMORY:-0}" '
        NR==FNR { if ($0 != "") want[$0]=1; next }
        NF>=3 && ($1 in want) && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $3+mem >= cut { print $1, $2+0 }
    ' - "$OFFENDERS_FILE" 2>/dev/null
    return 0
}

# TTL (s) et NIVEAU du ban à poser — fonction PURE, aucun effet de bord, testable isolément.
#   $1 = count (score awk)   $2 = hp (1 = circuit honeypot/SECURITY/POST-flood)   $3 = récidives
# Émet « ttl niveau ». niveau = récidives + circuit honeypot + bonus d'agressivité, borné au nombre
# de paliers ; niveau 0 => la base du circuit, soit le comportement historique EXACT d'un 1er ban.
# max(ttl, base) : ne raccourcit JAMAIS le ban par rapport au réglage explicite de l'admin (un
# HONEYPOT_BAN_TIMEOUT durci en conf locale reste souverain). BAN_ESCALATION vide => escalade off.
escalation_ttl() {
    local count="${1:-0}" hp="${2:-0}" rec="${3:-0}" base level n ttl
    local -a tiers
    case "$hp" in 1) base="$HONEYPOT_BAN_TIMEOUT" ;; *) base="$BAN_TIMEOUT" ;; esac
    read -r -a tiers <<< "${BAN_ESCALATION:-}"
    n=${#tiers[@]}
    if [ "$n" -eq 0 ]; then printf '%s 0' "$base"; return 0; fi
    case "$rec" in ''|*[!0-9]*) rec=0 ;; esac
    level=$rec
    [ "$hp" = 1 ] && level=$((level + 1))
    if [ "${AGGRESSIVE_SCORE:-0}" -gt 0 ] 2>/dev/null && [ "${count:-0}" -ge "${AGGRESSIVE_SCORE}" ] 2>/dev/null; then
        level=$((level + 1))
    fi
    [ "$level" -gt "$n" ] && level=$n
    if [ "$level" -le 0 ]; then ttl="$base"; else ttl="${tiers[level-1]}"; fi
    case "$ttl" in ''|*[!0-9]*) ttl="$base" ;; esac
    [ "$ttl" -lt "$base" ] 2>/dev/null && ttl="$base"
    printf '%s %s' "$ttl" "$level"
    return 0
}

# Enregistre les bans du run (tableau esc_records, lignes « ip epoch_fin_du_ban ») ET purge les
# entrées périmées, en un seul awk + bascule atomique. Le compteur est INCRÉMENTÉ si l'IP était
# connue et encore dans sa période d'épreuve ; il repart à 1 si l'entrée était périmée (l'IP a
# purgé sa peine puis est restée sage : c'est une nouvelle primo-délinquance).
escalation_record() {
    { [ "$DRY_RUN" = false ] && [ "$(id -u)" -eq 0 ]; } || return 0
    [ "${#esc_records[@]}" -gt 0 ] || return 0
    local now dir tmp src
    now=$(date +%s)
    src="$OFFENDERS_FILE"; [ -r "$src" ] || src=/dev/null   # 1re écriture : awk ne doit pas échouer
    dir=$(dirname "$OFFENDERS_FILE"); mkdir -p "$dir" 2>/dev/null
    tmp=$(mktemp "$dir/.offenders.XXXXXX" 2>/dev/null) || return 0
    printf '%s\n' "${esc_records[@]}" | awk -v cut="$now" -v mem="${ESCALATION_MEMORY:-0}" '
        NR==FNR { if (NF>=2) newexp[$1]=$2; next }
        NF>=3 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
            if ($1 in newexp) {
                print $1, ($3+mem >= cut ? $2+1 : 1), newexp[$1]
                delete newexp[$1]
            } else if ($3+mem >= cut) print $1, $2+0, $3
        }
        END { for (ip in newexp) print ip, 1, newexp[ip] }
    ' - "$src" > "$tmp" 2>/dev/null
    chmod 644 "$tmp" 2>/dev/null
    mv -f "$tmp" "$OFFENDERS_FILE" 2>/dev/null || rm -f "$tmp" 2>/dev/null
    return 0
}

# Oubli du compteur : déban manuel (verdict d'innocence de l'admin) ou déban whitelist. « all »
# vide le fichier. Neutre en dry-run et hors root.
escalation_forget() {  # $1 = IP | all
    { [ "${DRY_RUN:-false}" = false ] && [ "$(id -u)" -eq 0 ]; } || return 0
    [ -f "$OFFENDERS_FILE" ] || return 0
    local dir tmp
    if [ "${1,,}" = all ]; then : > "$OFFENDERS_FILE" 2>/dev/null; return 0; fi
    [ -n "${1:-}" ] || return 0
    dir=$(dirname "$OFFENDERS_FILE")
    tmp=$(mktemp "$dir/.offenders.XXXXXX" 2>/dev/null) || return 0
    awk -v ip="$1" '$1 != ip' "$OFFENDERS_FILE" > "$tmp" 2>/dev/null
    chmod 644 "$tmp" 2>/dev/null
    mv -f "$tmp" "$OFFENDERS_FILE" 2>/dev/null || rm -f "$tmp" 2>/dev/null
    return 0
}

# Durée lisible pour les messages (« 14 j », « 36 h ») — unité TRADUITE, valeur non numérique
# rendue telle quelle. Utilisé sans saut de ligne, via $(fmt_duration …).
fmt_duration() {  # $1 = secondes
    local s="${1:-0}"
    case "$s" in ''|*[!0-9]*) printf '%s' "$s"; return 0 ;; esac
    if [ "$s" -ge 86400 ]; then printf '%s %s' "$((s / 86400))" "$(t unit.days)"
    else                        printf '%s %s' "$((s / 3600))"  "$(t unit.hours)"; fi
}

# Fichier de log candidat pour un dossier <BASE_DIR>/<vhost>/log/ : access.log s'il existe, sinon le
# plus récent *access.log en écartant yesterday-access.log (symlink ISPConfig périmé, jamais le bon).
# Vide si aucun. Factorisé : utilisé par discover_valid_logs ET la découverte du diag (anti-divergence ;
# futur point d'entrée des profils de layout, Phase 2 de l'universalisation).
candidate_log_for_dir() {  # $1 = dossier terminé par /log/
    if [ -f "${1}access.log" ]; then printf '%s' "${1}access.log"
    else ls -1t "${1}"*access.log 2>/dev/null | grep -v '/yesterday-access\.log$' | head -n 1; fi
}

# Profil de layout des logs EFFECTIF (echo). Explicite si LOG_PROFILE est un profil connu ; sinon
# 'auto' => sonde les chemins caractéristiques — ISPConfig D'ABORD (parc inchangé), puis plesk, cpanel,
# directadmin, nginx ; repli ispconfig (défaut historique). Mémoïsé (une seule sonde par run).
log_profile() {
    [ -n "${LOG_PROFILE_ACTIVE:-}" ] && { printf '%s' "$LOG_PROFILE_ACTIVE"; return; }
    local p
    case "${LOG_PROFILE:-auto}" in
        ispconfig|cpanel|directadmin|plesk|nginx|generic) p="$LOG_PROFILE" ;;
        *) if   ls -d ${BASE_DIR}/*/log/ >/dev/null 2>&1;       then p=ispconfig
           elif ls -d /var/www/vhosts/*/logs/ >/dev/null 2>&1;  then p=plesk
           elif [ -d /var/log/apache2/domlogs ];                then p=cpanel
           elif [ -d /var/log/httpd/domains ];                  then p=directadmin
           elif ls /var/log/nginx/*access*.log >/dev/null 2>&1; then p=nginx
           else p=ispconfig; fi ;;
    esac
    LOG_PROFILE_ACTIVE="$p"; printf '%s' "$p"
}

# Découverte des logs à analyser (factorisée : boucle principale ET sentinelle). Remplit les
# tableaux globaux FILES_FOUND puis VALID_FILES (lisibles et non vides). On écarte
# yesterday-access.log (symlink ISPConfig vers le log de la veille, souvent périmé) : jamais
# le bon fichier à analyser. Les vhosts d'EXCLUDE_VHOSTS sont sautés (trace --verbose).
discover_valid_logs() {
    local log_dir vhost latest file f
    FILES_FOUND=()
    # Énumération des fichiers candidats selon le PROFIL (le parseur awk, lui, est commun). La
    # dérivation du « vhost » (pour EXCLUDE_VHOSTS/verbose) est propre à chaque layout.
    case "$(log_profile)" in
        ispconfig)   # ${BASE_DIR}/<vhost>/log/access.log (défaut historique — verbatim)
            for log_dir in ${BASE_DIR}/*/log/; do
                [ -d "$log_dir" ] || continue
                vhost="${log_dir%/log/}"; vhost="${vhost##*/}"
                if is_excluded_vhost "$vhost"; then [ "$VERBOSE" = true ] && t verbose.vhost_excluded "$vhost"; continue; fi
                latest=$(candidate_log_for_dir "$log_dir")
                [ -n "$latest" ] && FILES_FOUND+=("$latest")
            done ;;
        plesk)       # /var/www/vhosts/<domaine>/logs/access_log|access_ssl_log
            for log_dir in /var/www/vhosts/*/logs/; do
                [ -d "$log_dir" ] || continue
                vhost="${log_dir%/logs/}"; vhost="${vhost##*/}"
                if is_excluded_vhost "$vhost"; then [ "$VERBOSE" = true ] && t verbose.vhost_excluded "$vhost"; continue; fi
                latest=$(ls -1t "${log_dir}"access*log 2>/dev/null | head -n 1)
                [ -n "$latest" ] && FILES_FOUND+=("$latest")
            done ;;
        cpanel)      # /var/log/apache2/domlogs/<domaine> (+ <domaine>-ssl_log), un fichier par domaine
            for f in /var/log/apache2/domlogs/*; do
                [ -f "$f" ] || continue
                case "$f" in *.offset|*.bkup|*ftpxferlog*) continue ;; esac
                vhost="${f##*/}"; vhost="${vhost%-ssl_log}"
                if is_excluded_vhost "$vhost"; then [ "$VERBOSE" = true ] && t verbose.vhost_excluded "$vhost"; continue; fi
                FILES_FOUND+=("$f")
            done ;;
        directadmin) # /var/log/httpd/domains/<domaine>.log (hors .error.log)
            for f in /var/log/httpd/domains/*.log; do
                [ -f "$f" ] || continue
                case "$f" in *.error.log) continue ;; esac
                vhost="${f##*/}"; vhost="${vhost%.log}"
                if is_excluded_vhost "$vhost"; then [ "$VERBOSE" = true ] && t verbose.vhost_excluded "$vhost"; continue; fi
                FILES_FOUND+=("$f")
            done ;;
        nginx)       # /var/log/nginx/*access*.log (hors *error*)
            for f in /var/log/nginx/*access*.log; do
                [ -f "$f" ] || continue
                case "$f" in *error*) continue ;; esac
                vhost="${f##*/}"
                if is_excluded_vhost "$vhost"; then [ "$VERBOSE" = true ] && t verbose.vhost_excluded "$vhost"; continue; fi
                FILES_FOUND+=("$f")
            done ;;
        generic)     # ${BASE_DIR}/*access*.log et ${BASE_DIR}/*/*access*.log (hors *error*/yesterday)
            for f in ${BASE_DIR}/*access*.log ${BASE_DIR}/*/*access*.log; do
                [ -f "$f" ] || continue
                case "$f" in *error*|*/yesterday-access.log) continue ;; esac
                vhost="${f##*/}"
                if is_excluded_vhost "$vhost"; then [ "$VERBOSE" = true ] && t verbose.vhost_excluded "$vhost"; continue; fi
                FILES_FOUND+=("$f")
            done ;;
    esac
    # Dédup (globs qui se recouvrent en generic, symlinks) en préservant l'ordre.
    if [ "${#FILES_FOUND[@]}" -gt 0 ]; then
        local -A _seen=(); local -a _uniq=()
        for f in "${FILES_FOUND[@]}"; do [ -n "${_seen[$f]:-}" ] && continue; _seen[$f]=1; _uniq+=("$f"); done
        FILES_FOUND=("${_uniq[@]}")
    fi
    VALID_FILES=()
    for file in "${FILES_FOUND[@]}"; do
        if [ -r "$file" ] && [ -s "$file" ]; then
            [ "$VERBOSE" = true ] && t verbose.log_ok "$file"
            VALID_FILES+=("$file")
        else
            [ "$VERBOSE" = true ] && t verbose.log_skip "$file"
        fi
    done
    return 0
}

# Sentinelle du mode auto (tick « porté ») : survol des SENTINEL_LINES dernières lignes de chaque
# log à la recherche d'un signal d'attaque POSTÉRIEUR au dernier run complet ($1 = borne
# AAAAMMJJHHMMSS) — sans cette borne, de vieilles lignes déjà analysées re-déclencheraient un run
# complet à CHAQUE tick sur un site calme. Signal = une signature sécurité (IP non whitelistée) OU
# une même IP dépassant BAN_THRESHOLD en 404 hors bruit. Volontairement grossière et légère (fin
# de fichier en page cache, parse de date payé par les seules lignes candidates) : elle ne bannit
# rien, elle décide seulement s'il faut payer l'analyse complète — le scoring fenêtré fait foi.
# Retour 0 = déclenchement.
sentinel_hit() {
    local cutoff="$1"
    discover_valid_logs
    [ ${#VALID_FILES[@]} -eq 0 ] && return 1
    tail -n "$SENTINEL_LINES" -q "${VALID_FILES[@]}" 2>/dev/null | \
        SECURITY_RE="$SECURITY_PATTERN" NOISE_RE="$NOISE_PATTERN" \
        awk -v wl="$WHITELIST_IP" -v cutoff="$cutoff" -v thr="$BAN_THRESHOLD" '
    BEGIN {
        split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", M, " ")
        for (i=1;i<=12;i++) mon[M[i]]=i
        n=split(wl, Wl, "|"); for (i=1;i<=n;i++) white[Wl[i]]=1
        security_re = ENVIRON["SECURITY_RE"]
        noise_re = ENVIRON["NOISE_RE"]
    }
    !($1 in white) {
        cand = 0
        if (security_re != "" && tolower($7) ~ security_re) cand = 1
        else if ($9 == 404 && (noise_re == "" || tolower($7) !~ noise_re)) cand = 2
        if (!cand) next
        split(substr($4,2), d, /[\/:]/)
        ts = sprintf("%04d%02d%02d%02d%02d%02d", d[3], mon[d[2]], d[1], d[4], d[5], d[6])
        if (ts < cutoff) next
        if (cand == 1) exit 10
        if (++c404[$1] > thr) exit 10
    }'
    [ $? -eq 10 ]
}

# ---------- --diag : auto-diagnostic lecture seule de l'état du serveur ----------
# Liste les anomalies (composants & versions, crons, pare-feu, conf/réseau, logs, cohérence des
# notifications) sans rien modifier ni envoyer (≠ --check-notification qui émet un test live).
# Calque check_notification : en-tête, une ligne [ OK ]/[WARN]/[FAIL] par contrôle, bilan, exit
# (0 = sain, 1 = au moins une anomalie). DIAG_PROBLEMS compte les WARN + FAIL.
DIAG_PROBLEMS=0
DIAG_QUIET=false           # true => diag_line accumule sans imprimer (réutilisé par le résumé)
declare -a DIAG_ISSUES=()  # lignes "[WARN]/[FAIL] message" accumulées (pour le résumé quotidien)
declare -a HEALTH_LINES=() # signes vitaux localisés AVEC valeurs (bloc « Signes vitaux » du résumé)
declare -a HEALTH_SEV=()   # gravité (ok|warn|crit) alignée sur HEALTH_LINES (coloration vert/orange/rouge)
HEALTH_DONE=false          # garde anti-double-mesure (l'échantillon réseau ~1 s ne tourne qu'une fois)
diag_line() {  # $1 = ok|warn|fail ; $2 = message déjà localisé
    local tag sev
    case "$1" in
        ok)   tag="[ OK ]"; sev=ok ;;
        warn) tag="[WARN]"; sev=warn; DIAG_PROBLEMS=$((DIAG_PROBLEMS + 1)); DIAG_ISSUES+=("$tag $2") ;;
        *)    tag="[FAIL]"; sev=crit; DIAG_PROBLEMS=$((DIAG_PROBLEMS + 1)); DIAG_ISSUES+=("$tag $2") ;;
    esac
    [ "$DIAG_QUIET" = true ] && return 0
    printf '%s %s\n' "$(sev_ansi "$sev" "$tag")" "$2"   # tag coloré au terminal (OUTPUT_MODE=ansi) ; DIAG_ISSUES reste nu (résumé)
}
diag_is_on() { case "${1:-}" in true|1|yes|on) return 0 ;; *) return 1 ;; esac; }

# Options réseau curl robustes (contrôle de version, MAJ). --retry seul NE réessaie PAS l'exit 7
# « Couldn't connect » (ni timeout ni code HTTP) ; --retry-all-errors (curl >= 7.71) le couvre —
# mais c'est une option FATALE sur curl plus ancien, donc ajoutée seulement si la version la
# supporte (détection fail-safe : tout échec => on retombe sur --retry nu). Mémoïsé (un seul
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

# run_diag_checks : exécute les ~25 contrôles (appels diag_line), SANS en-tête ni bilan ni exit.
# Extrait de do_diag pour être réutilisable par le résumé quotidien (build_stats_text) en mode
# DIAG_QUIET (accumulation dans DIAG_ISSUES sans impression). do_diag l'enrobe (en-tête + bilan).
run_diag_checks() {
    local engine="/usr/local/sbin/ban_404.sh" updater="/usr/local/sbin/update_ban_404.sh"
    local upd_ver="" repo_versions repo_engine repo_upd up n chans
    local active inactive excluded unreadable log_dir vhost f now mt age_d age_h engine_stale

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
        # UNE seule requête : le fichier VERSIONS du dépôt porte les deux versions publiées
        # (synchro avec les scripts garantie par check.sh). Évite de télécharger les deux
        # scripts entiers, et surtout de contribuer au rate-limiting par IP (HTTP 429) de
        # raw.githubusercontent.com. net_opts_init compose les options de robustesse : --retry
        # absorbe le 429 (curl >= 7.66) mais PAS l'exit 7 « Couldn't connect » (blip d'egress) —
        # --retry-all-errors (curl >= 7.71, si supporté) l'y ajoute ; --connect-timeout borne un
        # connect qui traîne. Repli sur les téléchargements complets historiques si VERSIONS
        # manque (fork/miroir sans ce fichier).
        net_opts_init
        repo_versions=$(curl -fsSL "${NET_OPTS[@]}" --max-time 15 "$REPO_RAW/VERSIONS" 2>/dev/null)
        repo_engine=$(printf '%s\n' "$repo_versions" | grep -m1 '^BAN404_VERSION='   | cut -d'"' -f2)
        repo_upd=$(   printf '%s\n' "$repo_versions" | grep -m1 '^UPDATER_VERSION=' | cut -d'"' -f2)
        if [ -z "$repo_engine" ]; then
            repo_engine=$(curl -fsSL --max-time 15 "$REPO_RAW/ban_404.sh"        2>/dev/null | grep -m1 '^BAN404_VERSION='   | cut -d'"' -f2)
        fi
        if [ -z "$repo_upd" ]; then
            repo_upd=$(   curl -fsSL --max-time 15 "$REPO_RAW/update_ban_404.sh" 2>/dev/null | grep -m1 '^UPDATER_VERSION=' | cut -d'"' -f2)
        fi
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
    # Présence ET bit exécutable : run-parts saute EN SILENCE un fichier non exécutable — le cron
    # « existe » mais ne tourne jamais (bans, self-heals et MAJ figés sans le moindre symptôme).
    if   [ -x /etc/cron.hourly/ban_404 ]; then diag_line ok "$(t diag.present /etc/cron.hourly/ban_404)"
    elif [ -f /etc/cron.hourly/ban_404 ]; then diag_line warn "$(t diag.cron_noexec /etc/cron.hourly/ban_404)"
    else diag_line fail "$(t diag.absent /etc/cron.hourly/ban_404)"; fi
    # Nom courant 0_ban_404_update (préfixe forçant l'ordre run-parts : updater AVANT résumé) ;
    # l'ancien nom ban_404_update reste OK (fonctionnel, renommé par l'updater >= 1.2.12).
    if   [ -x /etc/cron.daily/0_ban_404_update ]; then diag_line ok "$(t diag.present /etc/cron.daily/0_ban_404_update)"
    elif [ -x /etc/cron.daily/ban_404_update ]; then diag_line ok "$(t diag.present /etc/cron.daily/ban_404_update)"
    elif [ -f /etc/cron.daily/0_ban_404_update ]; then diag_line warn "$(t diag.cron_noexec /etc/cron.daily/0_ban_404_update)"
    elif [ -f /etc/cron.daily/ban_404_update ]; then diag_line warn "$(t diag.cron_noexec /etc/cron.daily/ban_404_update)"
    else diag_line warn "$(t diag.absent /etc/cron.daily/0_ban_404_update)"; fi
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
    # Fraîcheur du MOTEUR : un cron.hourly qui ne s'exécute plus (bit -x perdu, verrou zombie,
    # crontab mutilé) fige bans ET self-heals en silence — l'updater daily, lui, peut continuer à
    # rafraîchir le moteur, masquant la panne. Le moteur touche RUN_STAMP_FILE en FIN de run réel :
    # >= 3 h sans trace = au moins 2 passages horaires manqués.
    engine_stale=false
    if [ -f "$RUN_STAMP_FILE" ]; then
        now=$(date +%s); mt=$(stat -c %Y "$RUN_STAMP_FILE" 2>/dev/null || echo 0)
        age_h=$(( (now - mt) / 3600 ))
        if [ "$age_h" -ge 3 ]; then diag_line warn "$(t diag.engine_stale "$age_h")"; engine_stale=true
        else diag_line ok "$(t diag.engine_fresh)"; fi
    else
        diag_line warn "$(t diag.engine_never)"
    fi
    # Verrou anti-chevauchement. Le run cron.hourly tient le verrou EXCLUSIF pendant TOUT son passage ;
    # s'il chevauche le résumé (cron.daily ~06:25) ou un --diag interactif, le test le verrait « tenu »
    # sans anomalie réelle — faux positif (le motif du diag.lock_stuck vu sur le parc). On ne signale
    # donc le verrou QUE si le moteur paraît AUSSI figé (RUN_STAMP_FILE périmé ci-dessus, engine_stale) :
    # un vrai verrou zombie fait échouer chaque passage horaire au flock, donc plus aucun run ne se
    # stampe => last_run vieillit. Stamp frais = simple chevauchement bénin => on reste muet. Test non
    # bloquant en LECTURE seule ; le sous-shell relâche le fd 9 en sortant (ne laisse aucun verrou).
    if [ "$engine_stale" = true ] && [ -e "$LOCK_FILE" ] && ! ( flock -n 9 ) 9<"$LOCK_FILE" 2>/dev/null; then
        diag_line warn "$(t diag.lock_stuck "$LOCK_FILE")"
    fi
    if diag_is_on "$DAILY_SUMMARY"; then
        if [ -x /etc/cron.daily/1_ban_404_summary ] || [ -x /etc/cron.daily/ban_404_summary ]; then diag_line ok "$(t diag.summary_cron_ok)"
        elif [ -f /etc/cron.daily/1_ban_404_summary ]; then diag_line warn "$(t diag.cron_noexec /etc/cron.daily/1_ban_404_summary)"
        elif [ -f /etc/cron.daily/ban_404_summary ]; then diag_line warn "$(t diag.cron_noexec /etc/cron.daily/ban_404_summary)"
        else diag_line warn "$(t diag.summary_cron_missing_wanted)"; fi
    else
        if [ -f /etc/cron.daily/1_ban_404_summary ] || [ -f /etc/cron.daily/ban_404_summary ]; then diag_line warn "$(t diag.summary_cron_orphan)"
        else diag_line ok "$(t diag.summary_cron_off)"; fi
    fi
    # Cron de ticks intermédiaires : cohérence conf (CRON_STEP) <-> /etc/cron.d/ban_404_step.
    # CRON_STEP absent + fichier absent => aucune ligne (zéro bruit pour le parc qui n'en use pas).
    sc_mode=$(cron_step_mode)
    if [ -n "${CRON_STEP:-}" ] && [ "$sc_mode" = off ]; then
        diag_line warn "$(t diag.step_cron_invalid "$CRON_STEP")"
    elif [ "$sc_mode" != off ]; then
        if [ -f /etc/cron.d/ban_404_step ]; then
            if [ "$sc_mode" = auto ]; then diag_line ok "$(t diag.step_cron_ok_auto "$(cadence_read)")"
            else diag_line ok "$(t diag.step_cron_ok "$CRON_STEP")"; fi
        else
            diag_line warn "$(t diag.step_cron_missing_wanted)"
        fi
    elif [ -f /etc/cron.d/ban_404_step ]; then
        diag_line warn "$(t diag.step_cron_orphan)"
    fi

    # 4. Pare-feu : d'abord la PLATEFORME + les backends (détection, sans root), puis l'état
    #    ipset/iptables/persistance (root) UNIQUEMENT si la plateforme est supportée — inutile (et
    #    bruyant en [FAIL]) de chercher un ipset sur une plateforme en lecture seule.
    local pf_id pf_avail
    pf_id=$( . /etc/os-release 2>/dev/null; printf '%s' "${ID:-inconnu}" )
    pf_avail=""
    { command -v ipset >/dev/null 2>&1 && { command -v iptables >/dev/null 2>&1 || [ -x /sbin/iptables ]; }; } && pf_avail="iptables+ipset"
    command -v nft >/dev/null 2>&1 && pf_avail="${pf_avail:+$pf_avail, }nftables"
    [ -n "$pf_avail" ] || pf_avail="—"
    if platform_supported; then
        diag_line ok "$(t diag.platform_ok "$pf_id")"
        diag_line ok "$(t diag.fw_backend "$(fw_backend_label)" "$pf_avail")"   # backend EFFECTIF (FW_BACKEND) + disponibles
        if [ "$(id -u)" -eq 0 ]; then
            if fw_set_exists; then
                diag_line ok "$(t diag.fw_set_ok "$IPSET_NAME" "$(fw_count "$IPSET_NAME")")"
            else
                diag_line fail "$(t diag.fw_set_missing "$IPSET_NAME")"
            fi
            if fw_rule_present; then
                diag_line ok "$(t diag.fw_rule_ok)"
            else
                diag_line fail "$(t diag.fw_rule_missing)"
            fi
            if fw_persist_present; then
                diag_line ok "$(t diag.persist_ok)"
            else
                diag_line warn "$(t diag.persist_missing)"
            fi
            # Ban gradué : état + volumétrie de la mémoire des récidives. Informatif ([ OK ] dans
            # les deux cas) — désactiver l'escalade est un choix d'admin légitime, pas une anomalie.
            if [ -n "${BAN_ESCALATION// /}" ]; then
                local esc_tiers="" esc_tracked esc_rep _s
                local -a esc_t=()
                read -r -a esc_t <<< "$BAN_ESCALATION"
                for _s in "${esc_t[@]}"; do esc_tiers+="$(fmt_duration "$_s") "; done
                # IP suivies (dans leur période d'épreuve) et, parmi elles, celles qui ont DÉJÀ
                # récidivé (>= 2 bans). On ne compte pas « au palier maxi » : le palier dépend aussi
                # du circuit (honeypot = +1), que le fichier d'état ne mémorise pas.
                read -r esc_tracked esc_rep < <(awk -v cut="$(date +%s)" -v mem="${ESCALATION_MEMORY:-0}" '
                    NF>=3 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $3+mem >= cut { k++; if ($2+0 >= 2) m++ }
                    END { print k+0, m+0 }' "$OFFENDERS_FILE" 2>/dev/null)
                diag_line ok "$(t diag.escalation_on "${esc_tiers% }" "$(fmt_duration "${ESCALATION_MEMORY:-0}")" "${esc_tracked:-0}" "${esc_rep:-0}")"
            else
                diag_line ok "$(t diag.escalation_off)"
            fi
        else
            diag_line warn "$(t diag.root_skip)"
        fi
    else
        diag_line warn "$(t diag.platform_readonly "$pf_id")"
        diag_line ok "$(t diag.fw_backend "$(t diag.fw_none)" "$pf_avail")"
    fi

    # 5. Conf & logrotate
    if [ -f "$CONF_FILE" ]; then diag_line ok "$(t diag.present "$CONF_FILE")"
    else diag_line fail "$(t diag.absent "$CONF_FILE")"; fi
    if [ -f /etc/logrotate.d/ban_404 ]; then diag_line ok "$(t diag.present /etc/logrotate.d/ban_404)"
    else diag_line warn "$(t diag.absent /etc/logrotate.d/ban_404)"; fi
    # Complétion Bash : tester le FRAMEWORK (fichier bash_completion, propre au paquet), pas le
    # répertoire — apt/systemd créent /usr/share/bash-completion/completions même sans le paquet,
    # et sans le framework RIEN ne charge notre fichier : Tab muet alors que tout semblait [ OK ].
    # L'installeur pose le paquet ; son absence sur un serveur géré est donc une vraie anomalie.
    if   [ ! -f /usr/share/bash-completion/bash_completion ]; then diag_line warn "$(t diag.completion_pkg)"
    elif [ ! -f /usr/share/bash-completion/completions/ban_404.sh ]; then diag_line warn "$(t diag.absent /usr/share/bash-completion/completions/ban_404.sh)"
    # Shim de chargement anticipé (déposé par l'updater >= 1.2.13) : sans lui, « sudo ban_404.sh
    # <Tab> » ne complète pas (la délégation sudo de bash-completion <= 2.11 ne charge pas à la
    # demande) — seul le Tab direct fonctionne.
    elif [ ! -f /etc/bash_completion.d/ban_404 ]; then diag_line warn "$(t diag.absent /etc/bash_completion.d/ban_404)"
    else diag_line ok "$(t diag.present /usr/share/bash-completion/completions/ban_404.sh)"; fi

    # 6. Découverte des logs (même logique que l'analyse ; purement lecture). On sépare les cas
    # BÉNINS (site inactif : aucun access.log, symlink cassé, ou fichier vide — fréquent en
    # ISPConfig où access.log pointe sur le log du jour, absent si le site ne logue plus) du SEUL
    # vrai problème : un log présent mais NON LISIBLE (permission/ACL). --verbose détaille chaque
    # dossier fautif pour repérer un éventuel vrai site mal classé.
    diag_line ok "$(t diag.log_profile "$(log_profile)")"
    if [ "$(log_profile)" = ispconfig ]; then
        # Classification par dossier PROPRE à ISPConfig (access.log = log du jour, souvent absent
        # si le site ne logue plus : cas BÉNIN à distinguer du seul vrai problème, un log non lisible).
        active=0; inactive=0; unreadable=0; excluded=0
        for log_dir in ${BASE_DIR}/*/log/; do
            [ -d "$log_dir" ] || continue
            vhost="${log_dir%/log/}"; vhost="${vhost##*/}"
            if is_excluded_vhost "$vhost"; then excluded=$((excluded + 1)); continue; fi
            f=$(candidate_log_for_dir "$log_dir")   # access.log ou repli *access.log (hors yesterday-access.log)
            if   [ -z "$f" ];   then inactive=$((inactive + 1));     [ "$VERBOSE" = true ] && t diag.log_v_nolog "$vhost"
            elif [ ! -e "$f" ]; then inactive=$((inactive + 1));     [ "$VERBOSE" = true ] && t diag.log_v_broken "$vhost"
            elif [ ! -r "$f" ]; then unreadable=$((unreadable + 1)); [ "$VERBOSE" = true ] && t diag.log_v_unreadable "$vhost"
            elif [ ! -s "$f" ]; then inactive=$((inactive + 1));     [ "$VERBOSE" = true ] && t diag.log_v_empty "$vhost"
            else active=$((active + 1)); fi
        done
        if   [ "$unreadable" -gt 0 ]; then diag_line warn "$(t diag.logs "$active" "$inactive" "$unreadable" "$excluded")"
        elif [ "$active" -gt 0 ];     then diag_line ok   "$(t diag.logs "$active" "$inactive" "$unreadable" "$excluded")"
        else                               diag_line warn "$(t diag.logs "$active" "$inactive" "$unreadable" "$excluded")"; fi
    else
        # Autres profils : on rejoue la découverte (lecture seule) et on rapporte le nb de logs valides.
        discover_valid_logs
        if [ "${#VALID_FILES[@]}" -gt 0 ]; then diag_line ok "$(t diag.logs_found "${#VALID_FILES[@]}")"
        else diag_line warn "$(t diag.logs_found 0)"; fi
    fi

    # 7. Cohérence des notifications (config seule, aucun envoi)
    chans=""
    [ -n "$WEBHOOK_URL" ] && chans="webhook"
    [ -n "$NOTIFY_EMAIL" ] && chans="${chans:+$chans, }e-mail"
    if [ -n "$chans" ]; then diag_line ok "$(t diag.notify_channels "$chans")"
    else diag_line ok "$(t diag.notify_none)"; fi
    if diag_is_on "$NOTIFY_BANS"   && [ -z "$WEBHOOK_URL" ] && [ -z "$NOTIFY_EMAIL" ]; then diag_line warn "$(t diag.notify_orphan_bans)"; fi
    if diag_is_on "$DAILY_SUMMARY" && [ -z "$WEBHOOK_URL" ] && [ -z "$NOTIFY_EMAIL" ]; then diag_line warn "$(t diag.notify_orphan_summary)"; fi

    # 8. Signes vitaux du serveur (load, mémoire, disque, MTA, IO, réseau)
    run_health_checks
}

# ---------- Signes vitaux du serveur (sous-commande health ; inclus dans diag et le résumé) ----------
# health_line double diag_line : le message (valeurs comprises) part aussi dans HEALTH_LINES, que
# build_stats_text imprime en bloc « Signes vitaux » TOUJOURS affiché dans le résumé — les seuils
# franchis remontent, eux, via DIAG_ISSUES comme n'importe quel [WARN]/[FAIL] de diagnostic.
# L'accumulation reste hors de diag_line pour ne pas embarquer les ~25 contrôles classiques.
health_line() {  # $1 = ok|warn|crit ; $2 = message déjà localisé (avec valeurs)
    HEALTH_LINES+=("$2")
    HEALTH_SEV+=("$1")
    local dtag="$1"; [ "$1" = crit ] && dtag=fail   # crit => [FAIL] (compte comme anomalie), warn => [WARN]
    diag_line "$dtag" "$2"
}

# Occupation espace + inodes d'un point de montage ($1). Inodes « - » (FS sans inodes) => 0.
health_disk_check() {
    local mnt="$1" pcent ipcent
    pcent=$(df -P "$mnt" 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}')
    case "$pcent" in ''|*[!0-9]*) return 0 ;; esac
    ipcent=$(df -Pi "$mnt" 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}')
    case "$ipcent" in ''|*[!0-9]*) ipcent=0 ;; esac
    if [ "$pcent" -gt "$HEALTH_DISK_CRIT" ] || [ "$ipcent" -gt "$HEALTH_DISK_CRIT" ]; then
        health_line crit "$(t diag.health_disk_full "$mnt" "$pcent" "$ipcent" "$HEALTH_DISK_CRIT")"
    elif [ "$pcent" -gt "$HEALTH_DISK_WARN" ] || [ "$ipcent" -gt "$HEALTH_DISK_WARN" ]; then
        health_line warn "$(t diag.health_disk_full "$mnt" "$pcent" "$ipcent" "$HEALTH_DISK_WARN")"
    else
        health_line ok "$(t diag.health_disk "$mnt" "$pcent" "$ipcent")"
    fi
}

# Débit octets/s => forme humaine (kB/MB), pour la ligne réseau. Borné à 0 (wrap de compteur).
health_rate() { awk -v b="${1:-0}" 'BEGIN{ if (b < 0) b = 0; if (b >= 1048576) printf "%.1f MB", b/1048576; else printf "%.0f kB", b/1024 }'; }

# run_health_checks : mesure les signes vitaux (lecture seule, aucune dépendance obligatoire :
# chaque mesure se dégrade en silence ou en ligne « non mesurable » si l'outil/le /proc manque ;
# tout passe non-root). Valeurs => health_line (diag + bloc du résumé) ; contrôles warn-only
# (unités systemd en échec, reboot requis) => diag_line direct, muets quand tout va bien.
run_health_checks() {
    [ "$HEALTH_DONE" = true ] && return 0
    diag_is_on "${HEALTH_CHECKS:-true}" || return 0
    HEALTH_DONE=true
    local l1 l5 l15 cores up mem_total mem_avail mem_pct swap_pct
    local root_dev var_dev q_raw queue running io iface rx1 tx1 rx2 tx2 failed n_failed

    # a. Charge (load average) + uptime — WARN si load 15 min > HEALTH_LOAD_WARN x cœurs
    if [ -r /proc/loadavg ]; then
        read -r l1 l5 l15 _ < /proc/loadavg
        cores=$(nproc 2>/dev/null) || cores=$(grep -c ^processor /proc/cpuinfo 2>/dev/null)
        [ -n "$cores" ] || cores=1
        up=$(awk '{printf "%dd %dh", int($1/86400), int(($1%86400)/3600)}' /proc/uptime 2>/dev/null)
        if awk -v l="$l15" -v c="$cores" -v m="$HEALTH_LOAD_CRIT" 'BEGIN{exit !(l > c*m)}'; then
            health_line crit "$(t diag.health_load_high "$l1" "$l5" "$l15" "$cores" "$HEALTH_LOAD_CRIT" "${up:-?}")"
        elif awk -v l="$l15" -v c="$cores" -v m="$HEALTH_LOAD_WARN" 'BEGIN{exit !(l > c*m)}'; then
            health_line warn "$(t diag.health_load_high "$l1" "$l5" "$l15" "$cores" "$HEALTH_LOAD_WARN" "${up:-?}")"
        else
            health_line ok "$(t diag.health_load "$l1" "$l5" "$l15" "$cores" "${up:-?}")"
        fi
    fi

    # b. Mémoire (MemAvailable) + swap — WARN si dispo < HEALTH_MEM_WARN % ; swap informatif
    if [ -r /proc/meminfo ]; then
        # av : présence de MemAvailable (noyau >= 3.14) — absent => t=0 => mesure sautée (pas de faux WARN 0 %)
        read -r mem_total mem_avail mem_pct swap_pct <<< "$(awk '
            /^MemTotal:/{t=$2} /^MemAvailable:/{a=$2; av=1} /^SwapTotal:/{st=$2} /^SwapFree:/{sf=$2}
            END{ if (!av) t=0; printf "%d %d %d %s", int(t/1024), int(a/1024), (t>0 ? int(a*100/t) : 0), (st>0 ? int((st-sf)*100/st) : "-") }
        ' /proc/meminfo 2>/dev/null)"
        if [ -n "$mem_total" ] && [ "$mem_total" -gt 0 ]; then
            if [ "$mem_pct" -lt "$HEALTH_MEM_CRIT" ]; then
                health_line crit "$(t diag.health_mem_low "$mem_pct" "$mem_avail" "$mem_total" "$HEALTH_MEM_CRIT" "$swap_pct")"
            elif [ "$mem_pct" -lt "$HEALTH_MEM_WARN" ]; then
                health_line warn "$(t diag.health_mem_low "$mem_pct" "$mem_avail" "$mem_total" "$HEALTH_MEM_WARN" "$swap_pct")"
            else
                health_line ok "$(t diag.health_mem "$mem_pct" "$mem_avail" "$mem_total" "$swap_pct")"
            fi
        fi
    fi

    # c. Disque : / toujours, /var seulement si partition distincte (logs, spool mail)
    health_disk_check /
    root_dev=$(df -P / 2>/dev/null | awk 'NR==2{print $1}')
    var_dev=$(df -P /var 2>/dev/null | awk 'NR==2{print $1}')
    [ -n "$var_dev" ] && [ "$var_dev" != "$root_dev" ] && health_disk_check /var

    # d. MTA postfix : service actif ? file d'attente ? (l'incident fondateur : postfix arrêté =>
    # mailq énorme, mails perdus en silence). Arrêté => [FAIL] (du courrier se perd ACTIVEMENT).
    # postqueue lit la file même moteur arrêté ; s'il échoue (absent, restriction) => « ? » sans WARN.
    if command -v postfix >/dev/null 2>&1 || [ -x /usr/sbin/postfix ]; then
        queue="?"
        q_raw=$(postqueue -p 2>/dev/null | tail -n1)
        case "$q_raw" in
            *empty*) queue=0 ;;
            *Requests*) queue=$(printf '%s' "$q_raw" | awk '{print $(NF-1)}'); case "$queue" in ''|*[!0-9]*) queue="?" ;; esac ;;
        esac
        # pgrep -x master : preuve directe que le démon tourne (l'unité systemd postfix.service,
        # oneshot, peut rester « active » après un crash du master => pas fiable seule).
        if pgrep -x master >/dev/null 2>&1; then
            if [ "$queue" != "?" ] && [ "$queue" -gt "$HEALTH_MAILQ_CRIT" ]; then
                health_line crit "$(t diag.health_mta_queue "$queue" "$HEALTH_MAILQ_CRIT")"
            elif [ "$queue" != "?" ] && [ "$queue" -gt "$HEALTH_MAILQ_WARN" ]; then
                health_line warn "$(t diag.health_mta_queue "$queue" "$HEALTH_MAILQ_WARN")"
            else
                health_line ok "$(t diag.health_mta "$queue")"
            fi
        else
            health_line crit "$(t diag.health_mta_down "$queue")"
        fi
    else
        health_line ok "$(t diag.health_mta_none)"
    fi

    # e. Pression IO (PSI, noyau >= 4.20) — instantané, sans échantillonnage
    if [ -r /proc/pressure/io ]; then
        io=$(awk '/^some/{for(i=2;i<=NF;i++) if($i ~ /^avg60=/){sub(/^avg60=/,"",$i); print $i; exit}}' /proc/pressure/io 2>/dev/null)
        if [ -n "$io" ]; then
            if awk -v v="$io" -v s="$HEALTH_IO_CRIT" 'BEGIN{exit !(v > s)}'; then
                health_line crit "$(t diag.health_io_high "$io" "$HEALTH_IO_CRIT")"
            elif awk -v v="$io" -v s="$HEALTH_IO_WARN" 'BEGIN{exit !(v > s)}'; then
                health_line warn "$(t diag.health_io_high "$io" "$HEALTH_IO_WARN")"
            else
                health_line ok "$(t diag.health_io "$io")"
            fi
        fi
    else
        health_line ok "$(t diag.health_io_na)"
    fi

    # f. Débit réseau de l'interface de la route par défaut (2 lectures espacées de 1 s).
    # Purement informatif (aucun seuil universel de débit) ; skip silencieux si non mesurable.
    iface=$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
    if [ -n "$iface" ] && [ -r /proc/net/dev ]; then
        # Après retrait du préfixe « iface: », RX octets = champ 1 et TX octets = champ 9 (robuste
        # aux vieux noyaux qui collent la première valeur au « : »).
        read -r rx1 tx1 <<< "$(awk -v d="$iface" '{gsub(/^[ \t]+/,""); if (index($0, d ":") == 1) {sub(/^[^:]+:/,""); print $1, $9; exit}}' /proc/net/dev)"
        if [ -n "$rx1" ]; then
            sleep 1
            read -r rx2 tx2 <<< "$(awk -v d="$iface" '{gsub(/^[ \t]+/,""); if (index($0, d ":") == 1) {sub(/^[^:]+:/,""); print $1, $9; exit}}' /proc/net/dev)"
            health_line ok "$(t diag.health_net "$iface" "$(health_rate $((rx2 - rx1)))" "$(health_rate $((tx2 - tx1)))")"
        fi
    fi

    # g. Unités systemd en échec — warn-only, muet quand tout va bien (modèle diag.lock_stuck)
    if command -v systemctl >/dev/null 2>&1; then
        failed=$(systemctl --failed --no-legend --plain 2>/dev/null | awk 'NF{print $1}')
        if [ -n "$failed" ]; then
            n_failed=$(printf '%s\n' "$failed" | wc -l)
            diag_line warn "$(t diag.health_units "$n_failed" "$(printf '%s\n' "$failed" | head -n3 | paste -sd, -)")"
        fi
    fi

    # h. Redémarrage requis (MAJ noyau/libc en attente) — warn-only, muet sinon
    [ -f /var/run/reboot-required ] && diag_line warn "$(t diag.health_reboot)"

    return 0
}

do_diag() {
    [ -t 1 ] && OUTPUT_MODE=ansi      # tags [ OK ]/[WARN]/[FAIL] colorés au terminal (sev_ansi ; plain sinon)
    t diag.header
    run_diag_checks
    # Moyennes 24 h uniquement sur demande explicite (--avg) : diag reste l'état COURANT par défaut.
    [ "$SHOW_AVG24" = true ] && build_metrics_averages
    # Bilan
    echo ""
    if [ "$DIAG_PROBLEMS" -eq 0 ]; then t diag.tally_clean; exit 0; fi
    t diag.tally_problems "$DIAG_PROBLEMS"; exit 1
}

# Sous-commande health : les signes vitaux seuls (sans les ~25 contrôles ban-404 de diag).
# Demander explicitement les signes vitaux doit toujours répondre : on force HEALTH_CHECKS
# (une conf HEALTH_CHECKS=false ne désactive que diag et le résumé).
do_health() {
    [ -t 1 ] && OUTPUT_MODE=ansi      # tags colorés au terminal
    t health.header
    HEALTH_CHECKS=true
    run_health_checks
    # Bilan (clés du diagnostic réutilisées)
    echo ""
    if [ "$DIAG_PROBLEMS" -eq 0 ]; then t diag.tally_clean; exit 0; fi
    t diag.tally_problems "$DIAG_PROBLEMS"; exit 1
}

# ---------- --unban <IP|all> : retrait manuel de l'ipset (sans bricoler ipset à la main) ----------
do_unban() {  # $1 = IP | all  (valeur requise, pas de défaut)
    local target="${1:-}" n
    [ -z "$target" ] && { t unban.missing; exit 1; }
    [ "$(id -u)" -ne 0 ] && { t unban.needroot; exit 1; }
    fw_set_exists || { t unban.noset "$IPSET_NAME"; exit 1; }
    if [ "${target,,}" = "all" ]; then
        n=$(fw_count "$IPSET_NAME")
        fw_flush || { t unban.fail "all"; exit 1; }
        t_log unban.all_done "$n"
        escalation_forget all
    elif fw_is_banned "$target"; then
        fw_unban_ip "$target" || { t unban.fail "$target"; exit 1; }
        t_log unban.done "$target"
        # Déban MANUEL = verdict d'innocence de l'admin : le compteur de récidive repart de zéro.
        escalation_forget "$target"
    else
        # L'IP n'est pas dans le set — mais elle peut rester inscrite dans la MÉMOIRE DE RÉCIDIVE :
        # soit son ban a simplement expiré (l'entrée survit ESCALATION_MEMORY après la libération,
        # c'est la période d'épreuve), soit le pare-feu n'a jamais su la stocker (IPv6, cf.
        # fw_addr_supported). Jusqu'en 2.3.7 on sortait ICI, avant escalation_forget : ce passé
        # était donc INEFFAÇABLE, et l'admin n'avait aucun moyen d'accorder l'amnistie à une IP
        # dont le ban avait expiré. « unban » vaut verdict d'innocence dans les deux cas.
        t unban.notfound "$target"
        # Test d'appartenance sur le CHAMP 1 exactement (même comparaison que escalation_forget) :
        # un grep sur la ligne confondrait des IP dont l'une est préfixe de l'autre.
        if [ -f "$OFFENDERS_FILE" ] && awk -v ip="$target" '$1==ip{f=1} END{exit !f}' "$OFFENDERS_FILE" 2>/dev/null; then
            escalation_forget "$target"
            t_log unban.forgotten "$target"
        fi
        exit 0
    fi
    fw_persist
    exit 0
}

# Sous-commandes nues (list, stats, diag, health...) : forme canonique depuis 1.5.0, « -- »
# réservé aux options. Les formes historiques --list/--stats/... restent acceptées À VIE dans la
# même branche du case (crons du parc, scripts, habitudes) ; la complétion ne propose que la
# forme nue. La boucle pose des drapeaux quel que soit l'ordre => cumulables et mélangeables
# (« list stats », « stats --verbose list », « --list stats »...).
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        --show-blocked) SHOW_BLOCKED=true; shift ;;
        --verbose) VERBOSE=true; shift ;;
        --no-log) LOG_EVENTS=false; shift ;;
        --no-health) HEALTH_CHECKS=false; shift ;;
        lang|--lang) change_lang "${2:-}" ;;
        --lang=*) change_lang "${1#*=}" ;;
        --by-timeout) LIST_BY_TIMEOUT=true; shift ;;
        --resolve) RESOLVE_PTR=true; shift ;;
        --avg) SHOW_AVG24=true; shift ;;
        list|--list) DO_LIST=true; shift ;;
        stats|--stats) DO_STATS=true; shift ;;
        summary|--summary) do_summary ;;
        check-notification|--check-notification) check_notification "${2:-all}" ;;
        --check-notification=*) check_notification "${1#*=}" ;;
        diag|--diag) DO_DIAG=true; shift ;;
        health) DO_HEALTH=true; shift ;;
        unban|--unban) do_unban "${2:-}" ;;
        --unban=*) do_unban "${1#*=}" ;;
        version|--version) t version.line "$BAN404_VERSION"; t version.author; exit 0 ;;
        help|--help|-h) show_help ;;
        *) t err.unknown_opt "$1"; exit 1 ;;
    esac
done

# Le dry-run ne journalise jamais (lignes [SIMULATION] [+] => compteurs de --stats faussés).
[ "$DRY_RUN" = true ] && LOG_EVENTS=false

# --- Auto-diagnostic (lecture seule), exécuté APRÈS la boucle de parsing : ainsi --verbose est
# déjà pris en compte par run_diag_checks (détail par dossier) quel que soit l'ordre sur la ligne
# (diag --verbose autant que --verbose diag). do_diag sort. ---
[ "$DO_DIAG" = true ] && do_diag

# --- Signes vitaux seuls (lecture seule). diag les inclut déjà : si les deux sont demandés,
# diag (ci-dessus, qui sort) a la priorité. do_health sort. ---
[ "$DO_HEALTH" = true ] && do_health

# --- Actions de rapport (cumulables) : --stats et/ou --list, puis on sort. ---
if [ "$DO_STATS" = true ] || [ "$DO_LIST" = true ]; then
    [ "$DO_STATS" = true ] && build_stats_text
    [ "$DO_STATS" = true ] && [ "$DO_LIST" = true ] && echo ""
    [ "$DO_LIST" = true ] && do_list
    exit 0
fi

# --- Fail-safe plateforme : sur une plateforme NON validée (distro/back-end inconnus), on force la
#     LECTURE SEULE (aucune écriture ipset/iptables/persistance) plutôt que d'agir de travers. Les
#     sous-commandes lecture seule (diag/stats/list/health, ci-dessus) restent disponibles. Backward-
#     compatible : le parc Debian/Ubuntu + iptables/ipset reste « supporté » => comportement inchangé. ---
if [ "$DRY_RUN" = false ] && ! platform_supported; then
    t_log platform.readonly       # journalisé AVANT de forcer dry-run (LOG_EVENTS encore actif ici)
    DRY_RUN=true
fi

# --- Verrou anti-chevauchement (cron). Inutile en simulation (lecture seule). ---
if [ "$DRY_RUN" = false ]; then
    exec 9>"$LOCK_FILE" || { t lock.open_fail "$LOCK_FILE"; exit 1; }
    if ! flock -n 9; then
        t_log lock.busy "$LOCK_FILE"
        exit 1
    fi
fi

# --- Porte de cadence (CRON_STEP=auto) : sauter les ticks intermédiaires arrivés trop tôt. ---
# Budget minimal exigé (les ticks tournent toutes les 5 min) : un tick « porté » ne fait que
# conf + verrou + deux stat + la sentinelle (tail/awk sur des fins de fichiers en page cache),
# AUCUNE écriture (ni stamp, ni journal, ni métriques) et ne touche ni ipset ni self-heals.
# Jamais appliquée aux runs interactifs (tty) ni au dry-run : un humain qui lance le moteur
# attend une analyse. Marge de 90 s : le jitter cron ne doit pas faire glisser d'un tick un
# passage arrivant « pile » à l'échéance. La sortie « portée » ne stampe pas last_run (qui
# reste = dernier run COMPLET, la référence de la porte ET de la sentinelle).
# Relevé horaire dû => la porte s'ouvre (depuis 2.3.11). Tout run complet — sentinelle, cadence
# resserrée — relance l'horloge last_run, mais ne relève les métriques que si SAMPLE_MIN_INTERVAL
# est écoulé depuis le relevé précédent : un run tombant 30-54 min après un relevé n'en posait
# pas et repoussait le suivant d'un intervalle entier (relevés espacés jusqu'à ~110 min,
# constaté sur un serveur à sentinelle fréquente le 15 sept. 2026). La date du relevé est le
# mtime de METRICS_FILE (écrit par metrics_sample seul). Échéance bornée par SAMPLE_MIN_INTERVAL :
# un run forcé DOIT relever, sinon chaque tick rouvrirait la porte. Fichier absent => pas de
# forçage (le prochain run normal le crée). Pire cas si l'écriture échoue durablement (disque
# plein) : un run complet par tick, soit la cadence fixe 5 min — un mode supporté.
if [ "$DRY_RUN" = false ] && [ ! -t 0 ] && [ ! -t 1 ] && [ "$(cron_step_mode)" = auto ]; then
    LAST_FULL=$(stat -c %Y "$RUN_STAMP_FILE" 2>/dev/null || echo 0)
    if [ "$(date +%s)" -lt $(( LAST_FULL + $(cadence_read) * 60 - 90 )) ]; then
        LAST_SAMPLE=$(stat -c %Y "$METRICS_FILE" 2>/dev/null)
        SAMPLE_DUE=$(( 3600 - 90 )); [ "${SAMPLE_MIN_INTERVAL:-0}" -gt "$SAMPLE_DUE" ] 2>/dev/null && SAMPLE_DUE=$SAMPLE_MIN_INTERVAL
        if [[ "$LAST_SAMPLE" =~ ^[0-9]+$ ]] && [ "$(date +%s)" -ge $(( LAST_SAMPLE + SAMPLE_DUE )) ]; then
            :   # relevé horaire dû : run complet
        elif sentinel_hit "$(date -d "@$LAST_FULL" '+%Y%m%d%H%M%S')"; then
            t_log sentinel.triggered
        else
            exit 0
        fi
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
# Chaque lookup est borné par PTR_TIMEOUT (via reverse_dns / timeout) : les IP de botnet
# ont massivement des PTR morts, et un getent non borné attend le timeout du résolveur
# (5-10 s) — sur un run de rattrapage à ~1000 candidats, cela coûtait ~45 min de DNS.
is_legit_crawler() {
    local ip="$1" rdns
    rdns=$(reverse_dns "$ip" | tr 'A-Z' 'a-z')
    [ -z "$rdns" ] && return 1

    case "$rdns" in
        *.googlebot.com|*.google.com|*.search.msn.com|*.bing.com|\
        *.yandex.com|*.yandex.net|*.yandex.ru|\
        *.apple.com|*.applebot.apple.com|*.baidu.com) ;;
        *) return 1 ;;
    esac

    # Forward-confirmed : l'IP d'origine doit figurer parmi les adresses du hostname
    if command -v timeout >/dev/null 2>&1; then
        timeout "${PTR_TIMEOUT:-2}" getent ahosts "$rdns" 2>/dev/null | awk '{print $1}' | grep -qxF "$ip" || return 1
    else
        getent ahosts "$rdns" 2>/dev/null | awk '{print $1}' | grep -qxF "$ip" || return 1
    fi

    echo "$rdns"
    return 0
}

# L'IP tombe-t-elle dans une plage d'où PEUT venir un crawler légitime ? Test PUREMENT local
# (comparaisons de préfixes en Bash, aucun fork, aucun DNS) : il ne dit PAS que l'IP est un
# crawler, seulement qu'il vaut la peine de payer le FCrDNS pour le vérifier. Voir
# CRAWLER_HINT_PREFIXES.
crawler_hint() {  # $1 = IP
    local p
    [ -n "${CRAWLER_HINT_PREFIXES// /}" ] || return 1
    for p in $CRAWLER_HINT_PREFIXES; do
        case "$1" in "$p"*) return 0 ;; esac
    done
    return 1
}

# Même liste, sous forme de regex ancrée, pour filtrer un FLUX de membres en un seul grep (le
# balayage à froid ci-dessous traite des dizaines de milliers de lignes : une boucle Bash par
# membre y coûterait des secondes, un grep quelques millisecondes). Construite à la demande.
crawler_hint_re() {
    local p re=""
    for p in $CRAWLER_HINT_PREFIXES; do re="$re|^${p//./\\.}"; done
    printf '%s' "${re#|}"
}

# --- Débannissement à froid des crawlers légitimes ---------------------------
# Pendant du enforce_whitelist_unban, pour le cas symétrique : une IP de crawler bannie À TORT
# n'est JAMAIS libérée toute seule, car une IP droppée ne produit plus de requêtes -> elle ne
# réapparaît plus dans les candidats -> le FCrDNS de la boucle ne la revoit jamais. Elle purge
# donc son ban entier (7 j sur le circuit honeypot). Ce balayage la rattrape à froid.
# Coût maîtrisé : un seul grep pré-filtre les membres (aucun DNS pour l'écrasante majorité), et
# seuls les rares candidats retenus paient le FCrDNS, dans la limite de CRAWLER_SCAN_MAX.
enforce_crawler_unban() {
    local ip dom removed=false n=0 re
    re=$(crawler_hint_re)
    [ -n "$re" ] || return 0
    while read -r ip; do
        [ -z "$ip" ] && continue
        if [ "$n" -ge "${CRAWLER_SCAN_MAX:-100}" ]; then
            [ "$VERBOSE" = true ] && t crawler.scan_capped "$CRAWLER_SCAN_MAX"
            break
        fi
        n=$((n + 1))
        dom=$(is_legit_crawler "$ip") || continue
        if [ "$DRY_RUN" = true ]; then
            t crawler.sim_cold_unban "$ip" "$dom"
        elif fw_unban_ip "$ip"; then
            t_log unban.crawler_cold "$ip" "$dom"; removed=true
            escalation_forget "$ip"   # acquitté par FCrDNS => son passé de récidiviste n'a plus de sens
        fi
    done < <(fw_list_members | grep -E "$re")
    [ "$removed" = true ] && fw_persist
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
    # Préfixe « 1_ » : run-parts exécute cron.daily en ordre lexicographique, et l'ancien nom
    # ban_404_summary passait AVANT ban_404_update — le résumé partait avec les versions de la
    # veille (faux [WARN] « MAJ dispo »). Avec 0_ban_404_update (renommé par l'updater >= 1.2.12)
    # et 1_ban_404_summary, l'updater précède toujours le résumé.
    local f="/etc/cron.daily/1_ban_404_summary" legacy="/etc/cron.daily/ban_404_summary"
    [ "$DRY_RUN" = true ] && return 0
    [ "$(id -u)" -eq 0 ] || return 0
    # Migration one-shot de l'ancien nom (contenu identique : simple renommage ; si DAILY_SUMMARY
    # est désactivé, le case retire ensuite le fichier renommé comme n'importe quel orphelin).
    if [ -f "$legacy" ]; then
        mv -f "$legacy" "$f" 2>/dev/null && t_log heal.summary_cron_renamed "$f"
    fi
    # Contenu canonique (syntaxe sous-commande depuis 1.5.0 ; --summary reste accepté, mais on
    # aligne le parc). Comparé au fichier en place : différent => réécrit (migre les anciens
    # « --summary » et guérit un wrapper corrompu), identique => rien (idempotent).
    local want
    want=$(printf '%s\n%s\n' '#!/bin/sh' 'exec /usr/local/sbin/ban_404.sh summary')
    case "$DAILY_SUMMARY" in
        true|1|yes|on)
            if [ -f "$f" ]; then
                [ "$(cat "$f" 2>/dev/null)" = "$want" ] && return 0   # déjà conforme => rien à faire
                printf '%s\n' "$want" > "$f" && chmod 755 "$f" && t_log heal.summary_cron_syntax "$f"
                return 0
            fi
            printf '%s\n' "$want" > "$f"
            chmod 755 "$f" && t heal.summary_cron "$f" ;;
        *)
            [ -f "$f" ] || return 0                   # déjà absent => rien à faire
            rm -f "$f" && t heal.summary_cron_removed "$f" ;;
    esac
    return 0
}

# Réconciliation du cron de ticks intermédiaires sur CRON_STEP (même modèle que le cron de
# résumé : le moteur est seul maître du fichier, contenu canonique, idempotent). /etc/cron.d
# exige un champ utilisateur, un nom SANS point et une fin de fichier avec saut de ligne ;
# 0644 (fichier de conf, PAS exécutable, contrairement à cron.hourly/daily). nice -n 10 : les
# ticks (sentinelle comprise) s'effacent devant les vrais services du serveur. Un changement de
# réglage (10 -> 15, fixe -> auto...) fait diverger le canonique => réécriture ; valeur vide ou
# invalide => retrait (fail-safe : on retombe sur l'horaire), l'état de cadence partant avec.
self_heal_step_cron() {
    local f="/etc/cron.d/ban_404_step" mode step want
    [ "$DRY_RUN" = true ] && return 0
    [ "$(id -u)" -eq 0 ] || return 0
    mode=$(cron_step_mode)
    if [ "$mode" = off ]; then
        [ -f "$f" ] || return 0
        rm -f "$f" "$CADENCE_FILE" 2>/dev/null && t_log heal.step_cron_removed "$f"
        return 0
    fi
    step=5; [ "$mode" = fixed ] && step="$CRON_STEP"   # auto : tick plancher 5 min, la porte module
    want=$(printf '%s\n%s\n' \
        "# ban_404 : ticks intermédiaires (CRON_STEP=${CRON_STEP}) — fichier géré par le moteur (self_heal_step_cron), ne pas éditer." \
        "*/${step} * * * * root nice -n 10 /usr/local/sbin/ban_404.sh >/dev/null 2>&1")
    if [ -f "$f" ]; then
        [ "$(cat "$f" 2>/dev/null)" = "$want" ] && return 0   # déjà conforme => rien à faire
        printf '%s\n' "$want" > "$f" && chmod 644 "$f" && t_log heal.step_cron_syntax "$f"
        return 0
    fi
    printf '%s\n' "$want" > "$f" && chmod 644 "$f" && t_log heal.step_cron "$f" "$CRON_STEP"
    return 0
}

# Rotation du journal : passage de weekly/rotate 8 (canonique historique de l'installeur) à
# daily/rotate 14. Motif : une rotation HEBDOMADAIRE coupe la fenêtre 24 h du résumé une fois par
# semaine, avec un log courant de quelques heures seulement face à un fichier rotaté d'une semaine
# entière — c'est le pire des cas pour les compteurs (stats_log_stream rattrape désormais le
# rotaté, mais un fichier quotidien reste plus sain à parcourir et borne la perte à 1 jour).
# Migration ONE-SHOT et NON DESTRUCTIVE : on ne réécrit que si le fichier correspond exactement à
# l'ancien canonique (weekly + rotate 8) — une conf personnalisée par l'admin est laissée intacte,
# et le chemin surveillé est REPRIS du fichier en place (jamais réinventé). Idempotent : une fois
# en daily, la garde weekly ne matche plus et la fonction ne fait plus rien.
self_heal_logrotate() {
    local f="/etc/logrotate.d/ban_404" path
    [ "$DRY_RUN" = true ] && return 0
    [ "$(id -u)" -eq 0 ] || return 0
    [ -f "$f" ] || return 0
    grep -qE '^[[:space:]]*weekly[[:space:]]*$' "$f" 2>/dev/null || return 0
    grep -qE '^[[:space:]]*rotate[[:space:]]+8[[:space:]]*$' "$f" 2>/dev/null || return 0
    path=$(awk -F'{' 'NF>1 { gsub(/^[ \t]+|[ \t]+$/, "", $1); print $1; exit }' "$f" 2>/dev/null)
    [ -n "$path" ] || path="$LOG_FILE"
    cat > "$f" <<EOF
$path {
    daily
    rotate 14
    compress
    missingok
    notifempty
}
EOF
    chmod 644 "$f" 2>/dev/null && t_log heal.logrotate_daily "$f"
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

# --- Échantillon horaire des métriques (pour les moyennes 24 h du résumé) -----------------
# Appelé uniquement depuis finish_run (donc sous la garde DRY_RUN=false + root, comme le stamp).
# AUCUN sleep : on relève des compteurs BRUTS (cumulatifs pour IO/réseau, instantanés pour
# load/mémoire), le débit/la pression moyens se déduisent par delta au moment du résumé. Une
# ligne = 6 colonnes « epoch load15 io_total_µs rx tx mem_avail_pct » ; « - » si non mesurable
# (le calcul awk saute ce champ). Purge-on-write : on ne garde que les lignes < 48 h et bien
# formées, réécriture atomique (mktemp + mv). Toujours return 0 : ne fait jamais échouer le run.
metrics_sample() {
    local now load15 io_total iface rx tx mem_avail mem_total mem_pct dir tmp last
    now=$(date +%s)
    # Garde d'espacement : avec CRON_STEP le moteur peut finir un run complet toutes les 5-10 min,
    # mais l'historique doit rester ~horaire (les moyennes 24 h et la fenêtre de purge supposent
    # ~1 point/heure). Fichier chronologique => l'epoch de la DERNIÈRE ligne suffit.
    last=$(tail -n 1 "$METRICS_FILE" 2>/dev/null | awk '{print $1}')
    [[ "$last" =~ ^[0-9]+$ ]] && [ $((now - last)) -lt "$SAMPLE_MIN_INTERVAL" ] && return 0
    load15='-'; [ -r /proc/loadavg ] && read -r _ _ load15 _ < /proc/loadavg
    [ -n "$load15" ] || load15='-'
    io_total='-'
    if [ -r /proc/pressure/io ]; then
        io_total=$(awk '/^some/{for(i=2;i<=NF;i++) if($i ~ /^total=/){sub(/^total=/,"",$i); print $i; exit}}' /proc/pressure/io 2>/dev/null)
        [ -n "$io_total" ] || io_total='-'
    fi
    rx='-'; tx='-'
    iface=$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')
    if [ -n "$iface" ] && [ -r /proc/net/dev ]; then
        read -r rx tx <<< "$(awk -v d="$iface" '{gsub(/^[ \t]+/,""); if (index($0, d ":") == 1) {sub(/^[^:]+:/,""); print $1, $9; exit}}' /proc/net/dev)"
        { [ -n "$rx" ] && [ -n "$tx" ]; } || { rx='-'; tx='-'; }
    fi
    mem_pct='-'
    if [ -r /proc/meminfo ]; then
        mem_avail=$(awk '/^MemAvailable:/{print $2; exit}' /proc/meminfo 2>/dev/null)
        mem_total=$(awk '/^MemTotal:/{print $2; exit}' /proc/meminfo 2>/dev/null)
        [ -n "$mem_avail" ] && [ -n "$mem_total" ] && [ "$mem_total" -gt 0 ] 2>/dev/null && mem_pct=$(( mem_avail * 100 / mem_total ))
    fi
    dir=$(dirname "$METRICS_FILE"); mkdir -p "$dir" 2>/dev/null
    tmp=$(mktemp "$dir/.metrics.XXXXXX" 2>/dev/null) || return 0
    {
        [ -f "$METRICS_FILE" ] && awk -v cut=$((now - 172800)) 'NF>=6 && $1 ~ /^[0-9]+$/ && $1+0>=cut' "$METRICS_FILE" 2>/dev/null
        printf '%s %s %s %s %s %s\n' "$now" "$load15" "$io_total" "$rx" "$tx" "$mem_pct"
    } > "$tmp" 2>/dev/null
    chmod 644 "$tmp" 2>/dev/null
    mv -f "$tmp" "$METRICS_FILE" 2>/dev/null || rm -f "$tmp" 2>/dev/null
    return 0
}

# --- Échantillon horaire du nb d'entrées par ipset (pour l'évol. + tendance 24 h du résumé) ----
# Même style que metrics_sample : appelé depuis finish_run (garde DRY_RUN=false + root), AUCUN sleep
# (on relève les compteurs bruts), écriture atomique mktemp + mv, purge-on-write des lignes < 48 h.
# Une ligne = 3 colonnes « epoch setname count » ; toutes les listes d'un passage partagent l'epoch
# (base 24 h commune). Énumère via fw_list_sets (le set transitoire ${IPSET_NAME}_grow est déjà
# écarté par le backend). Comptage sans dump via fw_count. Toujours return 0.
ipset_counts_sample() {
    local now dir tmp name count last
    now=$(date +%s)
    # Même garde d'espacement que metrics_sample : la sparkline « Évolution 8 h » (8 derniers
    # points) suppose ~1 point/heure — sans la garde, un CRON_STEP serré la réduirait à ~40 min.
    last=$(tail -n 1 "$IPSET_COUNTS_FILE" 2>/dev/null | awk '{print $1}')
    [[ "$last" =~ ^[0-9]+$ ]] && [ $((now - last)) -lt "$SAMPLE_MIN_INTERVAL" ] && return 0
    dir=$(dirname "$IPSET_COUNTS_FILE"); mkdir -p "$dir" 2>/dev/null
    tmp=$(mktemp "$dir/.ipsetcnt.XXXXXX" 2>/dev/null) || return 0
    {
        [ -f "$IPSET_COUNTS_FILE" ] && awk -v cut=$((now - 172800)) 'NF==3 && $1 ~ /^[0-9]+$/ && $1+0>=cut' "$IPSET_COUNTS_FILE" 2>/dev/null
        while IFS= read -r name; do
            [ -n "$name" ] || continue
            count=$(fw_count "$name")
            printf '%s %s %s\n' "$now" "$name" "$count"
        done < <(fw_list_sets)
    } > "$tmp" 2>/dev/null
    chmod 644 "$tmp" 2>/dev/null
    mv -f "$tmp" "$IPSET_COUNTS_FILE" 2>/dev/null || rm -f "$tmp" 2>/dev/null
    return 0
}

# --- Fin de run commune : repère de fraîcheur + filet MAJ --------------------------------
# Appelée sur TOUTES les fins de run réelles, y compris les sorties anticipées SAINES (aucun
# log valide, aucun suspect dans la fenêtre) : un run « rien à faire » est un run COMPLET.
# Sans cela, les heures creuses d'un serveur calme laissaient vieillir RUN_STAMP_FILE et
# déclenchaient un faux [WARN] « cron.hourly en panne » (fraîcheur >= 3 h) dans diag et le
# résumé — et le filet MAJ (36 h) ne s'armait jamais sur ces serveurs. Seules les morts en
# route (erreur, verrou occupé) ne stampent pas. Le filet reste en dernier : si l'updater
# remplace ce script (bascule atomique = nouvel inode), le process courant n'est pas affecté.
# Neutre en dry-run et non-root.
finish_run() {
    if [ "$DRY_RUN" = false ] && [ "$(id -u)" -eq 0 ]; then
        mkdir -p "$(dirname "$RUN_STAMP_FILE")" 2>/dev/null
        touch "$RUN_STAMP_FILE" 2>/dev/null
        metrics_sample                      # échantillon horaire (moyennes 24 h) ; même garde DRY_RUN+root
        ipset_counts_sample                 # échantillon horaire du nb d'entrées par ipset (évol. + tendance 24 h)
        # Cadence auto : ne compter QUE les bans « réels » (hp=0, flood volume-404) — pas le bruit du
        # circuit honeypot (hp=1 : honeypot + signatures SECURITY/POST-flood). Le scan de fond d'un
        # mutualisé bannit une nouvelle IP honeypot toutes les ~10-15 min ; le compter épinglait la
        # cadence au plancher en permanence (l'accalmie n'était jamais atteinte). Voir cadence_adjust.
        local _cad_real=0 _cad_b
        for _cad_b in "${new_bans[@]}"; do [ "${_cad_b##*|}" = 0 ] && _cad_real=$((_cad_real + 1)); done
        cadence_adjust "$_cad_real"         # hystérésis du mode CRON_STEP=auto (no-op sinon)
    fi
    self_heal_update_trigger
    return 0
}

# --- Wrapper cron horaire : lanceur muet ------------------------------------------------
# Depuis 1.4.28 le moteur journalise LUI-MÊME ses événements dans LOG_FILE (log_line) : le
# wrapper historique (qui horodatait tout stdout vers le log) ferait DOUBLON. Ce self-heal
# migre le wrapper vers sa forme canonique « exec … >/dev/null » au premier passage.
# Anti-doublon de transition : si l'ancien wrapper vient d'être détecté ET que stdout n'est
# pas un terminal (ce run a donc très probablement été lancé par l'ancien wrapper, qui
# journalise encore son stdout), on coupe LOG_EVENTS pour CE run — dès le suivant, le
# nouveau wrapper est en place. Neutre en dry-run ; sans effet si déjà migré.
self_heal_hourly_cron() {
    local f="/etc/cron.hourly/ban_404"
    [ "$DRY_RUN" = true ] && return 0
    [ "$(id -u)" -eq 0 ] || return 0
    [ -f "$f" ] || return 0                                   # pas de cron horaire : rien à migrer
    grep -q 'while IFS= read' "$f" 2>/dev/null || return 0    # déjà canonique
    cat > "$f" <<'EOF'
#!/bin/sh
# Depuis ban_404 1.4.28, le moteur journalise lui-même ses événements dans /var/log/ban_404.log.
exec /usr/local/sbin/ban_404.sh >/dev/null 2>&1
EOF
    chmod 755 "$f"
    [ -t 1 ] || LOG_EVENTS=false
    return 0
}
# Appelé AVANT le premier événement possible du run (l'auto-agrandissement ipset ci-dessous),
# pour que l'anti-doublon de transition couvre tout le run.
self_heal_hourly_cron

if [ "$DRY_RUN" = false ]; then
    # Bascule migratoire de backend (one-shot, fail-safe) : si l'admin a changé FW_BACKEND, on
    # transfère les bans vers le nouveau backend AVANT de démonter l'ancien (jamais de trou).
    fw_migrate_if_needed
    # Mise en place de l'infra du backend ACTIF : création du set + insertion de NOTRE règle DROP
    # (idempotent) ; en iptables, auto-agrandissement one-shot des sets pré-1.4.26 (maxelem 65536
    # -> 1048576, saturable en < 1 j sous botnet, ajouts refusés EN SILENCE une fois plein). Voir
    # fw_ensure_infra / ipt_ensure_infra / nft_ensure_infra dans la couche fw_*.
    fw_ensure_infra
fi

# Débannissement actif des IP whitelistées déjà présentes dans le set (avant l'analyse,
# pour s'appliquer même s'il n'y a aucun nouveau suspect ce passage-ci).
enforce_whitelist_unban

# Idem pour les crawlers légitimes bannis à tort : eux ne reviennent JAMAIS dans les candidats
# (une IP droppée ne produit plus de requêtes), donc seul un balayage à froid peut les libérer.
enforce_crawler_unban

# Auto-guérison éventuelle de l'updater legacy (one-shot ; sans effet si déjà moderne).
self_heal_updater

# Réconciliation du cron de résumé quotidien sur DAILY_SUMMARY (le crée/retire selon le réglage).
self_heal_summary_cron

# Réconciliation du cron de ticks intermédiaires sur CRON_STEP (créé/aligné/retiré selon la conf).
self_heal_step_cron

# Rotation du journal : migration one-shot weekly/8 -> daily/14 (sans effet si déjà migrée ou
# personnalisée). Une rotation hebdomadaire amputait la fenêtre 24 h du résumé une fois par semaine.
self_heal_logrotate

# 1-2. Recherche + filtrage des fichiers de logs (factorisés dans discover_valid_logs, partagés
# avec la sentinelle du mode CRON_STEP=auto). Un run déclenché par la sentinelle refait la
# découverte ici : quelques ls, négligeable devant l'analyse qui suit.
discover_valid_logs

if [ ${#VALID_FILES[@]} -eq 0 ]; then
    t no_valid_files
    finish_run   # fin saine : stamp de fraîcheur + filet MAJ (l'anomalie logs est vue par diag)
    exit 0
fi

# Borne basse de la fenêtre, au format AAAAMMJJHHMMSS (comparable directement, sans mktime) ;
# l'affichage --verbose reprend le même instant en date/heure lisible
CUTOFF_EPOCH=$(( $(date +%s) - WINDOW ))
CUTOFF=$(date -d "@$CUTOFF_EPOCH" '+%Y%m%d%H%M%S')
[ "$VERBOSE" = true ] && t verbose.analyzing "${TAIL_LINES}" "$(date -d "@$CUTOFF_EPOCH" '+%Y-%m-%d %H:%M:%S %Z')"

# 3. Extraction et tri via awk
#    - tail -q : seulement les dernières lignes de CHAQUE log (borne le coût)
#    - whitelist en correspondance EXACTE (split sur |)
#    - fenêtre temporelle (on ignore les lignes trop vieilles)
#    - insensibilité à la casse via tolower() (le flag /i n'existe pas en awk)
#    - filtre anti-bruit + honeypots (sur les 404) ; signatures sécurité + flood POST
#      (quel que soit le statut HTTP), seuils/motifs surchargeables via la conf.
#    Les motifs passent par ENVIRON (pas -v) : pas de re-traitement des échappements
#    (\.  reste \.) ; les seuils numériques passent par -v.
#    Signatures et flood POST ne testent que $7 (la requête) — jamais $0 : le referer
#    d'un visiteur arrivant depuis une URL piégée ne doit pas le faire bannir.
ips_data=$(tail -n "$TAIL_LINES" -q "${VALID_FILES[@]}" | \
    HONEYPOT_RE="$HONEYPOT_PATTERN" NOISE_RE="$NOISE_PATTERN" \
    SECURITY_RE="$SECURITY_PATTERN" POSTFLOOD_RE="$POST_FLOOD_PATTERN" \
    awk -v wl="$WHITELIST_IP" -v cutoff="$CUTOFF" -v thr="$BAN_THRESHOLD" -v hp="$HONEYPOT_SCORE" \
        -v pf_thr="$POST_FLOOD_THRESHOLD" -v dmin="$DISTINCT_PATH_MIN" '
BEGIN {
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", M, " ")
    for (i=1;i<=12;i++) mon[M[i]]=i
    n=split(wl, Wl, "|"); for (i=1;i<=n;i++) white[Wl[i]]=1
    noise_re = ENVIRON["NOISE_RE"]
    honeypot_re = ENVIRON["HONEYPOT_RE"]
    security_re = ENVIRON["SECURITY_RE"]
    postflood_re = ENVIRON["POSTFLOOD_RE"]
}
# Garde rapide : seules les lignes candidates (404, signature sécurité, POST surveillé)
# paient le parse de date qui suit.
!($1 in white) && ($9 == 404 || (security_re != "" && tolower($7) ~ security_re) || \
                   (postflood_re != "" && $6 ~ /POST/ && tolower($7) ~ postflood_re)) {

    # --- Fenêtre temporelle : $4 = [jj/Mon/aaaa:hh:mm:ss ---
    split(substr($4,2), d, /[\/:]/)
    ts = sprintf("%04d%02d%02d%02d%02d%02d", d[3], mon[d[2]], d[1], d[4], d[5], d[6])
    if (ts < cutoff) next

    p = tolower($7)

    # --- S. Signature sécurité (tout statut) : +HONEYPOT_SCORE (ban immédiat) ---
    if (security_re != "" && p ~ security_re) { count[$1] += hp; flag[$1]=1; next }

    # --- P. Flood POST (tout statut) : compté ici, seuil appliqué en END ---
    if (postflood_re != "" && $6 ~ /POST/ && p ~ postflood_re) { post[$1]++; next }

    if ($9 != 404) next

    # --- A. Bruit de fond (faux positifs) ---
    if (p ~ noise_re) next

    # --- B. Honeypots : +HONEYPOT_SCORE (ban quasi immédiat) ---
    if (p ~ honeypot_re) {
        count[$1] += hp; flag[$1]=1
    } else {
        count[$1]++
        # Diversite des chemins (DISTINCT_PATH_MIN) : un scanner balaie des chemins VARIES, un
        # navigateur bloque sur un asset manquant martele UNE SEULE URL. La query est retiree,
        # sinon un cache-buster (?v=123) fabriquerait un chemin neuf a chaque hit et masquerait la
        # repetition. On cesse de memoriser des que dmin est atteint : la reponse ne peut plus
        # changer, et la memoire de awk reste bornee a dmin entrees par IP, meme sous botnet.
        if (dmin > 1 && dpath[$1] < dmin) {
            b = p; sub(/\?.*/, "", b)
            k = $1 SUBSEP b
            if (!(k in seenp)) { seenp[k] = 1; dpath[$1]++ }
        }
    }
}
END {
    # Le score intègre le NOMBRE de POST (et pas seulement le forfait +HONEYPOT_SCORE) : sans lui,
    # un brute-force de 3000 POST scorait comme celui de 21 — même durée de ban, et surtout dernier
    # du « Top honeypot » du résumé, sous une IP ayant tapé 3 chemins-pièges. Un POST vaut 1 point,
    # comme un 404 ordinaire. Ne change AUCUNE décision de ban (le forfait dépasse déjà le seuil),
    # seulement le classement du Top honeypot et le palier atteint (AGGRESSIVE_SCORE, 2.3.0).
    # NB : aucune apostrophe dans ce bloc, il vit dans une chaine awk en quotes simples.
    for (x in post) if (post[x] > pf_thr) { count[x] += hp + post[x]; flag[x]=1 }
    # 3e champ = drapeau honeypot/sécurité/POST-flood : consommé par la boucle pour SAUTER le
    # FCrDNS (un crawler légitime ne déclenche jamais ces motifs) — voir is_legit_crawler.
    for (ip in count) if (count[ip] > thr && (flag[ip] || dmin <= 1 || dpath[ip] >= dmin)) print count[ip], (flag[ip] ? 1 : 0), ip
}' | sort -k1,1rn -k3,3V)

if [ -z "$ips_data" ]; then
    [ "$VERBOSE" = true ] && t no_suspect
    finish_run   # fin saine (la plus fréquente sur un serveur calme) : stamp + filet MAJ
    exit 0
fi

changes_made=false
rules_simulated=0
new_bans=()   # accumulés pour la notification (format : "ip|score|honeypot")
# Tableau PARALLÈLE à new_bans (format : "ip epoch_fin_du_ban"), consommé par escalation_record.
# Volontairement séparé : le format de new_bans est lu ailleurs par la fin (${b##*|} = le drapeau
# honeypot, cf. finish_run) et par maybe_notify_new_bans — y ajouter des champs casserait les deux.
esc_records=()
esc_now=$(date +%s)   # base commune des dates de fin de ban du run
# Récidives connues pour les seules IP candidates : UN passage awk sur le fichier d'état, avant la
# boucle (et non une lecture par IP). Table associative « ip -> nb de bans antérieurs ».
declare -A ESC_SEEN=()
while read -r _esc_ip _esc_n; do
    [ -n "$_esc_ip" ] && ESC_SEEN["$_esc_ip"]="$_esc_n"
done < <(printf '%s\n' "$ips_data" | awk '{print $3}' | escalation_lookup)
[ "$VERBOSE" = true ] && t verbose.processing

# 4. Boucle de traitement
unsupported_addr=0   # candidates écartées faute de support de leur famille d'adresse (IPv6)
while read -r count hpflag ip; do
    [ -z "$ip" ] && continue

    # Famille d'adresse que le backend ne sait pas stocker (IPv6) : on l'écarte AVANT toute
    # décision. Sans ce garde-fou, on journalisait un ban et on alimentait la mémoire de récidive
    # pour une IP qui restait libre (cf. fw_addr_supported). On compte pour un récapitulatif
    # unique en fin de run plutôt qu'une ligne par IP, qui inonderait le journal sous un scan.
    if ! fw_addr_supported "$ip"; then
        unsupported_addr=$((unsupported_addr + 1))
        continue
    fi

    # FCrDNS (épargne des crawlers légitimes). Le lookup PTR (borné à PTR_TIMEOUT) est coûteux :
    # sur un ex-serveur botnet (des centaines d'IP sans PTR à 2 s chacune), le payer pour tout le
    # monde faisait passer un run de quelques secondes à ~30 min. On le paie donc toujours pour un
    # ban « volume 404 », et pour un ban du circuit honeypot/sécurité (hpflag=1) SEULEMENT si
    # l'IP tombe dans une plage de crawler connue (crawler_hint, test local sans DNS).
    # Le postulat d'origine — « un vrai crawler n'atteint JAMAIS une signature sécurité » — est
    # FAUX : PrestaShop empile lui-même le paramètre resultsPerPage dans ses liens de facettes, et
    # Googlebot/Bingbot suivent ces URL. Sans ce garde-fou, 7 IP Googlebot et 1 Bingbot ont été
    # bannies 7 j sur le parc (constaté le 31 juil. 2026), sans aucun moyen d'en sortir.
    if [ "$hpflag" = 1 ] && ! crawler_hint "$ip"; then
        crawler_domain=""; is_crawler=1
    else
        crawler_domain=$(is_legit_crawler "$ip"); is_crawler=$?
    fi
    if [ "$is_crawler" -eq 0 ]; then
        if [ "$DRY_RUN" = false ] && fw_is_banned "$ip"; then
            t_log unban.crawler "$ip" "$crawler_domain" "$count"
            fw_unban_ip "$ip"
            escalation_forget "$ip"   # acquitté par FCrDNS => son passé de récidiviste n'a plus de sens
            changes_made=true
        elif [ "$DRY_RUN" = true ] && fw_is_banned "$ip"; then
            t sim.unban "$ip" "$crawler_domain"
            rules_simulated=$((rules_simulated + 1))
        else
            [ "$SHOW_BLOCKED" = true ] && t skip.crawler "$ip"
        fi
        continue
    fi

    # Whitelist CIDR : même logique que les crawlers (deban si présent, sinon skip)
    if in_whitelist_cidr "$ip"; then
        if [ "$DRY_RUN" = false ] && fw_is_banned "$ip"; then
            t_log cidr.unban "$ip" "$count"
            fw_unban_ip "$ip"
            escalation_forget "$ip"   # whitelistée => son passé de récidiviste n'a plus de sens
            changes_made=true
        elif [ "$DRY_RUN" = true ] && fw_is_banned "$ip"; then
            t cidr.sim_unban "$ip"
            rules_simulated=$((rules_simulated + 1))
        else
            [ "$SHOW_BLOCKED" = true ] && t cidr.skip "$ip"
        fi
        continue
    fi

    if fw_is_banned "$ip"; then
        [ "$SHOW_BLOCKED" = true ] && t already.banned "$ip" "$count"
    else
        # Durée du ban : base du circuit au 1er ban (comportement historique EXACT), palier plus
        # long dès la 1re récidive ou d'emblée pour un score >= AGGRESSIVE_SCORE. Le niveau
        # « nominal » (celui d'une IP inconnue et non agressive) vaut 1 sur le circuit honeypot et
        # 0 sur un flood : au-delà, on journalise la variante qui porte le rang et la durée.
        [ "$count" -ge "$HONEYPOT_SCORE" ] && hp=1 || hp=0
        esc_rec="${ESC_SEEN[$ip]:-0}"
        read -r esc_ttl esc_level <<< "$(escalation_ttl "$count" "$hp" "$esc_rec")"
        if [ "$DRY_RUN" = true ]; then
            if [ "$hp" = 1 ]; then
                t sim.ban_honeypot "$ip" "$count"
            else
                t sim.ban_add "$ip" "$count"
            fi
            [ "$esc_level" -gt "$hp" ] && t sim.ban_escalated "$((esc_rec + 1))" "$(fmt_duration "$esc_ttl")"
            rules_simulated=$((rules_simulated + 1))
        else
            # ORDRE CRITIQUE : on bannit D'ABORD, on journalise ENSUITE. Jusqu'en 2.3.6 la ligne
            # [+] partait avant l'appel et le code de retour était ignoré : un refus du pare-feu
            # (adresse IPv6 sur un set inet, set plein, erreur ipset) produisait un ban JOURNALISÉ,
            # COMPTÉ et MÉMORISÉ en récidive, alors qu'aucun paquet n'était bloqué.
            # Toujours un timeout PAR ENTRÉE : au niveau nominal d'un flood il vaut exactement
            # BAN_TIMEOUT, soit le défaut du set — aucun changement observable.
            if fw_ban_ip_ttl "$ip" "$esc_ttl"; then
                if [ "$hp" = 1 ]; then
                    if [ "$esc_level" -gt 1 ]; then t_log ban.honeypot_esc "$ip" "$count" "$((esc_rec + 1))" "$(fmt_duration "$esc_ttl")"
                    else                            t_log ban.honeypot     "$ip" "$count"; fi
                else
                    if [ "$esc_level" -gt 0 ]; then t_log ban.add_esc "$ip" "$count" "$((esc_rec + 1))" "$(fmt_duration "$esc_ttl")"
                    else                            t_log ban.add     "$ip" "$count"; fi
                fi
                changes_made=true
                new_bans+=("$ip|$count|$hp")
                esc_records+=("$ip $((esc_now + esc_ttl))")   # mémoire datée sur la FIN du ban
            else
                t_log ban.failed "$ip"
            fi
        fi
    fi
done <<< "$ips_data"

# Candidates écartées faute de support de leur famille d'adresse : une seule ligne [i], et
# seulement s'il y en a eu (zéro bruit sur un serveur sans trafic IPv6, c'est-à-dire le cas
# général du parc). Marqueur [i] : informatif, jamais compté par les statistiques 24 h.
if [ "$unsupported_addr" -gt 0 ]; then
    t_log ban.family_unsupported "$unsupported_addr"
fi

# Mémoire des récidives : un seul awk (fusion + purge) + bascule atomique, jamais en dry-run.
escalation_record

# 5. Sauvegarde
[ "$VERBOSE" = true ] && t verbose.result_header
if [ "$DRY_RUN" = true ]; then
    t result.sim "$rules_simulated"
else
    if [ "$changes_made" = true ]; then
        [ "$VERBOSE" = true ] && t verbose.changes_saved
        fw_persist
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

# Fin de run nominale : repère de fraîcheur (lu par --diag et le résumé quotidien) + filet de
# sécurité MAJ. Voir finish_run — les sorties anticipées saines (aucun log, aucun suspect)
# passent par le même chemin.
finish_run
