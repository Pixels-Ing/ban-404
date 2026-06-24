# ban-404

Ban automatique des IP qui génèrent un flood de 404 (scanners, brute-force de
chemins) sur des serveurs Apache multi-sites, via **ipset + iptables**.
Détection sur fenêtre glissante, honeypots (`.env`, `wp-config.php`…),
exclusion du bruit (assets, favicon, robots.txt…), crawlers légitimes épargnés
par **FCrDNS** (reverse DNS confirmé). Persistance au reboot via
`ipset-persistent`. Mise à jour centralisée par auto-pull (`cron.daily`).
Messages **multilingues** (en, fr, de, es, it). Whitelist exacte **et CIDR**,
**notifications** optionnelles (webhook / e-mail) sur ban.

## Contenu du dépôt

| Fichier                 | Rôle |
|-------------------------|------|
| `ban_404.sh`            | Le script de ban (déployé en `/usr/local/sbin/ban_404.sh`, lancé par `cron.hourly`). |
| `install_ban_404.sh`    | Installeur clé en main (paquets, cron, persistance, migration, décommissionnement). |
| `update_ban_404.sh`     | Self-updater : télécharge → valide → bascule le moteur **et lui-même** (lancé par `cron.daily`). |
| `ban_404.conf.example`  | Modèle de config locale par serveur. |

La **config par serveur** (whitelist, `REPO_RAW`, réglages) vit dans
`/etc/ban_404.conf`, **hors dépôt** : les mises à jour ne l'écrasent jamais.

## Mise en place (une seule fois)

1. Pousser ces fichiers dans un dépôt GitHub `ban-404`.
2. Dans `install_ban_404.sh`, éditer la variable `REPO_RAW` avec l'URL *raw* du
   dépôt, par ex. `https://raw.githubusercontent.com/Pixels-Ing/ban-404/main`.
   Commit + push.

## Installation d'un serveur

```bash
# Récupérer puis lancer (on ne fait pas « curl | bash » : on télécharge, on lit, on exécute)
curl -fsSL https://raw.githubusercontent.com/Pixels-Ing/ban-404/main/install_ban_404.sh -o /tmp/install_ban_404.sh
sudo bash /tmp/install_ban_404.sh

# Adapter la whitelist de CE serveur
sudo nano /etc/ban_404.conf      # WHITELIST_IP="127.0.0.1|TES.IP.FIXES"

# (Optionnel) changer la langue des messages : en | fr | de | es | it
sudo /usr/local/sbin/ban_404.sh --lang fr

# Diagnostic de l'installation
sudo /usr/local/sbin/ban_404.sh --diag

# Vérifier sans rien bannir
sudo /usr/local/sbin/ban_404.sh --dry-run --verbose

# Détail des options
sudo /usr/local/sbin/ban_404.sh --help
```

L'installeur est **idempotent** (relançable) et gère la migration de l'ancien
chemin `/etc/iptables/ipset` ainsi que le retrait d'anciens scripts de ban 404.

## Mises à jour

Améliorer `ban_404.sh` → `git push`. Chaque serveur récupère la nouvelle
version via `cron.daily` (sous 24 h). Validation `bash -n` avant bascule : un
commit cassé n'est jamais déployé. Forcer tout de suite :

```bash
sudo /usr/local/sbin/update_ban_404.sh           # récupère la nouveauté si elle existe
sudo /usr/local/sbin/update_ban_404.sh --force   # redéploie même si le contenu est identique
```

> Le self-updater met à jour **`ban_404.sh` ET lui-même** (`update_ban_404.sh`).
> Si tu modifies l'installeur ou la structure cron, relance l'installeur sur les
> serveurs (rare).
>
> Le self-updater **ajoute aussi à `/etc/ban_404.conf` les réglages optionnels manquants**
> (commentés), pour rendre les confs existantes auto-documentées. C'est **non destructif** : il
> n'écrase jamais un réglage, il ne fait qu'ajouter les variables absentes en commentaire.

## Réglages (`/etc/ban_404.conf`)

| Variable          | Défaut      | Rôle |
|-------------------|-------------|------|
| `BAN404_LANG`     | (auto)      | Langue des messages : `en` (défaut), `fr`, `de`, `es`, `it`. Auto-détectée depuis la locale du shell/système ; présente **commentée** dans la conf (ajoutée par l'updater si absente). Modifiable via `ban_404.sh --lang <code>` (décommente et fixe). |
| `WHITELIST_IP`    | `127.0.0.1` | IP jamais bannies (séparées par `\|`, correspondance exacte). |
| `WINDOW`          | `7200`      | Fenêtre glissante (s) sur laquelle on compte les 404. |
| `BAN_TIMEOUT`     | `172800`    | Durée du ban (s). |
| `TAIL_LINES`      | `50000`     | Lignes analysées par log (borne le coût sur gros sites). |
| `BAN_THRESHOLD`   | `10`        | Ban si le score dépasse ce seuil dans la fenêtre. |
| `HONEYPOT_SCORE`  | `100`       | Score ajouté par hit honeypot (≥ ce score ⇒ ban immédiat). |
| `WHITELIST_CIDR`  | (vide)      | Sous-réseaux jamais bannis (CIDR séparés par `\|`, ex. `10.0.0.0/8`). |
| `EXCLUDE_VHOSTS`  | (vide)      | Vhosts exclus de l'analyse (noms de dossier sous `/var/www`, séparés par `\|`). Leurs 404 ne génèrent aucun ban. |
| `WEBHOOK_URL`     | (vide)      | Si défini : POST JSON des nouveaux bans (Slack/Discord/Teams/n8n/Google Chat…). Tester avec `--check-notification`. |
| `NOTIFY_EMAIL`    | (vide)      | Si défini : e-mail des nouveaux bans (nécessite un MTA `mail`/`sendmail`). |
| `NOTIFY_MIN_BANS` | `1`         | Ne notifier que si ≥ N nouveaux bans dans l'exécution. |
| `NOTIFY_BANS`     | `false`     | Alerte à chaque exécution quand des IP sont bannies. `true` pour l'activer (indépendant du résumé quotidien). |
| `DAILY_SUMMARY`   | `false`     | Résumé quotidien (opt-in) envoyé via le canal configuré (`cron.daily`). |
| `REPO_RAW`        | —           | URL *raw* du dépôt (utilisée par le self-updater). |

Les notifications sont émises **dans la langue** `BAN404_LANG`. Réglages avancés
(regex `awk`, à ne surcharger qu'en connaissance de cause) : `HONEYPOT_PATTERN`
(motifs honeypot) et `NOISE_PATTERN` (bruit ignoré). Voir `ban_404.conf.example`.

## Commandes utiles

```bash
sudo /usr/local/sbin/ban_404.sh --list                 # IP bannies (triées par famille, + timeout)
sudo /usr/local/sbin/ban_404.sh --list --by-timeout    # tri par timeout restant (croissant)
sudo /usr/local/sbin/ban_404.sh --stats --list         # cumulables en un seul appel
sudo /usr/local/sbin/ban_404.sh --stats                # statistiques (bannies, bans/débans 24h, top IP)
sudo /usr/local/sbin/ban_404.sh --lang de              # changer la langue des messages
sudo /usr/local/sbin/ban_404.sh --summary              # envoyer le résumé quotidien (si activé)
sudo /usr/local/sbin/ban_404.sh --check-notification   # tester les canaux (webhook + e-mail), avec diagnostic
sudo /usr/local/sbin/update_ban_404.sh --force         # forcer le redéploiement (même si identique)
```

## Prérequis

Ubuntu/Debian. Sur Ubuntu 22.04, `ipset-persistent` est dans le dépôt
**universe** (activé par défaut sur Ubuntu Server). Aucune dépendance externe
au-delà des paquets posés par l'installeur (`ipset`, `iptables-persistent`,
`ipset-persistent`, `cron`).

## ⚠️ ufw et pare-feu existant

ban-404 écrit **directement** dans ipset + iptables et persiste son état via
`iptables-persistent` / `netfilter-persistent`. Or, sur **Debian 12+ et Ubuntu
récentes**, le paquet `ufw` déclare lui-même `Breaks: iptables-persistent,
netfilter-persistent` : installer `iptables-persistent` fait donc **retirer ufw
par apt**. Ce n'est pas ban-404 qui désinstalle ufw (le mot n'apparaît nulle
part dans le code) — c'est une résolution de dépendances d'`apt`, déclenchée par
le choix « ipset + iptables-persistent ».

**L'installeur gère ce cas** : si ufw est installé, il **sauvegarde d'abord les
règles en vigueur** — `iptables-save`, `ip6tables-save`, une copie de `/etc/ufw/`
et la sortie de `ufw status verbose` — sous
`/var/lib/ban_404/ufw-backup-<horodatage>/`, **avertit** que ufw va être retiré,
puis **demande confirmation**. En contexte non interactif (sans TTY), il
**s'arrête** au lieu de retirer ufw en silence ; relancer avec
`BAN404_REMOVE_UFW=1` pour autoriser le retrait, ou `apt remove ufw` au préalable.

**Important — ban-404 n'est pas un pare-feu.** Il n'ajoute qu'une règle `DROP`
ciblant son propre ipset de scanners 404 ; il n'a **aucune** politique « deny par
défaut » et n'ouvre/ferme aucun port de service. Si ufw portait la politique
d'accès de ce serveur, une fois ufw retiré cette politique n'est plus réappliquée
(notamment **au reboot**) et l'hôte peut être **plus exposé** que prévu.
Reconstitue alors une politique équivalente **directement en iptables**, persistée
via `netfilter-persistent save`, à partir de la sauvegarde ci-dessus :

```bash
# Repérer ce qui était filtré : règles ufw sauvegardées + ports réellement à l'écoute
sudo cat /var/lib/ban_404/ufw-backup-*/etc-ufw/user.rules     # règles IPv4 qu'avait ufw
sudo cat /var/lib/ban_404/ufw-backup-*/ufw-status.txt         # vue lisible (allow/deny)
sudo ss -tulpn                                                # services à l'écoute (à protéger)

# Recréer les règles voulues en iptables, puis persister
sudo iptables -A INPUT ...                                    # politique d'accès reconstituée
sudo netfilter-persistent save
```
