#!/bin/bash
# ban_404.completion.bash — complétion Bash pour ban_404.sh.
# Déployé en /usr/share/bash-completion/completions/ban_404.sh (chargement à la
# demande, déclenché par le nom de la commande) ; tiré par l'updater comme le moteur.
#
# Le shebang « #!/bin/bash » est EXIGÉ par la validation de update_file (download ->
# shebang + bash -n -> bascule atomique) ; il est INERTE ici puisque le fichier est
# SOURCÉ par bash-completion, jamais exécuté. Ne pas le retirer.
#
# Complétion CONTEXTUELLE : on ne propose que ce qui est pertinent selon ce qui est déjà
# sur la ligne (ex. après diag, seuls --verbose/--no-health ; après une action terminale,
# rien), et on masque ce qui est déjà tapé. Depuis 1.5.0 la forme canonique est la
# SOUS-COMMANDE NUE (list, stats, diag, health...) — seule proposée ici — mais les formes
# historiques --list/--stats/... restent acceptées par le parseur : une ligne tapée à
# l'ancienne guide donc le contexte à l'identique. La « matrice de pertinence » ci-dessous
# doit rester en phase avec la sémantique du « case » de parsing de ban_404.sh. Best-effort :
# elle GUIDE sans interdire (on peut toujours taper une option non proposée). Purement
# interactif : aucun impact sur le run cron.

_ban_404() {
    local cur prev w i
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # 1) Valeur attendue juste après une sous-commande/option qui en prend une.
    case "$prev" in
        lang|--lang)                             mapfile -t COMPREPLY < <(compgen -W "en fr de es it" -- "$cur"); return 0 ;;
        check-notification|--check-notification) mapfile -t COMPREPLY < <(compgen -W "email webhook all" -- "$cur"); return 0 ;;
        unban|--unban)                           mapfile -t COMPREPLY < <(compgen -W "all" -- "$cur"); return 0 ;;
    esac

    # 2) Balayer ce qui est DÉJÀ posé (hors mot en cours de frappe) pour classer le contexte.
    #    Chaque motif reconnaît la forme nue ET la forme historique --.
    local has_diag="" has_report="" has_terminal="" has_list="" has_stats="" seen=" "
    for ((i=1; i<COMP_CWORD; i++)); do
        w="${COMP_WORDS[i]}"
        case "$w" in
            diag|--diag)   has_diag=1 ;;
            list|--list)   has_report=1; has_list=1 ;;
            stats|--stats) has_report=1; has_stats=1 ;;
            health|unban|--unban|summary|--summary|check-notification|--check-notification|lang|--lang|version|--version|help|--help|-h) has_terminal=1 ;;
        esac
        seen="$seen$w "
    done

    # 3) Sous-ensemble pertinent selon le contexte. Les paires nue/-- ne sont PAS filtrées par
    #    « seen » (tokens littéraux : « --list » tapé ne masquerait pas « list ») : on construit
    #    la liste conditionnellement via has_list/has_stats.
    local opts
    if   [ -n "$has_terminal" ]; then opts=""                       # action terminale : plus rien
    elif [ -n "$has_diag" ];     then opts="--verbose --no-health"  # modificateurs de diag
    elif [ -n "$has_report" ];   then
        opts="--resolve"                                           # PTR : pertinent pour list et stats
        [ -z "$has_list" ]  && opts="$opts list"                   # rapports cumulables
        [ -z "$has_stats" ] && opts="$opts stats"
        [ -n "$has_list" ]  && opts="$opts --by-timeout"           # tri : pertinent pour list seul
        [ -n "$has_stats" ] && opts="$opts --verbose --no-health"  # stats rejoue le diag (santé incluse)
    else opts="list stats diag health summary unban lang check-notification version help --dry-run --show-blocked --verbose --no-log --no-health"
    fi

    # 4) Retirer ce qui est déjà sur la ligne (pas de doublon proposé).
    local avail="" tok
    # shellcheck disable=SC2086
    for tok in $opts; do
        case "$seen" in *" $tok "*) ;; *) avail+=" $tok" ;; esac
    done

    mapfile -t COMPREPLY < <(compgen -W "$avail" -- "$cur")
    return 0
}
complete -F _ban_404 ban_404.sh /usr/local/sbin/ban_404.sh
