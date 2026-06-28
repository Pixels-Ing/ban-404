#!/bin/bash
# ban_404.completion.bash — complétion Bash pour ban_404.sh.
# Déployé en /usr/share/bash-completion/completions/ban_404.sh (chargement à la
# demande, déclenché par le nom de la commande) ; tiré par l'updater comme le moteur.
#
# Le shebang « #!/bin/bash » est EXIGÉ par la validation de update_file (download ->
# shebang + bash -n -> bascule atomique) ; il est INERTE ici puisque le fichier est
# SOURCÉ par bash-completion, jamais exécuté. Ne pas le retirer.
#
# Complétion CONTEXTUELLE : on ne propose que les options pertinentes selon ce qui est
# déjà sur la ligne (ex. après --diag, seul --verbose ; après une action terminale, rien),
# et on masque les options déjà tapées. La « matrice de pertinence » ci-dessous doit rester
# en phase avec la sémantique du « case » de parsing de ban_404.sh. Best-effort : elle GUIDE
# sans interdire (on peut toujours taper une option non proposée). Purement interactif :
# aucun impact sur le run cron.

_ban_404() {
    local cur prev w i
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # 1) Valeur attendue juste après une option qui en prend une.
    case "$prev" in
        --lang)               mapfile -t COMPREPLY < <(compgen -W "en fr de es it" -- "$cur"); return 0 ;;
        --check-notification) mapfile -t COMPREPLY < <(compgen -W "email webhook all" -- "$cur"); return 0 ;;
        --unban)              mapfile -t COMPREPLY < <(compgen -W "all" -- "$cur"); return 0 ;;
    esac

    # 2) Balayer les options DÉJÀ posées (hors mot en cours de frappe) pour classer le contexte.
    local has_diag="" has_report="" has_terminal="" seen=" "
    for ((i=1; i<COMP_CWORD; i++)); do
        w="${COMP_WORDS[i]}"
        case "$w" in
            --diag)         has_diag=1 ;;
            --list|--stats) has_report=1 ;;
            --unban|--summary|--check-notification|--lang|--version|--help) has_terminal=1 ;;
        esac
        seen="$seen$w "
    done

    # 3) Sous-ensemble pertinent selon le contexte.
    local opts
    if   [ -n "$has_terminal" ]; then opts=""                                       # action terminale : plus rien
    elif [ -n "$has_diag" ];     then opts="--verbose"                              # seul modificateur de --diag
    elif [ -n "$has_report" ];   then opts="--list --stats --by-timeout --resolve"  # rapports cumulables + modifs
    else opts="--dry-run --show-blocked --verbose --list --stats --diag --unban --summary --check-notification --lang --version --help"
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
