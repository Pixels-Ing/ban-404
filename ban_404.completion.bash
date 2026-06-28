#!/bin/bash
# ban_404.completion.bash — complétion Bash pour ban_404.sh.
# Déployé en /usr/share/bash-completion/completions/ban_404.sh (chargement à la
# demande, déclenché par le nom de la commande) ; tiré par l'updater comme le moteur.
#
# Le shebang « #!/bin/bash » est EXIGÉ par la validation de update_file (download ->
# shebang + bash -n -> bascule atomique) ; il est INERTE ici puisque le fichier est
# SOURCÉ par bash-completion, jamais exécuté. Ne pas le retirer.
#
# La liste d'options doit rester en phase avec le « case » de parsing de ban_404.sh.
# Fonctionnalité purement interactive : aucun impact sur le run cron.

_ban_404() {
    local cur prev opts
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="--dry-run --show-blocked --verbose --list --by-timeout --resolve --stats \
--unban --summary --check-notification --diag --lang --version --help"

    # Valeurs attendues selon l'option précédente (complétion contextuelle).
    case "$prev" in
        --lang)
            mapfile -t COMPREPLY < <(compgen -W "en fr de es it" -- "$cur"); return 0 ;;
        --check-notification)
            mapfile -t COMPREPLY < <(compgen -W "email webhook all" -- "$cur"); return 0 ;;
        --unban)
            mapfile -t COMPREPLY < <(compgen -W "all" -- "$cur"); return 0 ;;
    esac

    mapfile -t COMPREPLY < <(compgen -W "$opts" -- "$cur")
    return 0
}
complete -F _ban_404 ban_404.sh /usr/local/sbin/ban_404.sh
