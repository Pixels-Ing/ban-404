#!/bin/bash
# check.sh — garde-fou (local / pre-commit / CI). À lancer depuis la racine du dépôt.
#   1) bash -n sur les 3 scripts (+ check.sh)
#   2) synchro du heredoc UPD_EOF de l'installeur avec update_ban_404.sh (zéro divergence)
#   3) shellcheck si disponible (bloque uniquement sur les erreurs, sévérité < error tolérée)
# Sortie != 0 au moindre échec.
#
# Pre-commit : créer .git/hooks/pre-commit contenant :  #!/bin/sh \n exec bash check.sh
set -u

SCRIPTS="ban_404.sh update_ban_404.sh install_ban_404.sh check.sh"

# Doit tourner à la racine du dépôt (les chemins sont relatifs).
if [ ! -f ban_404.sh ] || [ ! -f install_ban_404.sh ]; then
    echo "check.sh : à lancer depuis la racine du dépôt ban-404." >&2
    exit 1
fi

fail=0

echo "== bash -n =="
for f in $SCRIPTS; do
    if bash -n "$f" 2>/dev/null; then
        echo "  OK  $f"
    else
        echo "  KO  $f :"; bash -n "$f"; fail=1
    fi
done

echo "== synchro heredoc UPD_EOF <-> update_ban_404.sh =="
extract_updeof() {
    awk '/^cat > "\$UPDATER_PATH" <<.UPD_EOF.$/{f=1;next} /^UPD_EOF$/{f=0} f' install_ban_404.sh
}
if diff --strip-trailing-cr <(extract_updeof) update_ban_404.sh >/dev/null; then
    echo "  OK  identiques"
else
    echo "  KO  le heredoc UPD_EOF diverge de update_ban_404.sh :"
    diff --strip-trailing-cr <(extract_updeof) update_ban_404.sh
    fail=1
fi

echo "== shellcheck =="
if command -v shellcheck >/dev/null 2>&1; then
    # Affichage complet (informatif, non bloquant)...
    # shellcheck disable=SC2086
    shellcheck $SCRIPTS || true
    # ...mais on ne bloque que sur la sévérité "error".
    # shellcheck disable=SC2086
    shellcheck -S error $SCRIPTS || { echo "  KO  shellcheck a relevé des ERREURS"; fail=1; }
else
    echo "  (shellcheck absent — ignoré)"
fi

if [ "$fail" -eq 0 ]; then echo "== TOUT OK =="; else echo "== ÉCHEC =="; fi
exit "$fail"
