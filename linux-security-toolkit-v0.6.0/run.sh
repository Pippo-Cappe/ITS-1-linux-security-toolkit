#!/usr/bin/env bash
# Avvia LSTK con i privilegi necessari per l'audit completo. Se manca l'ambiente, esegue prima install.sh.
# Uso: ./run.sh [argomenti di lstk]   es.  ./run.sh   |   ./run.sh scan --format table
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
[ -x .venv/bin/lstk ] || ./install.sh
export PYTHONDONTWRITEBYTECODE=1      # evita file .pyc di proprietà root nel repository
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || { echo "Servono privilegi root per l'audit completo e sudo non c'e'. Avvio senza (copertura ridotta)." >&2; exec .venv/bin/lstk "$@"; }
  exec sudo --preserve-env=PYTHONDONTWRITEBYTECODE,LSTK_SIGNING_KEY,LSTK_REPORT_DIR -- .venv/bin/lstk "$@"
fi
exec .venv/bin/lstk "$@"
