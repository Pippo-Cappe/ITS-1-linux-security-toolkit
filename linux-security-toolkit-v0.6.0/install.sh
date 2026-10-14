#!/usr/bin/env bash
# Prepara LSTK dopo un "git clone": dipendenze di sistema, ambiente virtuale, pacchetto Python, Trivy.
# Uso: ./install.sh [-y|--yes] [--skip-system] [--skip-trivy]
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

YES=0; SKIP_SYSTEM=0; SKIP_TRIVY=0
for a in "$@"; do
  case "$a" in
    -y|--yes) YES=1 ;;
    --skip-system) SKIP_SYSTEM=1 ;;
    --skip-trivy) SKIP_TRIVY=1 ;;
    -h|--help) sed -n '2,3p' "$0"; exit 0 ;;
    *) echo "Opzione sconosciuta: $a" >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERRORE:\033[0m %s\n' "$*" >&2; exit 1; }
ask()  { [ "$YES" = 1 ] && return 0; read -r -p "$1 [s/N] " r </dev/tty || return 1; [[ "$r" =~ ^[sSyY]$ ]]; }

[ "$(uname -s)" = "Linux" ] || die "LSTK supporta solo Linux."
SUDO=""; if [ "$(id -u)" -ne 0 ]; then command -v sudo >/dev/null 2>&1 && SUDO="sudo --" || warn "né root né sudo: i pacchetti di sistema non potranno essere installati."; fi

# 1) Pacchetti di sistema (repository ufficiali della distribuzione)
if [ "$SKIP_SYSTEM" = 0 ]; then
  if   command -v apt-get >/dev/null; then MGR=apt;    PKGS="python3 python3-venv python3-pip nmap lynis iproute2"
  elif command -v dnf     >/dev/null; then MGR=dnf;    PKGS="python3 python3-pip nmap lynis iproute"
  elif command -v zypper  >/dev/null; then MGR=zypper; PKGS="python3 python3-pip nmap lynis iproute2"
  elif command -v pacman  >/dev/null; then MGR=pacman; PKGS="python python-pip nmap lynis iproute2"
  else MGR=""; warn "gestore pacchetti non riconosciuto: installa manualmente python3, venv, pip, nmap, lynis, iproute2."; fi
  if [ -n "$MGR" ]; then
    say "Pacchetti di sistema da installare ($MGR): $PKGS"
    if ask "Installarli ora (modifica il sistema, richiede privilegi)?"; then
      case "$MGR" in
        apt)    $SUDO apt-get update || warn "apt-get update con errori: si prosegue"; $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y $PKGS ;;
        dnf)    $SUDO dnf install -y $PKGS ;;
        zypper) $SUDO zypper --non-interactive install $PKGS ;;
        pacman) $SUDO pacman -S --noconfirm --needed $PKGS ;;
      esac || warn "installazione di alcuni pacchetti non riuscita (es. lynis su RHEL richiede EPEL): LSTK saltera' i moduli mancanti."
    else
      warn "saltato: LSTK proporra' di installare gli strumenti mancanti quando servono (/scan, /install)."
    fi
  fi
fi

# 2) Python >= 3.10 e ambiente virtuale
command -v python3 >/dev/null || die "python3 non trovato."
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' || die "serve Python >= 3.10 (trovato $(python3 -V))."
python3 -c 'import venv, ensurepip' 2>/dev/null || die "manca il modulo venv/ensurepip: installa python3-venv (Debian/Ubuntu/Kali)."
say "Creo l'ambiente virtuale .venv"
[ -x .venv/bin/python ] && .venv/bin/python -c 'import sys' 2>/dev/null || { rm -rf .venv; python3 -m venv .venv; }
say "Installo LSTK e le dipendenze Python (typer, rich)"
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet -e .

# 3) Trivy (release ufficiale, hash SHA-256 fissato nel codice)
if [ "$SKIP_TRIVY" = 0 ]; then
  if [ -x /usr/local/bin/trivy ] || command -v trivy >/dev/null; then say "Trivy gia' presente"; else
    say "Trivy non trovato"
    if ask "Scaricare e installare Trivy (download da github.com, verifica SHA-256, richiede privilegi)?"; then
      .venv/bin/python -m lstk install trivy --yes || warn "Trivy non installato: potrai farlo piu' tardi con /install trivy"
    fi
  fi
fi

say "Verifica finale"
.venv/bin/python -m lstk doctor || true
say "Pronto. Avvia con:  ./run.sh"
