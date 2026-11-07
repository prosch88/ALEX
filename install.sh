#!/bin/sh
# ALEX one-line installer - always installs the latest version from git.
#
#   curl -fsSL https://raw.githubusercontent.com/prosch88/ALEX/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/prosch88/ALEX/main/install.sh | bash -s -- --system   # system-wide (/usr/share/alex + /usr/bin/alex, needs sudo)
#   curl -fsSL https://raw.githubusercontent.com/prosch88/ALEX/main/install.sh | bash -s -- --user     # user install (default, ~/.local/share/alex)
#   ./install.sh --update   # pull latest + refresh deps
#
# What it does:
#   1. installs system deps (python3, tk, adb/fastboot) via apt/dnf/pacman/brew
#   2. clones (or git-pulls, so re-running always updates to latest)
#      https://github.com/prosch88/ALEX.git
#   3. creates a venv and pip-installs requirements.txt
#   4. installs a launcher (alex) + desktop entry + icon
set -eu

REPO="https://github.com/prosch88/ALEX.git"
MODE="user"
ACTION="install"
USER_HOME="${HOME:-$HOME}"
PREFIX_USER="$USER_HOME/.local/share/alex"
BIN_USER="$USER_HOME/.local/bin/alex"
PREFIX_SYS="/usr/share/alex"
BIN_SYS="/usr/bin/alex"

for arg in "$@"; do
  case "$arg" in
    --system) MODE="system" ;;
    --user) MODE="user" ;;
    --update) ACTION="update" ;;
    --help|-h)
      echo "Usage: install.sh [--user|--system] [--update]"
      echo "  --user    install to ~/.local/share/alex (default)"
      echo "  --system  install to /usr/share/alex + /usr/bin/alex (needs sudo)"
      echo "  --update  git pull latest + reinstall requirements in existing install"
      exit 0 ;;
    *) echo "Unknown option: $arg (see --help)" >&2; exit 1 ;;
  esac
done

if [ "$MODE" = "system" ]; then PREFIX="$PREFIX_SYS"; LAUNCHER="$BIN_SYS";
else PREFIX="$PREFIX_USER"; LAUNCHER="$BIN_USER"; fi

need() { command -v "$1" >/dev/null 2>&1; }
run_sudo() { if [ "$(id -u)" -eq 0 ]; then "$@"; elif need sudo; then sudo "$@"; else echo "Need root/sudo for $* (or use --user)" >&2; exit 1; fi; }

detect_pm() {
  if need apt-get; then echo apt
  elif need dnf; then echo dnf
  elif need pacman; then echo pacman
  elif need zypper; then echo zypper
  elif need apk; then echo apk
  elif need brew; then echo brew
  else echo none; fi
}

install_system_deps() {
  pm=$(detect_pm)
  echo "==> system deps via $pm"
  case "$pm" in
    apt) run_sudo apt-get update && run_sudo apt-get install -y python3 python3-tk python3-venv adb fastboot git ;;
    dnf) run_sudo dnf install -y python3 python3-tkinter python3-venv android-tools git ;;
    pacman) run_sudo pacman -Sy --needed --noconfirm python tk android-tools git ;;
    zypper) run_sudo zypper install -y python3 python3-tkinter android-tools git ;;
    apk) run_sudo apk add python3 py3-tkinter android-tools git ;;
    brew) brew install python@3.11 python-tk@3.11 android-platform-tools git || brew install python android-platform-tools git ;;
    none) echo "No package manager found; please install python3 (>=3.11), Tk, adb/fastboot, git manually." ;;
  esac
}

sync_repo() {
  if [ -d "$PREFIX/.git" ]; then
    echo "==> updating $PREFIX (git pull --ff-only)"
    git -C "$PREFIX" pull --ff-only
  elif [ -e "$PREFIX" ]; then
    echo "$PREFIX exists and is not a git checkout; remove it or pass a fresh location." >&2
    exit 1
  else
    if [ "$MODE" = "system" ]; then run_sudo mkdir -p "$(dirname "$PREFIX")"; run_sudo git clone --depth 1 "$REPO" "$PREFIX"
    else mkdir -p "$(dirname "$PREFIX")"; git clone --depth 1 "$REPO" "$PREFIX"; fi
  fi
}

setup_venv() {
  echo "==> venv + requirements in $PREFIX/.venv"
  if [ "$MODE" = "system" ]; then
    run_sudo python3 -m venv "$PREFIX/.venv"
    run_sudo "$PREFIX/.venv/bin/pip" install --upgrade pip
    run_sudo "$PREFIX/.venv/bin/pip" install -r "$PREFIX/requirements.txt"
  else
    python3 -m venv "$PREFIX/.venv"
    "$PREFIX/.venv/bin/pip" install --upgrade pip
    "$PREFIX/.venv/bin/pip" install -r "$PREFIX/requirements.txt"
  fi
}

install_launcher() {
  echo "==> launcher $LAUNCHER"
  if [ "$MODE" = "system" ]; then
    run_sudo install -m755 "$PREFIX/packaging/alex" "$LAUNCHER"
    # point the system launcher at the venv when present
    run_sudo sh -c "cat > /usr/bin/alex <<'EOF'
#!/bin/sh
set -e
if [ -x /usr/share/alex/.venv/bin/python ]; then
  exec /usr/share/alex/.venv/bin/python /usr/share/alex/alex.py \"\$@\"
fi
APP_HOME=/usr/share/alex
if [ -d \"\$APP_HOME/lib\" ]; then PYTHONPATH=\"\$APP_HOME/lib:\$APP_HOME:\${PYTHONPATH:-}\"; export PYTHONPATH; fi
exec python3 \"\$APP_HOME/alex.py\" \"\$@\"
EOF
chmod 755 /usr/bin/alex"
    run_sudo install -m644 "$PREFIX/packaging/alex.desktop" /usr/share/applications/alex.desktop || true
    run_sudo install -m644 "$PREFIX/assets/alex.png" /usr/share/pixmaps/alex.png || true
  else
    mkdir -p "$(dirname "$LAUNCHER")" "$USER_HOME/.local/share/applications" "$USER_HOME/.local/share/icons"
    cat > "$LAUNCHER" <<EOF
#!/bin/sh
set -e
if [ -x "$PREFIX/.venv/bin/python" ]; then
  exec "$PREFIX/.venv/bin/python" "$PREFIX/alex.py" "\$@"
fi
exec python3 "$PREFIX/alex.py" "\$@"
EOF
    chmod 755 "$LAUNCHER"
    sed "s|^Exec=alex|Exec=$LAUNCHER|; s|^Icon=alex|Icon=$USER_HOME/.local/share/icons/alex.png|" \
      "$PREFIX/packaging/alex.desktop" > "$USER_HOME/.local/share/applications/alex.desktop" || true
    cp "$PREFIX/assets/alex.png" "$USER_HOME/.local/share/icons/alex.png" || true
    case ":$PATH:" in *":$USER_HOME/.local/bin:"*) ;; *) echo "Add to PATH: export PATH=\"\$HOME/.local/bin:\$PATH\"" ;; esac
  fi
}

if [ "$ACTION" = "update" ]; then
  if [ ! -d "$PREFIX/.git" ]; then echo "No install found at $PREFIX (run without --update first)." >&2; exit 1; fi
  sync_repo
  setup_venv
  install_launcher
  echo "ALEX updated to $(git -C "$PREFIX" rev-parse --short HEAD)."
  exit 0
fi

# fresh install: system deps only when we have a package manager; never fail the whole install on it
install_system_deps || true
sync_repo
setup_venv
install_launcher
echo ""
echo "ALEX installed (latest $(git -C "$PREFIX" rev-parse --short HEAD)). Run with: $LAUNCHER"
echo "Re-run with --update any time to pull the latest version."
