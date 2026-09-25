#!/bin/sh
# PortPatrol installer for Linux: builds a private virtual environment under
# ~/.portpatrol, puts a portpatrol command in ~/.local/bin, and installs the
# desktop launcher. Every path derives from $HOME so it can be tested.

fail() {
    printf 'portpatrol install: %s\n' "$1" >&2
    exit 2
}

command -v python3 >/dev/null 2>&1 || fail "python3 not found. Install Python 3.8 or newer from https://www.python.org/downloads/."

python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null \
    || fail "Python 3.8 or newer is required. Install a newer Python from https://www.python.org/downloads/."

SRC_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) \
    || fail "cannot determine the installer directory."

VENV="$HOME/.portpatrol/venv"
BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
ERR_FILE=$(mktemp) || fail "cannot create a temporary file."
trap 'rm -f "$ERR_FILE"' EXIT

mkdir -p "$HOME/.portpatrol" || fail "cannot create $HOME/.portpatrol."

if ! python3 -m venv "$VENV" 2>"$ERR_FILE"; then
    if grep -qi 'ensurepip' "$ERR_FILE"; then
        fail "the venv module cannot bootstrap pip. On Debian or Ubuntu run: sudo apt install python3-venv. On Fedora: sudo dnf install python3. On Arch: sudo pacman -S python, then re-run this script."
    fi
    fail "could not create the virtual environment: $(head -n 1 "$ERR_FILE")"
fi

if ! "$VENV/bin/python" -m pip install --quiet --upgrade "$SRC_DIR" 2>"$ERR_FILE"; then
    fail "the pip install failed. The first run downloads a small build package, so an internet connection is needed. $(tail -n 1 "$ERR_FILE")"
fi

mkdir -p "$BIN_DIR" || fail "cannot create $BIN_DIR."
ln -sf "$VENV/bin/portpatrol" "$BIN_DIR/portpatrol" || fail "could not write $BIN_DIR/portpatrol."

WRAPPER="$HOME/.portpatrol/bin/portpatrol-desktop.sh"
mkdir -p "$HOME/.portpatrol/bin" || fail "cannot create $HOME/.portpatrol/bin."
cat > "$WRAPPER" <<EOF
#!/bin/sh
# Installed by portpatrol install.sh: scan, then wait for Enter.
"$VENV/bin/portpatrol" scan
status=\$?
printf '\\nPress Enter to close...'
read -r _ || true
exit \$status
EOF
chmod +x "$WRAPPER" || fail "could not mark $WRAPPER executable."

EXEC_VALUE="$WRAPPER"
case "$EXEC_VALUE" in
    *' '*|*'"'*) EXEC_VALUE="\"$EXEC_VALUE\"" ;;
esac

mkdir -p "$APP_DIR" || fail "cannot create $APP_DIR."
{
    printf '[Desktop Entry]\n'
    printf 'Type=Application\n'
    printf 'Name=PortPatrol\n'
    printf 'Comment=Scan localhost for open ports\n'
    printf 'Exec=%s\n' "$EXEC_VALUE"
    printf 'Icon=utilities-system-monitor\n'
    printf 'Terminal=true\n'
    printf 'Categories=System;Security;\n'
    printf 'StartupNotify=false\n'
} > "$APP_DIR/portpatrol.desktop" || fail "could not write $APP_DIR/portpatrol.desktop."

case ":${PATH:-}:" in
    *":$BIN_DIR:"*) ;;
    *)
        printf 'portpatrol install: %s is not on your PATH.\nAdd this line to your shell profile, then open a new terminal:\n  export PATH="$HOME/.local/bin:$PATH"\n' "$BIN_DIR" >&2
        ;;
esac

printf 'PortPatrol installed. Run: portpatrol\n'
printf 'The portpatrol launcher is in your application menu (terminal opens for the scan result).\n'
