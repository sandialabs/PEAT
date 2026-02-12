#!/bin/sh

# PEAT easy installer (POSIX sh)
# Installs latest release PEAT binary /usr/local/bin/peat,
# man page to /usr/local/share/man/man1, and updates the
# manual database (if 'mandb' command is present).

set -eu

REPO="${REPO:-sandialabs/PEAT}"
API_URL="https://github.com/$REPO/releases/latest/download"

BIN_URL="$API_URL/peat"
MAN_URL="$API_URL/peat.1"

BIN_DIR="/usr/local/bin"
BIN_DST="$BIN_DIR/peat"

MAN_DIR="/usr/local/share/man/man1"
MAN_DST="$MAN_DIR/peat.1"

TMPDIR=${TMPDIR:-/tmp}

say() { printf '%s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }

download_to() {
  url=$1
  out=$2

  if need_cmd curl; then
    curl -sfL -o "$out" "$url"
  elif need_cmd wget; then
    wget -qO "$out" "$url"
  else
    die "Neither curl nor wget is available; please install one to proceed."
  fi
}


# Require privileges (we write to /usr/local)
if [ "$(id -u)" -ne 0 ]; then
  if need_cmd sudo; then
    say "Re-running with sudo (needed to write to /usr/local)..."
    exec sudo -H -- "$0" "$@"
  else
    die "This installer must run as root (or install sudo)."
  fi
fi


TMPBIN="$TMPDIR/peat_bin_$$"
TMPMAN="$TMPDIR/peat_man_$$"
trap 'rm -f "$TMPBIN" "$TMPMAN"' EXIT HUP INT TERM


say "Downloading PEAT binary..."
download_to "$BIN_URL" "$TMPBIN"

say "Downloading man page..."
download_to "$MAN_URL" "$TMPMAN"


say "Installing peat to $BIN_DST ..."
[ -d "$BIN_DIR" ] || mkdir -p "$BIN_DIR"

if need_cmd install; then
  install -m 0755 "$TMPBIN" "$BIN_DST"
else
  cp -f "$TMPBIN" "$BIN_DST"
  chmod 0755 "$BIN_DST"
fi


say "Installing man page to $MAN_DST ..."
[ -d "$MAN_DIR" ] || mkdir -p "$MAN_DIR"
if need_cmd install; then
    install -m 0644 "$TMPMAN" "$MAN_DST"
else
    cp -f "$TMPMAN" "$MAN_DST"
    chmod 0644 "$MAN_DST"
fi

if need_cmd mandb; then
    say "Updating man database (mandb)..."
    mandb >/dev/null 2>&1 || mandb || true
else
    say "WARN: 'mandb' command not present, skipping man page update"
fi

say "Done! Try: peat --help"
