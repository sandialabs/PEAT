#!/usr/bin/env bash
#
# Usage: sudo bash linux-install-script.sh
#
# NOTE:
#   1. root permissions are required (run with 'sudo')
#   2. man-db must be installed. If not, install via 'sudo apt install man-db'

set -ex

SCRIPTDIR="$(dirname $0)"

cp "$SCRIPTDIR"/peat /usr/local/bin/
chmod +rx /usr/local/bin/peat
mkdir -p /usr/local/share/man/man1/
cp "$SCRIPTDIR"/peat.1 /usr/local/share/man/man1/
mandb
