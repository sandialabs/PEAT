#!/usr/bin/env bash

# Build a portable self-contained version of PEAT using PyInstaller
# NOTE: you may need these packages: python3-dev patchelf binutils scons libpq-dev libpq5
#   sudo apt install python3-dev patchelf binutils scons libpq-dev libpq5
#
# Usage: build-linux-package.sh [exe-name]
#   exe-name can be either 'peat' or 'sneakypeat'
#   defaults to 'peat'
#
# !! WARNING: this does NOT work with Pythons installed using "pyenv" !!
# This is due to the shared libraries needed by PyInstaller and staticx not being present.
# Instead, use the desired Python version from the deadsnakes PPA on Ubuntu.
#   sudo add-apt-repository -yu ppa:deadsnakes/ppa
#   sudo apt update
#   sudo apt install -y python3.11 python3.11-dev python3.11-venv
#
# NOTE (cegoes, 12/22/2022): psycopg2 libraries don't seem to be included if psycopg2-binary package is used.
# I'm not 100% sure this is the case, it's based on WARNINGS emitted by pyinstaller.
# To ensure they're included (and remove the WARNINGS), run this command:
#   pip install --no-binary=psycopg2 --no-cache-dir --force-reinstall --use-pep517 psycopg2

set -e

# 'peat' or 'sneakypeat'
EXE_NAME=${1:-"peat"}

INSTALLDIR="$(dirname "$(dirname "$(readlink -f "$0")")")"
TEMPNAME="${EXE_NAME}-pyinstaller-pre-staticx"

pushd "$INSTALLDIR" >/dev/null

# Remove artifacts from previous builds
rm -f "./build/$EXE_NAME" >/dev/null
rm -f "./build/$TEMPNAME" >/dev/null
rm -f "./dist/$EXE_NAME" >/dev/null
rm -f "./dist/$TEMPNAME" >/dev/null

echo "--- Python path: $(which python)"

# Build the bundle using PyInstaller.
# Note that the package created by PyInstaller relies on specific
# shared libraries (.so files) being present and is NOT portable across
# different versions of Ubuntu or other Linux distributions.
# The step following this involving staticx resolves this issue.
#
# NOTE: -OO works fine on Linux for Sneakypeat, and
# shaves ~1.1MB off the sneakypeat executable size.
# We can get away with this because sneakypeat doesn't
# really need the docstrings, which is what gets removed
# with -OO.
if [[ "$EXE_NAME" == "sneakypeat" ]]; then
    python -OO -m PyInstaller --noconfirm --clean "${INSTALLDIR}/distribution/${EXE_NAME}.spec"
else
    python -m PyInstaller --noconfirm --clean "${INSTALLDIR}/distribution/${EXE_NAME}.spec"
fi

cp ./dist/"$EXE_NAME" ./dist/"$TEMPNAME"

# StaticX includes the system libraries in the package. This makes
# the executable portable across Linux distributions and versions,
# e.g. a package built on Ubuntu 18.10 will work on Ubuntu 14.04, RHEL 7, etc.
echo "--- Running staticx..."
staticx ./dist/"$EXE_NAME" ./dist/"$EXE_NAME"

# Mark as world-readable and executable
echo "--- Changing executable permissions..."
chmod +rx ./dist/"$EXE_NAME"

# Move the intermediate package out of dist but retain
# for debugging issues with PyInstaller.
# Inspec: pdm run pyi-archive_viewer -l build/peat-pyinstaller-pre-staticx
mv ./dist/"$TEMPNAME" ./build/"$TEMPNAME"

# Restore the working directory
popd >/dev/null

echo "--- All done building the executable!"
echo "--- If there are warnings about 'Unexpected line in ldd output', then run: 'pip install --no-binary=psycopg2 --no-cache-dir --force-reinstall --use-pep517 psycopg2'"
