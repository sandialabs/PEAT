#!/usr/bin/env bash

set -eux

git config --global --add safe.directory "$(pwd)"

pdm install -d

pre-commit install

# git remote add upstream https://github.com/sandialabs/PEAT.git
# git remote set-url --push upstream no_push
