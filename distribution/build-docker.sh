#!/usr/bin/env sh
#
# Usage: build-docker.sh
#
# NOTE: this MUST work with "sh" and not use Bash features
# This is due to the Docker dind container not including Bash.

set -e

# cd to the PEAT root directory, regardless of where the script is run
# NOTE: can't use pushd/popd in case this script is run with "sh"
INSTALLDIR="$(dirname "$(dirname "$(readlink -f "$0")")")"
CURDIR="$(pwd)"
cd "$INSTALLDIR" >/dev/null

GIT_LATEST_TAG="$(git describe --tags --abbrev=0)"
IMAGE="ghcr.io/sandialabs/peat"
TAG="${TAG:-latest}"
BUILDER_TAG="$TAG-builder-cache"

# https://dev.to/pst418/speed-up-multi-stage-docker-builds-in-ci-cd-with-buildkit-s-registry-cache-11gi
# https://testdriven.io/blog/faster-ci-builds-with-docker-cache/
# https://docs.docker.com/engine/reference/commandline/build/#specifying-target-build-stage---target
export DOCKER_BUILDKIT=1

# Build and cache the "builder" stage of the multi-stage build
docker build \
  --pull \
  --cache-from "$IMAGE":"$BUILDER_TAG" \
  --tag "$IMAGE":"$BUILDER_TAG" \
  --target builder \
  --build-arg BUILDKIT_INLINE_CACHE=1 \
  --build-arg PDM_BUILD_SCM_VERSION="$GIT_LATEST_TAG" \
  --progress=plain \
  .

# Build the "release" stage, which is the image we actually use
docker build \
  --pull \
  --cache-from "$IMAGE":"$BUILDER_TAG" \
  --cache-from "$IMAGE":"$TAG" \
  --tag "$IMAGE":"$TAG" \
  --target release \
  --label built_by="$(whoami)" \
  --label org.opencontainers.image.created="$(date -I'seconds')" \
  --label org.opencontainers.image.revision="$(git rev-parse HEAD)" \
  --label org.opencontainers.image.version="$GIT_LATEST_TAG" \
  --build-arg PDM_BUILD_SCM_VERSION="$GIT_LATEST_TAG" \
  --progress=plain \
  .

# Restore working directory
cd "$CURDIR"
