# ARGs enable customization of the base image at build time without
# modifying the Dockerfile via "--build-arg" arguments to "docker build".
# For example, to use the internal SNL Docker registry, add the following argument:
#   --build-arg REGISTRY_IMAGE="nexus.web.sandia.gov:8083/python"
ARG REGISTRY_IMAGE=python
ARG PYTHON_VERSION=3.11.11

# ** Builder used to generate the required artifacts (pip packages, etc.) **
FROM ${REGISTRY_IMAGE}:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND="noninteractive" \
    PDM_CHECK_UPDATE=false

# Install build tools
RUN set -ex \
  && apt-get update \
  && apt-get install -qyf \
    make git gcc \
    tcpdump libpcap0.8 libpcap-dev lrzsz libxml2-dev libxslt1-dev \
    cython3 python3-pip python3-dev python3-venv \
    binutils libssl-dev libffi-dev libpq-dev libpq5 \
    qemu-utils libkmod-dev kmod \
    apt-utils apt-transport-https ca-certificates curl dpkg-dev gnupg2 \
  && apt-get autoclean \
  && apt-get --purge -y autoremove \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Update and install library dependencies, required tools, and Python versions
# Dependencies
# - tcpdump, libpcap, libpcap-dev: required for scapy
# - lrzsz: required for serial communications with certain devices
# - libxml, libxslt: required for TC6/XML parsing
# - libpq: required for PostgreSQL comms used by some modules
# - qemu-img, kmod, libkmod-dev: required for PEAT Pillage (disk image processing)
#
# Note: the tools (ping, wget, etc.) only add ~9MB to final image size.
# They're useful to have when stuck in an offline environment
# with nothing but your wits and a PEAT image.
RUN set -ex \
  && echo 'deb https://download.opensuse.org/repositories/security:/zeek/Debian_12/ /' | tee /etc/apt/sources.list.d/security:zeek.list \
  && curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_12/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null \
  && apt-get update \
  && apt-get install -y --download-only --no-install-recommends \
    iputils-ping net-tools iproute2 wget curl tree nano jq \
    tcpdump libpcap0.8 libpcap-dev lrzsz \
    libxml2 libxslt1.1 libpq5 \
    qemu-utils kmod libkmod-dev \
    zeek-6.0-core \
  && ls -lAh /var/cache/apt/archives/ \
  && mkdir /deb-files \
  && cd /deb-files \
  && cp /var/cache/apt/archives/*.deb ./ \
  && dpkg-scanpackages . /dev/null > Packages \
  && gzip -9 Packages \
  && apt-get autoclean \
  && apt-get --purge -y autoremove \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# NOTE: the run commands below are separate layers so less layers are invalidated
# on code changes. We don't care about size as much since this is an intermediate
# layer just used for building the virtual environment, it's not the final image.

ARG PIP_INDEX="https://pypi.org/"
ARG PIP_INDEX_URL="https://pypi.org/simple"

RUN set -ex \
  && pip install --quiet --no-cache-dir --upgrade pip \
  && pip install --no-cache-dir --upgrade pdm

WORKDIR /PEAT
COPY ./LICENSE ./
COPY ./NOTICE ./
COPY ./AUTHORS ./
COPY ./README.md ./
COPY ./pyproject.toml ./
COPY ./pdm.lock ./
COPY ./peat/ ./peat/

ARG PDM_BUILD_SCM_VERSION

# Create a virtual environment in /PEAT/.venv/, 
# download and install packages, and cleanup 
# unneeded tests bundled with beautifulsoup4.
RUN set -ex \
  && pdm install --check --prod \
  && rm -rf /PEAT/.venv/lib/python3.11/site-packages/bs4/tests


# ** The image that's actually built and deployed **
FROM ${REGISTRY_IMAGE}:${PYTHON_VERSION}-slim-bookworm AS release

# Container metadata
# Reference: https://github.com/opencontainers/image-spec/blob/main/annotations.md
# The args are used for setting the image metadata below
ARG REGISTRY_IMAGE=python
ARG PYTHON_VERSION=3.11.11
LABEL org.opencontainers.image.authors="PEAT Development Team" \
  org.opencontainers.image.vendor="Sandia National Laboratories" \
  org.opencontainers.image.source="https://ghcr.io/sandialabs/peat:latest" \
  org.opencontainers.image.documentation="https://sandialabs.github.io/peat/" \
  org.opencontainers.image.title="PEAT" \
  org.opencontainers.image.description="The Process Extraction and Analysis Tool (PEAT) Command Line Interface (CLI) packaged as a Docker image" \
  org.opencontainers.image.base.name="${REGISTRY_IMAGE}:${PYTHON_VERSION}-slim-bookworm"

# Setting "TZ" fixes the lack of a /etc/timezone file for the 'tzlocal' package
ENV PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND="noninteractive" \
    TZ="Etc/UTC" \
    PEAT_IN_CONTAINER=true \
    PATH="$PATH:/opt/zeek/bin"

# Copy the PEAT files and virtualenv with Python packages from builder
COPY --from=builder /PEAT /PEAT

# Install apt packages that were downloaded by the builder
# Sheldon Jones helped me out with this nifty trick
RUN --mount=type=bind,from=builder,source=/deb-files,target=/deb-files \
  . /etc/os-release \
  && echo "deb [trusted=yes] file:/deb-files/${OS_VERSION} ./" | tee /etc/apt/sources.list.d/static-packages.list \
  && apt-get update \
  && apt-get install -qyf --no-install-recommends \
    iputils-ping net-tools iproute2 wget curl tree nano jq \
    tcpdump libpcap0.8 libpcap-dev lrzsz \
    libxml2 libxslt1.1 libpq5 \
    qemu-utils kmod libkmod-dev \
    zeek-6.0-core \
  && apt-get autoclean \
  && apt-get --purge -y autoremove \
  && rm -f /etc/apt/sources.list.d/static-packages.list \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Checks if any files in peat_results have been modified in the last minute
HEALTHCHECK CMD find /peat_results/ -mmin -1 -type f | grep -q .

ENTRYPOINT ["/PEAT/.venv/bin/python", "-m", "peat"]
