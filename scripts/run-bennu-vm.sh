#!/usr/bin/env bash
#
# Run a SCEPTRE bennu field device VM for testing the PEAT SCEPTRE module.
#
# The VM image is the pre-built bennu image from sandialabs/sceptre-phenix-images.
# The VM is set up the same way the phenix SCEPTRE app sets up a field device:
# the config is copied to /etc/sceptre/config.xml, the config and the
# bennu-field-deviced binary are copied to the "sceptre" user's home directory
# (served by vsftpd), and bennu-watcherd starts the field device.
#
# FTP is forwarded to 127.0.0.1:2121, and the vsftpd passive ports 30000-30009
# are forwarded to the same ports on 127.0.0.1.
#
# Requirements: curl, python3, qemu-system-x86_64, qemu-img, and virt-customize
# (libguestfs-tools). KVM is used if /dev/kvm is accessible.
#
# Usage:
#   scripts/run-bennu-vm.sh digest                       Print digest of the image file
#   scripts/run-bennu-vm.sh pull <image>                 Download the image
#   scripts/run-bennu-vm.sh start <image> <config> <dir> Boot the VM, wait for FTP
#   scripts/run-bennu-vm.sh stop <dir>                   Stop the VM
#
# Environment variables:
#   BENNU_IMAGE_TAG     Image tag to download (default: latest)
#   BENNU_FTP_PORT      Local port to forward FTP to (default: 2121)
#   BENNU_BOOT_TIMEOUT  Seconds to wait for FTP after booting (default: 600)
#
# Example:
#   scripts/run-bennu-vm.sh pull bennu.qc2
#   scripts/run-bennu-vm.sh start bennu.qc2 examples/devices/sceptre/ep/dnp3-server.xml ./bennu-vm
#   peat pull -d sceptre -i 127.0.0.1 --assume-online -c examples/peat-config-sceptre-testing.yaml
#   scripts/run-bennu-vm.sh stop ./bennu-vm

set -euo pipefail

REGISTRY="https://ghcr.io"
REPOSITORY="sandialabs/sceptre-phenix-images/bennu.qc2"
IMAGE_TAG="${BENNU_IMAGE_TAG:-latest}"
FTP_PORT="${BENNU_FTP_PORT:-2121}"
BOOT_TIMEOUT="${BENNU_BOOT_TIMEOUT:-600}"
PASV_MIN=30000
PASV_MAX=30009

usage() {
    sed -n '/^# Usage:/,/^# Example:/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'
    exit 1
}

registry_token() {
    curl -fsS "${REGISTRY}/token?scope=repository:${REPOSITORY}:pull" |
        python3 -c 'import json, sys; print(json.load(sys.stdin)["token"])'
}

# Digest of the qcow2 file in the OCI artifact, used as a cache key
image_digest() {
    local token
    token="$(registry_token)"
    curl -fsS \
        -H "Authorization: Bearer ${token}" \
        -H "Accept: application/vnd.oci.image.manifest.v1+json" \
        "${REGISTRY}/v2/${REPOSITORY}/manifests/${IMAGE_TAG}" |
        python3 -c 'import json, sys; print(json.load(sys.stdin)["layers"][0]["digest"])'
}

pull_image() {
    local image="$1"
    local token digest
    token="$(registry_token)"
    digest="$(image_digest)"
    echo "Downloading ${REPOSITORY}:${IMAGE_TAG} (${digest}) to ${image}"
    curl -fSL --retry 3 -H "Authorization: Bearer ${token}" \
        -o "${image}.part" "${REGISTRY}/v2/${REPOSITORY}/blobs/${digest}"
    echo "${digest#sha256:}  ${image}.part" | sha256sum -c -
    mv "${image}.part" "${image}"
}

start_vm() {
    local image config workdir
    image="$(realpath "$1")"
    config="$(realpath "$2")"
    workdir="$3"
    mkdir -p "${workdir}"
    workdir="$(realpath "${workdir}")"

    # Overlay so the downloaded image is never modified
    qemu-img create -q -f qcow2 -b "${image}" -F qcow2 "${workdir}/bennu.qcow2"

    # Runs on boot. Networking is set up by hand because phenix normally does
    # it, and the rest is what the phenix SCEPTRE app's startup script does
    # for a field device (sceptre_start.mako in sandialabs/sceptre-phenix-apps).
    cat > "${workdir}/firstboot.sh" << 'EOF'
#!/bin/sh
exec > /dev/ttyS0 2>&1
set -x
# First interface backed by a (virtio) device, not a virtual interface
iface="$(basename "$(dirname "$(ls -d /sys/class/net/*/device | head -n 1)")")"
ip link set "${iface}" up
ip addr add 10.0.2.15/24 dev "${iface}" || true
ip route add default via 10.0.2.2 || true
mkdir -p /etc/sceptre/log
cd /etc/sceptre
echo "[Hashes]
reghash = `sha256sum /usr/bin/bennu-field-deviced | awk '{print $1}'`
shellhashA = `sed 's/\x5f\x53\x48\x45\x4c\x4c\x5f\x30/\x5f\x53\x48\x45\x4c\x4c\x5f\x31/g' /usr/bin/bennu-field-deviced > /tmp/foo && sha256sum /tmp/foo | awk '{print $1}' && rm /tmp/foo`
shellhashB = `python3 -c "f1=open('/usr/bin/bennu-field-deviced','rb').read();f2=open('/tmp/foo','wb');f2.write(f1.replace(b'SHELL_0',b'SHELL_1'));f2.close()" && sha256sum /tmp/foo | awk '{print $1}' && rm /tmp/foo`
" > /etc/sceptre/watcher.ini
cp /usr/bin/bennu-field-deviced /etc/sceptre/config.xml /home/sceptre/
chown sceptre:sceptre /home/sceptre/*
systemd-run --scope --unit=bennu-watcherd bennu-watcherd restart --f /etc/sceptre/config.xml --b /home/sceptre/bennu-field-deviced.firmware --w /etc/sceptre/watcher.ini
systemctl restart vsftpd
sleep 5
ls -la /home/sceptre
ps aux | grep '[b]ennu'
ss -ltnp
if pgrep -x bennu-field-dev > /dev/null; then
    echo "BENNU-VM-READY"
else
    echo "BENNU-VM-FAILED: bennu-field-deviced is not running"
    cat /etc/sceptre/log/*.log
fi
EOF

    echo "Customizing VM image"
    # --no-network: the libguestfs appliance network fails on Ubuntu 24.04 runners
    LIBGUESTFS_BACKEND=direct virt-customize --no-network -a "${workdir}/bennu.qcow2" \
        --mkdir /etc/sceptre/log \
        --upload "${config}:/etc/sceptre/config.xml" \
        --append-line "/etc/vsftpd.conf:pasv_min_port=${PASV_MIN}" \
        --append-line "/etc/vsftpd.conf:pasv_max_port=${PASV_MAX}" \
        --firstboot "${workdir}/firstboot.sh"

    local accel="tcg"
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        accel="kvm"
    fi

    local hostfwd="hostfwd=tcp:127.0.0.1:${FTP_PORT}-:21"
    for port in $(seq "${PASV_MIN}" "${PASV_MAX}"); do
        hostfwd="${hostfwd},hostfwd=tcp:127.0.0.1:${port}-:${port}"
    done

    echo "Booting VM (accel: ${accel})"
    qemu-system-x86_64 \
        -name bennu \
        -machine "q35,accel=${accel}" \
        -cpu max \
        -smp 2 \
        -m 2048 \
        -drive "file=${workdir}/bennu.qcow2,if=virtio,format=qcow2" \
        -netdev "user,id=net0,${hostfwd}" \
        -device virtio-net-pci,netdev=net0 \
        -display none \
        -serial "file:${workdir}/serial.log" \
        -pidfile "${workdir}/qemu.pid" \
        -daemonize

    echo "Waiting up to ${BOOT_TIMEOUT} seconds for the field device and FTP"
    local start="${SECONDS}"
    until grep -q "BENNU-VM-READY" "${workdir}/serial.log" 2> /dev/null &&
        curl -fsS --max-time 10 "ftp://sceptre:sceptre@127.0.0.1:${FTP_PORT}/" > /dev/null 2>&1; do
        if grep -q "BENNU-VM-FAILED" "${workdir}/serial.log" 2> /dev/null ||
            [ $((SECONDS - start)) -ge "${BOOT_TIMEOUT}" ]; then
            echo "The VM failed to start or timed out, serial log:"
            cat "${workdir}/serial.log" || true
            stop_vm "${workdir}"
            exit 1
        fi
        sleep 5
    done
    echo "VM is ready after $((SECONDS - start)) seconds"
    curl -fsS "ftp://sceptre:sceptre@127.0.0.1:${FTP_PORT}/"
}

stop_vm() {
    local workdir="$1"
    if [ -f "${workdir}/qemu.pid" ]; then
        kill "$(cat "${workdir}/qemu.pid")" || true
        rm -f "${workdir}/qemu.pid"
    fi
}

case "${1:-}" in
    digest) image_digest ;;
    pull) [ $# -eq 2 ] || usage; pull_image "$2" ;;
    start) [ $# -eq 4 ] || usage; start_vm "$2" "$3" "$4" ;;
    stop) [ $# -eq 2 ] || usage; stop_vm "$2" ;;
    *) usage ;;
esac
