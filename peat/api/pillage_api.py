import contextlib
import getpass
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

# Allow module to be imported without errors
# on non-Linux systems (Windows and OSX).
# kmodpy is only used for mounting disk images on Linux.
try:
    import kmodpy

    KMODPY_INSTALLED = True
except (ImportError, OSError):
    KMODPY_INSTALLED = False

from peat import config, consts, log, utils

# Keep track if the nbd module was already loaded when pillage started
# don't remove it if it was.  Keep the system in the same state when done
# pillaging
NBD_ALREADY_LOADED = False

#: Disk image formats that Windows can mount natively (with ``Mount-DiskImage``).
#: Other formats are converted to VHDX with ``qemu-img`` before mounting.
WINDOWS_NATIVE_IMAGE_FORMATS: Final[tuple[str, ...]] = (".vhd", ".vhdx", ".iso")

#: Directories in the root of a drive, mount, or disk image that are skipped when searching.
#: These are Windows system directories that won't have project files in them.
#: Names are compared case-insensitively, since Windows paths are case-insensitive.
EXCLUDED_DIRS: Final[tuple[str, ...]] = (
    "Windows",
    "System Volume Information",
    "PerfLogs",
    "MSOCache",
    "cygwin64",
    "Recovery",
    "Boot",
    "$Recycle.Bin",
    "bootmgr",
)

#: OEM ID in the boot sector of a BitLocker encrypted volume, at offset 3
BITLOCKER_SIGNATURE: Final[bytes] = b"-FVE-FS-"

#: Magic bytes at the start of a LUKS (version 1 or 2) encrypted volume
LUKS_SIGNATURE: Final[bytes] = b"LUKS\xba\xbe"

#: Label at the start of the label sector of a LVM physical volume (one of the first 4 sectors)
LVM_LABEL: Final[bytes] = b"LABELONE"

#: Type of a LVM2 physical volume, at offset 24 in its label sector
LVM_TYPE: Final[bytes] = b"LVM2 001"

#: Format of a BitLocker recovery password: 48 digits, in 8 groups of 6 separated by dashes
BITLOCKER_RECOVERY_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(r"\d{6}(?:-\d{6}){7}")

#: Times to prompt for the password of a locked volume, if there isn't a password file
MAX_PASSWORD_PROMPTS: Final[int] = 3

#: Network block device that disk images are attached to on Linux
NBD_DEVICE: Final[str] = "/dev/nbd1"

#: Seconds to wait for a command used for mounting images on Linux to finish
LINUX_COMMAND_TIMEOUT: Final[float] = 120.0

# Scripts for mounting disk images on Windows. The image path is passed in
# an environment variable, to avoid quoting issues and command injection.

_PS_ATTACHED_SCRIPT: Final[str] = r"""
$ErrorActionPreference = 'Stop'
[bool](Get-DiskImage -ImagePath $env:PEAT_PILLAGE_IMAGE).Attached
"""

# Mounts the disk image read-only (unless it's already attached), waits for
# Windows to bring all of its volumes online, then prints the volumes as JSON.
# Partitions on a disk come online one at a time, so it waits until the number
# of volumes stops changing, to avoid missing any.
_PS_MOUNT_SCRIPT: Final[str] = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$imagePath = $env:PEAT_PILLAGE_IMAGE
$alreadyAttached = (Get-DiskImage -ImagePath $imagePath).Attached
if (-not $alreadyAttached) {
    Mount-DiskImage -ImagePath $imagePath -Access ReadOnly | Out-Null
}
$volumes = @()
$previousCount = -1
for ($i = 0; $i -lt 30; $i++) {
    # ISO images are optical drives with one volume, VHDs are disks with partitions
    $disk = Get-DiskImage -ImagePath $imagePath | Get-Disk -ErrorAction SilentlyContinue
    if ($disk) {
        # Windows Server's default SAN policy leaves newly attached disks offline.
        # Disks that were already attached are left as they are.
        if ($disk.IsOffline -and -not $alreadyAttached) {
            Set-Disk -Number $disk.Number -IsOffline $false -ErrorAction SilentlyContinue
        }
        $volumes = @($disk | Get-Partition -ErrorAction SilentlyContinue |
            Get-Volume -ErrorAction SilentlyContinue)
    } else {
        $volumes = @(Get-DiskImage -ImagePath $imagePath |
            Get-Volume -ErrorAction SilentlyContinue)
    }
    if ($volumes.Count -gt 0 -and $volumes.Count -eq $previousCount) { break }
    $previousCount = $volumes.Count
    Start-Sleep -Milliseconds 500
}
# The lock status of volumes without a readable filesystem, if the BitLocker
# module is available (it isn't on Windows Server without the BitLocker feature)
$bitlocker = [bool](Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)
$result = [PSCustomObject]@{
    volumes = @($volumes | ForEach-Object {
        $letter = if ($_.DriveLetter) { [string]$_.DriveLetter } else { '' }
        $fs = [string]$_.FileSystemType
        $lockStatus = ''
        if ($bitlocker -and (-not $fs -or $fs -eq 'Unknown' -or $fs -eq 'RAW')) {
            $mountPoint = if ($letter) { "$($letter):" } else { [string]$_.Path }
            try {
                $lockStatus = [string](Get-BitLockerVolume -MountPoint $mountPoint).LockStatus
            } catch { }
        }
        [PSCustomObject]@{
            drive_letter = $letter
            path = [string]$_.Path
            filesystem = $fs
            label = [string]$_.FileSystemLabel
            bitlocker = $lockStatus
        }
    })
}
ConvertTo-Json -InputObject $result -Depth 3 -Compress
"""

_PS_UNMOUNT_SCRIPT: Final[str] = r"""
$ErrorActionPreference = 'Stop'
$imagePath = $env:PEAT_PILLAGE_IMAGE
if ((Get-DiskImage -ImagePath $imagePath).Attached) {
    Dismount-DiskImage -ImagePath $imagePath | Out-Null
}
"""

_PS_BITLOCKER_AVAILABLE_SCRIPT: Final[str] = r"""
[bool](Get-Command Unlock-BitLocker -ErrorAction SilentlyContinue)
"""

# Unlocks a BitLocker volume, then waits for Windows to mount its filesystem and
# prints the filesystem type. The secret is passed in an environment variable,
# so it isn't in the command line of the process. Unlock-BitLocker takes the
# password as a SecureString, or a recovery password (48 digits) as a string.
_PS_UNLOCK_SCRIPT: Final[str] = r"""
$ErrorActionPreference = 'Stop'
$mountPoint = $env:PEAT_PILLAGE_VOLUME
$secret = $env:PEAT_PILLAGE_SECRET
$env:PEAT_PILLAGE_SECRET = $null
if ($env:PEAT_PILLAGE_SECRET_TYPE -eq 'recovery') {
    Unlock-BitLocker -MountPoint $mountPoint -RecoveryPassword $secret | Out-Null
} else {
    $password = ConvertTo-SecureString -String $secret -AsPlainText -Force
    Unlock-BitLocker -MountPoint $mountPoint -Password $password | Out-Null
}
$secret = $null
if ((Get-BitLockerVolume -MountPoint $mountPoint).LockStatus -ne 'Unlocked') {
    [Console]::Error.WriteLine('The volume is still locked after Unlock-BitLocker')
    exit 2
}
$fs = ''
for ($i = 0; $i -lt 20; $i++) {
    $fs = [string](Get-Volume -Path $env:PEAT_PILLAGE_VOLUME_PATH).FileSystemType
    if ($fs -and $fs -ne 'Unknown' -and $fs -ne 'RAW') { break }
    Start-Sleep -Milliseconds 500
}
$fs
"""

_PS_LOCK_SCRIPT: Final[str] = r"""
$ErrorActionPreference = 'Stop'
Lock-BitLocker -MountPoint $env:PEAT_PILLAGE_VOLUME -ForceDismount | Out-Null
"""

#: Seconds to wait for a PowerShell command used for mounting images to finish
POWERSHELL_TIMEOUT: Final[float] = 120.0

# TODO: integrate pillage with parse. Pillage results should go in peat_results.


def pillage(source: str, password_file: Path | str | None = None) -> bool:
    """
    peat pillage.

    Args:
        source: Path of a directory or disk image to pillage
        password_file: File with passwords or BitLocker recovery passwords
            to unlock encrypted volumes on a disk image, one per line
            (see :class:`UnlockSecrets`)

    Returns:
        If pillaging was successful
    """
    if not config.PILLAGE:
        log.error(
            "No Pillage config specified! Make sure the 'pillage' section "
            "is included in the peat config file!"
        )
        return False

    results_path = Path("pillage_results")
    if not results_path.exists():
        results_path.mkdir()

    log.info(f"Pillage source path: {source}")
    source_path = Path(source)

    # Validate source exists
    if source_path.exists():
        if source_path.is_dir():
            log.info(f"Pillaging directory {source}")
            if password_file:
                log.warning("Ignoring the password file, since the source is a directory")
            return search(source_path, results_path)

        elif source_path.is_file():
            secrets = UnlockSecrets(password_file)
            if not secrets.load():
                return False

            if consts.WINDOWS:
                return pillage_image_windows(source_path, results_path, secrets)

            # TODO: build in support for images made of up smaller image files
            return pillage_image_linux(source_path, results_path, secrets)
        else:
            log.error("Unsupported source type")
            return False

    log.error(f"Source ({source}) does not exist")
    return False


def is_recovery_password(secret: str) -> bool:
    """
    If a secret is formatted like a BitLocker recovery password
    (48 digits, in 8 groups of 6 separated by dashes).
    """
    return BITLOCKER_RECOVERY_PASSWORD_RE.fullmatch(secret.strip()) is not None


class UnlockSecrets:
    """
    Passwords and BitLocker recovery passwords used to unlock encrypted volumes.

    Secrets are read from a password file, with one password or recovery password
    per line. Each line is used exactly as written, only the line ending is removed,
    and empty lines are ignored. If there isn't a password file and PEAT is running
    in an interactive terminal, the user is prompted for a password when a locked
    volume is found instead.

    Secrets are never logged, and are passed to other programs through
    stdin or environment variables, never as command line arguments.
    """

    def __init__(self, password_file: Path | str | None = None) -> None:
        self.password_file: Path | None = Path(password_file) if password_file else None
        self._secrets: list[str] = []

    def load(self) -> bool:
        """
        Read the password file, if there is one.

        Returns:
            If the password file was read successfully, or there isn't one
        """
        if not self.password_file:
            return True

        try:
            text = self.password_file.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as ex:
            log.error(f"Failed to read password file '{self.password_file}': {ex}")
            return False

        self._secrets = [line.rstrip("\r") for line in text.split("\n") if line.rstrip("\r")]
        if not self._secrets:
            log.error(f"Password file '{self.password_file}' doesn't have any passwords in it")
            return False

        log.info(
            f"Read {len(self._secrets)} passwords from '{self.password_file}', "
            f"to try on encrypted volumes"
        )
        return True

    @staticmethod
    def can_prompt() -> bool:
        """If PEAT is running in an interactive terminal, so the user can be prompted."""
        try:
            return bool(sys.stdin and sys.stdin.isatty())
        except (AttributeError, ValueError):
            return False

    def candidates(self, volume: str) -> Iterator[str]:
        """
        The secrets to try on a locked volume, in order.

        Secrets from the password file (and ones that unlocked other volumes)
        are tried first. Then, if there isn't a password file and PEAT is running
        in an interactive terminal, the user is prompted, up to
        :data:`MAX_PASSWORD_PROMPTS` times, or until they enter an empty password.
        """
        yield from list(self._secrets)

        if self.password_file or not self.can_prompt():
            return

        for _ in range(MAX_PASSWORD_PROMPTS):
            try:
                secret = getpass.getpass(
                    f"Password or BitLocker recovery password for {volume} "
                    f"(leave empty to skip it): "
                )
            except EOFError:
                return
            if not secret:
                return
            yield secret

    def remember(self, secret: str) -> None:
        """Remember a secret that unlocked a volume, to try it first on other volumes."""
        if secret not in self._secrets:
            self._secrets.insert(0, secret)


def _locked_volume_message(name: str, label: str) -> str:
    return (
        f"Skipping volume {name}, it's encrypted with {label} and locked. To search "
        f"it, run pillage with '--password-file FILE', where FILE has the password "
        f"or recovery password on a line, or run it in a terminal to be prompted "
        f"for the password."
    )


def validate_image_mounting() -> bool:
    """Ensure all the requirements needed to mount an image are satisfied.

    In order to mount an image and search, certain conditions must be met:

    - PEAT must be run as ``root``
    - PEAT must be run on a Linux system and not on Windows Subsystem for Linux (WSL).
      Windows is handled separately, by :func:`validate_image_mounting_windows`.
    - ``kmodpy`` Python package must be installed
    - ``qemu-nbd`` must be installed and available in the system PATH

    ``cryptsetup`` (for encrypted volumes) and ``lvm`` (for LVM volumes)
    are only checked for if the image has volumes that need them.

    Returns:
        If the requirements for mounting are met
    """
    if consts.WSL or not consts.LINUX:
        log.error(
            "To mount an image for searching, you must be running on Linux "
            "or Windows (WSL and OSX are not supported at this time). If you "
            "are using WSL, run peat.exe on Windows instead."
        )
        return False
    elif os.geteuid() != 0:
        log.error("To mount an image for searching, you must be running as root")
    elif not KMODPY_INSTALLED:
        log.error("To mount an image for searching, you must have kmodpy installed")
    elif not shutil.which("qemu-nbd"):
        log.error(
            "Could not find 'qemu-nbd', which is required to mount a disk "
            "image. To fix this, install the 'qemu-utils' package: "
            "'sudo apt-get install qemu-utils'"
        )
    else:
        return True

    return False


@dataclass
class _LinuxImage:
    """What was set up to pillage a disk image on Linux, so it can be cleaned up."""

    loaded_nbd: bool = False
    nbd_connected: bool = False
    #: Names of device mapper devices opened with cryptsetup
    mappers: list[str] = field(default_factory=list)
    #: LVM volume groups that were activated, and the LVM config used for them
    volume_groups: list[tuple[str, str]] = field(default_factory=list)
    #: Directories volumes were mounted to
    mounts: list[Path] = field(default_factory=list)


def pillage_image_linux(source: Path, results: Path, secrets: UnlockSecrets | None = None) -> bool:
    """
    Mount a disk image read-only on Linux, search its volumes, then unmount it.

    The image is attached with ``qemu-nbd``, and every partition on it is mounted
    read-only to its own directory in a ``pillage_temp_*`` directory. Partitions
    that can't be mounted (e.g. swap) are skipped. BitLocker and LUKS encrypted
    partitions are unlocked read-only with ``cryptsetup``, and LVM volume groups
    are activated read-only. Everything is cleaned up when pillage finishes,
    even if it fails or is interrupted.
    """
    if not validate_image_mounting():
        return False

    if secrets is None:
        secrets = UnlockSecrets()

    log.info(f"Pillaging image {source}")

    temp_path = Path(tempfile.mkdtemp(prefix="pillage_temp_", dir=os.getcwd()))
    image = _LinuxImage()
    success = False

    try:
        if not attach_image_linux(source, image):
            log.error("Failed to mount image")
            return False

        for device in list_partitions_linux(NBD_DEVICE):
            mount_volume_linux(device, temp_path, secrets, image)

        if not image.mounts:
            log.error("No volumes on the image could be mounted")
            return False

        searched = 0
        try:
            for mount_point in image.mounts:
                log.info(f"Pillaging volume '{mount_point.name}' (mounted at '{mount_point}')")
                if search(mount_point, results, exclude_system_dirs=True):
                    searched += 1
        except (Exception, KeyboardInterrupt) as ex:
            log.critical(f"Failed pillage search: {ex}")

        success = searched > 0
    finally:
        cleanup_image_linux(image, temp_path)

    return success


def _run_command(
    args: list[str], input_data: bytes = b"", timeout: float = LINUX_COMMAND_TIMEOUT
) -> subprocess.CompletedProcess:
    """
    Run a command used to mount images on Linux, and capture its output.

    Secrets must only be passed in ``input_data`` (stdin), never in ``args``.
    Output is captured to temporary files instead of pipes, since commands that
    start a daemon (e.g. ``qemu-nbd -c``, or FUSE filesystems) may leave a pipe
    open after they exit, which would block reading it.
    """
    log.debug(f"Running '{' '.join(args)}'")

    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            proc = subprocess.run(
                args, input=input_data, stdout=out, stderr=err, timeout=timeout, check=False
            )
            returncode = proc.returncode
        except subprocess.TimeoutExpired:
            returncode = 1
            err.write(f"timed out after {timeout} seconds".encode())
        except OSError as ex:
            returncode = 1
            err.write(str(ex).encode())

        out.seek(0)
        err.seek(0)
        return subprocess.CompletedProcess(
            args,
            returncode,
            stdout=out.read().decode("utf-8", errors="replace"),
            stderr=err.read().decode("utf-8", errors="replace").strip(),
        )


def _run_failed(proc: subprocess.CompletedProcess) -> str:
    return f"Failed to run '{' '.join(proc.args)}' (return code: {proc.returncode})" + (
        f": {proc.stderr}" if proc.stderr else ""
    )


def attach_image_linux(source: Path, image: _LinuxImage) -> bool:
    """Attach a disk image read-only to :data:`NBD_DEVICE` with ``qemu-nbd``."""
    global NBD_ALREADY_LOADED

    NBD_ALREADY_LOADED = "nbd" in list_loaded_modules()
    if not NBD_ALREADY_LOADED:
        try:
            # Equivalent of "modprobe nbd"
            kmodpy.Kmod().modprobe("nbd")
        except Exception as e:
            log.error(f"Failed to load 'nbd' kernel module: {e}")
            return False
        image.loaded_nbd = True

    proc = _run_command(["qemu-nbd", "-r", "-c", NBD_DEVICE, str(source)])
    if proc.returncode != 0:
        log.error(_run_failed(proc))
        return False
    image.nbd_connected = True

    # Give the kernel time to find the partitions, and udev to create their devices
    time.sleep(0.5)
    if shutil.which("udevadm"):
        _run_command(["udevadm", "settle", "--timeout=10"])

    return True


def list_partitions_linux(device: str, sys_block: Path = Path("/sys/block")) -> list[str]:
    """
    The partitions of a block device (e.g. ``/dev/nbd1p1``), in order.

    Returns:
        Paths of the partition devices, or the device itself
        if it doesn't have a partition table
    """
    name = Path(device).name
    partitions = []

    for part in (sys_block / name).glob(f"{name}p*"):
        number = part.name[len(name) + 1 :]
        if number.isdigit():
            partitions.append((int(number), f"/dev/{part.name}"))

    if not partitions:
        log.info(f"'{device}' doesn't have any partitions, searching it as a single volume")
        return [device]

    devices = [dev for _, dev in sorted(partitions)]
    log.debug(f"Partitions on '{device}': {devices}")
    return devices


def is_luks(header: bytes) -> bool:
    """If the header of a volume is from a LUKS (version 1 or 2) encrypted volume."""
    return header[:6] == LUKS_SIGNATURE


def is_lvm(header: bytes) -> bool:
    """If the header of a volume is from a LVM2 physical volume."""
    # The label is in one of the first 4 sectors, usually the second one
    for offset in range(0, 2048, 512):
        sector = header[offset : offset + 512]
        if sector[:8] == LVM_LABEL and sector[24:32] == LVM_TYPE:
            return True
    return False


def mount_volume_linux(
    device: str, temp_path: Path, secrets: UnlockSecrets, image: _LinuxImage
) -> None:
    """
    Mount a volume (partition) read-only in its own directory in ``temp_path``,
    unlocking it first if it's encrypted, and activating it if it's LVM.
    Volumes that can't be mounted are logged and skipped.
    """
    name = Path(device).name
    header = read_volume_header(device)

    if is_bitlocker(header) or is_luks(header):
        mapper = unlock_volume_linux(
            device, "bitlk" if is_bitlocker(header) else "luks", secrets, image
        )
        if not mapper:
            return
        device = f"/dev/mapper/{mapper}"
        header = read_volume_header(device)

    if is_lvm(header):
        for lv_name, lv_device in activate_lvm_linux(device, image):
            mount_linux(lv_device, temp_path / f"{name}_{lv_name}", image)
    else:
        mount_linux(device, temp_path / name, image)


def mount_linux(device: str, mount_point: Path, image: _LinuxImage) -> bool:
    """Mount a filesystem read-only."""
    mount_point.mkdir()

    proc = _run_command(["mount", "-o", "ro", device, str(mount_point)])
    if proc.returncode != 0:
        log.info(
            f"Skipping volume '{device}', it couldn't be mounted. It may be swap, "
            f"an extended partition, or a filesystem this system doesn't support. "
            f"{_run_failed(proc)}"
        )
        mount_point.rmdir()
        return False

    image.mounts.append(mount_point)
    log.info(f"Mounted volume '{device}' read-only at '{mount_point}'")
    return True


def unlock_volume_linux(
    device: str, kind: str, secrets: UnlockSecrets, image: _LinuxImage
) -> str | None:
    """
    Unlock a BitLocker (``kind`` is ``"bitlk"``) or LUKS (``"luks"``) encrypted
    volume read-only, with ``cryptsetup open --readonly``. The key is passed to
    ``cryptsetup`` through stdin. BitLocker volumes can be unlocked with a password
    or recovery password.

    Returns:
        Name of the unlocked device in ``/dev/mapper/``,
        or :obj:`None` if it couldn't be unlocked
    """
    label = "BitLocker" if kind == "bitlk" else "LUKS"

    if not shutil.which("cryptsetup"):
        log.error(
            f"Skipping volume '{device}', it's encrypted with {label}, and unlocking "
            f"it requires 'cryptsetup', which wasn't found. To fix this, install the "
            f"'cryptsetup' package: 'sudo apt-get install cryptsetup'"
        )
        return None

    mapper = f"peat_pillage_{os.getpid()}_{Path(device).name}"
    tried = 0

    for secret in secrets.candidates(f"'{device}' ({label})"):
        tried += 1
        key = secret.strip() if is_recovery_password(secret) else secret
        proc = _run_command(
            [
                "cryptsetup",
                "open",
                "--type",
                kind,
                "--readonly",
                "--key-file",
                "-",
                device,
                mapper,
            ],
            input_data=key.encode("utf-8"),
        )
        if proc.returncode == 0:
            image.mappers.append(mapper)
            secrets.remember(secret)
            log.info(f"Unlocked {label} volume '{device}' (read-only) as '/dev/mapper/{mapper}'")
            return mapper
        log.warning(
            f"Failed to unlock {label} volume '{device}' with password {tried}: {proc.stderr}"
        )

    if tried:
        log.error(
            f"Skipping volume '{device}', none of the {tried} passwords tried "
            f"unlocked it ({label})"
        )
    else:
        log.warning(_locked_volume_message(f"'{device}'", label))
    return None


def _lvm_config(device: str, volume_group: str = "") -> str:
    """
    LVM config that only lets LVM use one device, so volume groups on the host
    are left alone, and activates the logical volumes in a volume group read-only.
    """
    dev_filter = f'[ "a|^{re.escape(device)}$|", "r|.*|" ]'
    conf = f"devices {{ use_devicesfile = 0 filter = {dev_filter} global_filter = {dev_filter} }}"
    if volume_group:
        conf += f' activation {{ read_only_volume_list = [ "{volume_group}" ] }}'
    return conf


def activate_lvm_linux(device: str, image: _LinuxImage) -> list[tuple[str, str]]:
    """
    Activate the LVM volume group on a physical volume read-only.

    Volume groups with the same name as one that's already on the system are
    skipped, since their device names would conflict.

    Returns:
        List of the name and device path of each logical volume in the volume group
    """
    if not shutil.which("lvm"):
        log.error(
            f"Skipping volume '{device}', it's an LVM physical volume, and activating it "
            f"requires LVM, which wasn't found. To fix this, install the 'lvm2' package: "
            f"'sudo apt-get install lvm2'"
        )
        return []

    proc = _run_command(
        [
            "lvm",
            "pvs",
            "--config",
            _lvm_config(device),
            "--noheadings",
            "-o",
            "vg_name,vg_uuid",
            device,
        ]
    )
    fields = proc.stdout.split()
    if proc.returncode != 0 or len(fields) != 2:
        log.warning(
            f"Skipping volume '{device}', failed to read its LVM metadata. {_run_failed(proc)}"
        )
        return []
    vg_name, vg_uuid = fields

    # Volume groups on the host. The volume group on the image may be in this
    # list too (with the same UUID), if the host activated it automatically.
    host_vgs = _run_command(["lvm", "vgs", "--noheadings", "-o", "vg_name,vg_uuid"])
    for line in host_vgs.stdout.splitlines():
        host_fields = line.split()
        if len(host_fields) == 2 and host_fields[0] == vg_name and host_fields[1] != vg_uuid:
            log.error(
                f"Skipping LVM volume group '{vg_name}' on volume '{device}', since a "
                f"volume group with the same name is already on this system. To search "
                f"it, pillage the image on a system without a '{vg_name}' volume group."
            )
            return []

    conf = _lvm_config(device, vg_name)
    image.volume_groups.append((vg_name, conf))
    proc = _run_command(
        ["lvm", "vgchange", "--config", conf, "--activate", "y", "--monitor", "n", vg_name]
    )
    if proc.returncode != 0:
        # Some logical volumes may still have been activated
        log.warning(f"Failed to activate all of LVM volume group '{vg_name}'. {_run_failed(proc)}")

    proc = _run_command(["lvm", "lvs", "--config", conf, "--noheadings", "-o", "lv_name", vg_name])
    if proc.returncode != 0:
        log.warning(f"Failed to list the logical volumes in '{vg_name}'. {_run_failed(proc)}")
        return []

    # Device mapper names of logical volumes are "<vg>-<lv>", with dashes doubled
    dm_vg = vg_name.replace("-", "--")
    lvs = [(lv, f"/dev/mapper/{dm_vg}-{lv.replace('-', '--')}") for lv in proc.stdout.split()]
    log.info(
        f"Activated LVM volume group '{vg_name}' (read-only) on '{device}', with "
        f"logical volumes: {', '.join(lv for lv, _ in lvs)}"
    )
    return lvs


def cleanup_image_linux(image: _LinuxImage, temp_path: Path) -> bool:
    """
    Unmount everything that was mounted to pillage an image, deactivate LVM
    volume groups, lock encrypted volumes, detach the image, and remove the
    ``nbd`` kernel module if PEAT loaded it. Each step is attempted, even if
    earlier ones fail.

    Returns:
        If everything was cleaned up
    """
    result = unmounted = True

    for mount_point in reversed(image.mounts):
        proc = _run_command(["umount", str(mount_point)])
        if proc.returncode != 0:
            log.error(_run_failed(proc))
            result = unmounted = False
        else:
            log.debug(f"Unmounted '{mount_point}'")
            with contextlib.suppress(OSError):
                mount_point.rmdir()

    for vg_name, conf in reversed(image.volume_groups):
        proc = _run_command(["lvm", "vgchange", "--config", conf, "--activate", "n", vg_name])
        if proc.returncode != 0:
            log.error(_run_failed(proc))
            result = False

    for mapper in reversed(image.mappers):
        proc = _run_command(["cryptsetup", "close", mapper])
        if proc.returncode != 0:
            # udev may still have the device open briefly after unmounting
            time.sleep(1)
            proc = _run_command(["cryptsetup", "close", mapper])
        if proc.returncode != 0:
            log.error(_run_failed(proc))
            result = False

    if image.nbd_connected:
        result &= remove_nbd_device()
    if image.loaded_nbd:
        result &= remove_nbd_module()

    # Only delete the temp directory if nothing is still mounted in it
    if unmounted:
        shutil.rmtree(temp_path, ignore_errors=True)
        log.debug(f"Deleted temp directory '{temp_path}'")

    if not result:
        log.warning(
            f"Failed to clean up after pillaging the image. Clean up manually"
            f"{'' if unmounted else f', and then delete {temp_path}'} (see 'When "
            f"things go wrong' in the pillage documentation)."
        )

    return result


def remove_nbd_module() -> bool:
    if not NBD_ALREADY_LOADED:
        # The module is busy for a moment after the device is disconnected
        for attempt in range(10):
            try:
                kmodpy.Kmod().rmmod("nbd")
                break
            except Exception as e:
                if attempt == 9:
                    log.error(f"Failed to remove 'nbd' module: {e}")
                    return False
                time.sleep(0.5)

    return True


def remove_nbd_device() -> bool:
    proc = _run_command(["qemu-nbd", "-d", NBD_DEVICE])

    if proc.returncode != 0:
        log.error(_run_failed(proc))
        return False

    return True


def list_loaded_modules() -> list[str]:
    result = []
    km = kmodpy.Kmod()
    for mod in km.list():
        result.append(mod[0].decode("utf-8"))

    return result


def pillage_image_windows(
    source: Path, results: Path, secrets: UnlockSecrets | None = None
) -> bool:
    """
    Mount a disk image read-only on Windows, search its volumes, then unmount it.

    VHD, VHDX, and ISO images are mounted natively with ``Mount-DiskImage``.
    Other formats (raw, VMDK, qcow2, etc.) are first converted to a temporary
    VHDX file in a ``pillage_temp_*`` directory using ``qemu-img``, which must
    be installed. Volumes encrypted with BitLocker are unlocked with
    ``Unlock-BitLocker``, using the passwords in ``secrets``. Images that were
    attached before pillage started are left attached, and volumes PEAT
    unlocked on them are locked again.
    """
    if not validate_image_mounting_windows(source):
        return False

    if secrets is None:
        secrets = UnlockSecrets()

    log.info(f"Pillaging image {source}")

    # Not resolve(), which turns mapped network drives into UNC paths,
    # and those may not be visible from an Administrator terminal.
    image = Path(os.path.abspath(source))
    temp_path = None
    mount_attempted = False
    already_attached = False
    unlocked: list[str] = []
    success = False

    try:
        if image.suffix.lower() not in WINDOWS_NATIVE_IMAGE_FORMATS:
            temp_path = Path(tempfile.mkdtemp(prefix="pillage_temp_", dir=os.getcwd()))
            converted = convert_image_windows(image, temp_path)
            if not converted:
                return False
            image = converted

        already_attached = is_image_attached_windows(image)
        if already_attached is None:
            return False

        mount_attempted = True
        volumes = mount_image_windows(image)

        if volumes is None:
            log.error("Failed to mount image")
        else:
            unlock_volumes_windows(volumes, secrets, unlocked)
            try:
                success = search_volumes_windows(volumes, results)
            except (Exception, KeyboardInterrupt) as ex:
                log.critical(f"Failed pillage search: {ex}")
    finally:
        # Leave the image attached if it was attached before pillage started,
        # but lock the volumes PEAT unlocked. Otherwise, always unmount it, even
        # if mounting failed part way, which also locks the unlocked volumes.
        if mount_attempted and already_attached:
            for mount_point in unlocked:
                lock_bitlocker_windows(mount_point)
            log.info(f"Leaving '{image}' attached, since it was attached before pillage started")
        elif mount_attempted and unmount_image_windows(image):
            log.debug(f"Unmounted image '{image}'")

        if temp_path:
            try:
                shutil.rmtree(temp_path)
                log.debug(f"Deleted temp directory '{temp_path}'")
            except OSError as ex:
                log.warning(
                    f"Failed to delete temp directory '{temp_path}', delete it "
                    f"manually (see 'Cleanup' in the pillage documentation): {ex}"
                )

    return success


def validate_image_mounting_windows(source: Path) -> bool:
    """
    Ensure all the requirements needed to mount an image on Windows are satisfied.

    - PowerShell (``powershell.exe``) must be available, for ``Mount-DiskImage``
    - PEAT must be run as Administrator, unless the image is an ISO
    - ``qemu-img`` must be installed and in the system PATH, unless
      the image is a VHD, VHDX, or ISO

    Returns:
        If the requirements for mounting are met
    """
    suffix = source.suffix.lower()

    if not shutil.which("powershell"):
        log.error(
            "Could not find 'powershell.exe', which is required to mount a disk image on Windows"
        )
    elif suffix != ".iso" and not utils.are_we_superuser():
        log.error(
            "To mount a disk image for searching on Windows, you must run PEAT "
            "as Administrator (ISO images are the exception). Re-run PEAT from "
            "an Administrator PowerShell or CMD terminal."
        )
    elif suffix not in WINDOWS_NATIVE_IMAGE_FORMATS and not shutil.which("qemu-img"):
        log.error(
            f"Windows can't mount '{suffix}' images natively, only VHD, VHDX, and ISO "
            f"images. Install QEMU (https://qemu.weilnetz.de/w64/) and add "
            f"'qemu-img.exe' to the PATH so PEAT can convert the image, convert it "
            f"to VHDX yourself ('qemu-img convert -O vhdx {source.name} image.vhdx'), "
            f"or mount it with another tool and pillage the drive letter instead."
        )
    else:
        return True

    return False


def convert_image_windows(source: Path, temp_dir: Path) -> Path | None:
    """
    Convert a disk image Windows can't mount natively to a VHDX file.

    Returns:
        Path to the converted VHDX image, or :obj:`None` if the conversion failed
    """
    dest = temp_dir / f"{source.stem}.vhdx"
    qemu_args = ["qemu-img", "convert", "-O", "vhdx", str(source), str(dest)]

    log.info(
        f"Converting '{source.name}' to VHDX so Windows can mount it. This makes "
        f"a temporary copy of the image in '{temp_dir}', which may take a while "
        f"and use a lot of disk space for large images."
    )
    log.debug(f"Running '{' '.join(qemu_args)}'")

    retval = subprocess.call(qemu_args)
    if retval != 0 or not dest.is_file():
        log.error(f"Failed to run '{' '.join(qemu_args)}' (return code: {retval})")
        return None

    return dest


def _run_powershell(
    script: str, image: Path | None = None, env_vars: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    """
    Run a PowerShell script. Values the script uses, such as the image path or
    a secret, are passed to it in environment variables, never in the script.
    """
    # PowerShell 7 (pwsh) adds its own module directories to PSModulePath. If PEAT
    # is run from pwsh, Windows PowerShell inherits them and fails to load modules
    # such as Microsoft.PowerShell.Security (for ConvertTo-SecureString). Without
    # PSModulePath, Windows PowerShell uses its default module directories.
    # (os.environ keys are upper case on Windows, so compare case-insensitively)
    env = {k: v for k, v in os.environ.items() if k.lower() != "psmodulepath"}
    if image is not None:
        env["PEAT_PILLAGE_IMAGE"] = str(image)
    if env_vars:
        env.update(env_vars)
    args = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]

    try:
        return subprocess.run(
            args,
            env=env,
            capture_output=True,
            encoding="utf-8-sig",  # Strip the byte order mark, if there is one
            errors="replace",
            timeout=POWERSHELL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            args, 1, stdout="", stderr=f"timed out after {POWERSHELL_TIMEOUT} seconds"
        )


def is_image_attached_windows(image: Path) -> bool | None:
    """
    If a disk image is already attached (mounted) on Windows.

    Returns:
        If the image is attached, or :obj:`None` if the check failed
        (e.g. the file isn't a valid disk image)
    """
    proc = _run_powershell(_PS_ATTACHED_SCRIPT, image)
    result = proc.stdout.strip()

    if proc.returncode != 0 or result not in ["True", "False"]:
        log.error(
            f"Failed to check if '{image}' is attached with Get-DiskImage "
            f"(return code: {proc.returncode}): {proc.stderr.strip()}"
        )
        return None

    return result == "True"


def mount_image_windows(image: Path) -> list[dict] | None:
    """
    Mount a VHD, VHDX, or ISO image read-only using ``Mount-DiskImage``.

    If the image is already attached, it isn't mounted again. The caller is
    responsible for unmounting the image, even if this fails, since it may
    have failed after the image was mounted.

    Returns:
        List of dicts describing each volume on the image,
        or :obj:`None` if mounting failed.
    """
    log.debug(f"Mounting image '{image}' (read-only)")
    proc = _run_powershell(_PS_MOUNT_SCRIPT, image)

    if proc.returncode != 0:
        log.error(
            f"Failed to mount '{image}' with Mount-DiskImage "
            f"(return code: {proc.returncode}): {proc.stderr.strip()}"
        )
        return None

    # The JSON is the last line, in case anything else was printed before it
    lines = proc.stdout.strip().splitlines()
    try:
        info = json.loads(lines[-1] if lines else "")
    except json.JSONDecodeError:
        log.error(f"Failed to parse Mount-DiskImage output: {proc.stdout.strip()}")
        return None

    # PowerShell 5.1 doesn't serialize empty arrays nested in objects consistently
    volumes = info.get("volumes") or []
    if isinstance(volumes, dict):
        volumes = [volumes]

    log.debug(f"Mounted image '{image}' with {len(volumes)} volumes: {volumes}")
    return volumes


def unmount_image_windows(image: Path) -> bool:
    proc = _run_powershell(_PS_UNMOUNT_SCRIPT, image)

    if proc.returncode != 0:
        log.error(
            f"Failed to unmount '{image}' with Dismount-DiskImage "
            f"(return code: {proc.returncode}): {proc.stderr.strip()}. To unmount "
            f"it manually, run 'Dismount-DiskImage -ImagePath \"{image}\"' "
            f"from an Administrator PowerShell terminal."
        )
        return False

    return True


def _is_unreadable_windows(vol: dict) -> bool:
    """If Windows can't read the filesystem of a volume (or it's locked)."""
    fs = vol.get("filesystem", "")
    return not fs or fs.lower() in ["unknown", "raw"]


def _is_locked_bitlocker_windows(vol: dict) -> bool:
    """
    If a volume is encrypted with BitLocker and locked, from its lock status
    (if the BitLocker module is available), or the header of the volume.
    """
    if vol.get("bitlocker"):
        return vol["bitlocker"] == "Locked"
    return bool(vol.get("path")) and is_bitlocker(read_volume_header(vol["path"].rstrip("\\/")))


def is_bitlocker_available_windows() -> bool:
    """If the BitLocker PowerShell module (``Unlock-BitLocker``) is available."""
    proc = _run_powershell(_PS_BITLOCKER_AVAILABLE_SCRIPT)
    return proc.returncode == 0 and proc.stdout.strip() == "True"


def unlock_volumes_windows(
    volumes: list[dict], secrets: UnlockSecrets, unlocked: list[str]
) -> None:
    """
    Unlock the volumes on a mounted disk image that are encrypted with BitLocker.

    Volumes that are unlocked have their ``filesystem`` updated, and their mount
    point (drive letter or volume GUID path) is added to ``unlocked``.
    """
    locked = [
        vol for vol in volumes if _is_unreadable_windows(vol) and _is_locked_bitlocker_windows(vol)
    ]
    if not locked:
        return

    if not is_bitlocker_available_windows():
        log.error(
            f"{len(locked)} volumes on the image are encrypted with BitLocker, but they "
            f"can't be unlocked, since the BitLocker PowerShell module (Unlock-BitLocker) "
            f"isn't available. On Windows Server, install the BitLocker feature "
            f"('Install-WindowsFeature BitLocker', then restart). Alternatively, "
            f"pillage the image on Linux, which unlocks BitLocker with cryptsetup."
        )
        return

    for vol in locked:
        name = vol.get("label") or vol["path"]
        mount_point = f"{vol['drive_letter']}:" if vol.get("drive_letter") else vol["path"]
        tried = 0

        for secret in secrets.candidates(f"'{mount_point}' (BitLocker)"):
            tried += 1
            filesystem = unlock_bitlocker_windows(mount_point, vol["path"], secret)
            if filesystem is not None:
                unlocked.append(mount_point)
                secrets.remember(secret)
                vol["filesystem"] = filesystem
                log.info(f"Unlocked BitLocker volume '{name}' ({filesystem})")
                break
        else:
            if tried:
                log.error(
                    f"Couldn't unlock BitLocker volume '{name}', none of the "
                    f"{tried} passwords tried unlocked it"
                )
            else:
                log.warning(_locked_volume_message(f"'{name}'", "BitLocker"))


def unlock_bitlocker_windows(mount_point: str, volume_path: str, secret: str) -> str | None:
    """
    Unlock a BitLocker volume with ``Unlock-BitLocker``, using a password, or a recovery
    password if the secret is formatted like one (see :func:`is_recovery_password`).

    Args:
        mount_point: Drive letter (e.g. ``E:``) or volume GUID path of the volume
        volume_path: Volume GUID path of the volume (``\\\\?\\Volume{...}\\``)
        secret: Password or recovery password

    Returns:
        The filesystem of the unlocked volume, or :obj:`None` if it couldn't be unlocked
    """
    recovery = is_recovery_password(secret)
    proc = _run_powershell(
        _PS_UNLOCK_SCRIPT,
        env_vars={
            "PEAT_PILLAGE_VOLUME": mount_point,
            "PEAT_PILLAGE_VOLUME_PATH": volume_path,
            "PEAT_PILLAGE_SECRET": secret.strip() if recovery else secret,
            "PEAT_PILLAGE_SECRET_TYPE": "recovery" if recovery else "password",
        },
    )

    if proc.returncode != 0:
        log.warning(
            f"Unlock-BitLocker failed for '{mount_point}' with a "
            f"{'recovery password' if recovery else 'password'} "
            f"(return code: {proc.returncode}): {proc.stderr.strip()}"
        )
        return None

    lines = proc.stdout.strip().splitlines()
    return lines[-1].strip() if lines else ""


def lock_bitlocker_windows(mount_point: str) -> bool:
    """Lock a BitLocker volume that PEAT unlocked, with ``Lock-BitLocker``."""
    proc = _run_powershell(_PS_LOCK_SCRIPT, env_vars={"PEAT_PILLAGE_VOLUME": mount_point})

    if proc.returncode != 0:
        log.error(
            f"Failed to lock BitLocker volume '{mount_point}' (return code: "
            f"{proc.returncode}): {proc.stderr.strip()}. To lock it manually, run "
            f"'Lock-BitLocker -MountPoint \"{mount_point}\"' from an Administrator "
            f"PowerShell terminal."
        )
        return False

    log.info(f"Locked BitLocker volume '{mount_point}' again")
    return True


def search_volumes_windows(volumes: list[dict], results: Path) -> bool:
    """
    Search the volumes of a mounted disk image.

    Volumes that were assigned a drive letter are searched using it
    (e.g. ``E:\\``), otherwise the volume GUID path is used
    (e.g. ``\\\\?\\Volume{...}\\``). Volumes with a filesystem Windows
    can't read (e.g. ext4) are skipped.

    Returns:
        If at least one volume was searched successfully
    """
    searched = 0

    for vol in volumes:
        fs = vol.get("filesystem", "")
        name = vol.get("label") or vol.get("path", "")

        # Locked BitLocker volumes don't have a readable filesystem
        if _is_unreadable_windows(vol) and _is_locked_bitlocker_windows(vol):
            log.warning(f"Skipping volume '{name}', it's encrypted with BitLocker and locked")
            continue

        if _is_unreadable_windows(vol):
            log.warning(
                f"Skipping volume '{name}', its filesystem isn't readable by Windows. "
                f"To pillage it, run PEAT on Linux, which supports more filesystems."
            )
            continue

        if vol.get("drive_letter"):
            vol_path = f"{vol['drive_letter']}:\\"
        elif vol.get("path"):
            # Kept as a string, since pathlib drops the trailing backslash from
            # volume GUID paths, and without it they refer to the volume device
            # instead of the root directory of its filesystem.
            vol_path = vol["path"].rstrip("\\/") + os.sep
        else:
            log.warning(f"Skipping volume '{name}', it doesn't have a path")
            continue

        log.info(f"Pillaging volume '{vol_path}' ({fs}, label: '{vol.get('label', '')}')")
        if search(vol_path, results, exclude_system_dirs=True):
            searched += 1

    if not searched:
        log.error("No volumes on the image could be searched")
        return False

    return True


def read_volume_header(path: str, size: int = 4096) -> bytes:
    """
    Read the first bytes of a volume (e.g. ``/dev/nbd1p1``, or
    ``\\\\?\\Volume{...}`` on Windows) to check what's on it.

    On Windows, reading a volume GUID path this way can fail (with EINVAL),
    so BitLocker volumes are also detected with ``Get-BitLockerVolume``.

    Returns:
        The bytes that were read, or empty bytes if it couldn't be read
    """
    try:
        with open(path, "rb", buffering=0) as fp:
            return fp.read(size)
    except OSError as ex:
        log.debug(f"Failed to read the header of volume '{path}': {ex}")
        return b""


def is_bitlocker(header: bytes) -> bool:
    """If the header (boot sector) of a volume is from a BitLocker encrypted volume."""
    return header[3:11] == BITLOCKER_SIGNATURE


def _is_junction(path: str) -> bool:
    """
    If a path is a Windows directory junction (mount point reparse point).

    Junctions such as ``C:\\Documents and Settings`` point to other directories
    on the same system, and following them would search the same files twice.
    """
    try:
        return os.lstat(path).st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT
    except (AttributeError, OSError):
        return False


def search(source: Path | str, results: Path, exclude_system_dirs: bool | None = None) -> bool:
    """
    Search a directory for files to pillage, and copy them to the results directory.

    Args:
        source: Directory to search
        results: Directory to copy pillaged files to
        exclude_system_dirs: Skip system directories in the root of the source
            that won't have project files in them, e.g. ``Windows``
            (see :data:`EXCLUDED_DIRS`). By default, they're only skipped if
            the source is the root of a drive or mounted filesystem.

    Returns:
        If the search was successful
    """
    source = str(source)
    if not os.path.isdir(source):
        log.error(f"Failed pillage search: source path '{source}' is not a valid directory.")
        return False

    if exclude_system_dirs is None:
        exclude_system_dirs = os.path.ismount(source)

    excluded = {name.lower() for name in EXCLUDED_DIRS} if exclude_system_dirs else set()
    exclude_counter = 0
    junction_counter = 0
    errors: list[OSError] = []

    def _walk_error(err: OSError) -> None:
        # Common on live Windows systems, e.g. for folders only SYSTEM can read
        errors.append(err)
        log.debug(f"Failed to search '{err.filename}': {err.strerror}")

    for root, dirnames, filenames in os.walk(source, onerror=_walk_error):
        log.trace2(f"Searching in: {root}")

        # Prune excluded system directories in the root of the source,
        # and junctions, so os.walk doesn't descend into them.
        for dirname in list(dirnames):
            dir_path = os.path.join(root, dirname)
            if root == source and dirname.lower() in excluded:
                log.trace2(f"Skipping excluded dir '{dir_path}'")
                dirnames.remove(dirname)
                exclude_counter += 1
            elif consts.WINDOWS and _is_junction(dir_path):
                log.debug(f"Skipping directory junction '{dir_path}'")
                dirnames.remove(dirname)
                junction_counter += 1

        for filename in filenames:
            src_file = Path(root) / filename
            is_valid, config_type = is_valid_file(src_file)

            if is_valid:
                dst_file = Path(results) / config_type / filename

                # If a file with that name already exists in the results folder
                # increment a counter and append that counter to the file name
                name_only = dst_file.stem
                ext_only = dst_file.suffix
                count = 1
                while dst_file.exists():
                    dst_file = Path(results) / config_type / f"{name_only}{ext_only}.{count}"
                    count += 1

                # Prompt user if they want to copy each file
                if not config.PILLAGE["auto_copy"]:
                    auto_copy = input(
                        f"Found {src_file}, do you want to copy it to {dst_file} (Y or N):"
                    )
                    print(auto_copy, file=sys.stderr, flush=True)  # noqa: T201

                    if auto_copy == "Y":
                        copy_file(src_file, dst_file)
                    else:
                        log.warning(
                            f"[Pillage] Declined to copy {src_file} to "
                            f"{dst_file} (auto_copy is false)"
                        )
                else:
                    copy_file(src_file, dst_file)

        if not config.PILLAGE["recursive"]:
            break

    if exclude_counter:
        log.info(f"Skipped {exclude_counter} excluded subdirectories")
    if junction_counter:
        log.info(
            f"Skipped {junction_counter} directory junctions, which point to other "
            f"directories. To search where a junction points, pillage that directory."
        )

    if errors and errors[0].filename == source:
        log.error(f"Failed pillage search: couldn't read '{source}': {errors[0].strerror}")
        return False
    elif errors:
        log.warning(
            f"Couldn't search {len(errors)} directories, e.g. '{errors[0].filename}' "
            f"({errors[0].strerror}). Run PEAT as Administrator or root to search them."
        )

    return True


# TODO: function not used yet, still need to decide how to search through specific locations
#   How to search through specific directories?  Only search those listed?
#   Search through all but only validate a file if its one of those specified?
#   How to handle if one brand says search through everything and ones
#       says only a specific directory?
#   Searching through everything and then validating at a file level
#       would be easiest to implement but not be the quickest way to search.
#       If only a single location is specified that search will take the same
#       amount of time as a search with all directories.
# def create_location_list():
#     locations = []
#     all_dirs = False
#     if 'brands' in config.PILLAGE:
#         for brand_data in config.PILLAGE['brands'].values():
#             if 'locations' in brand_data:
#                 if len(brand_data['locations']) > 0:
#                     locations.append(brand_data['locations'])
#                 else:
#                     # if there is a location entry but no locations defined then look
#                     # through all directories
#                     all_dirs = True
#     if 'default' in config.PILLAGE:
#         if 'locations' in config.PILLAGE['default']:
#             if len(config.PILLAGE['default']) > 0:
#                 locations.append(config.PILLAGE['default']['locations'])
#             else:
#                 # if there is a location entry but no locations defined then look
#                 # through all directories
#                 all_dirs = True
#     return all_dirs, locations


def copy_file(src: Path, dst: Path) -> None:
    if not dst.parent.exists():
        dst.parent.mkdir(exist_ok=True, parents=True)

    try:
        shutil.copyfile(str(src), str(dst))
    except OSError as ex:
        # e.g. the file is locked by another program on Windows
        log.error(f"[Pillage] Failed to copy {src} to {dst}: {ex}")
        return

    log.info(f"[Pillage] Copied {src} to {dst}")


def is_valid_file(_file: Path):
    """
    Determine if a file is valid based on the search criteria
    in the Pillage configuration.
    """
    brand_list = []
    valid_file = False
    config_type = ""

    if "brands" in config.PILLAGE:
        for brand, brand_data in config.PILLAGE["brands"].items():
            valid_file, condition = check_file_conditions(_file, brand_data)
            if valid_file:
                brand_list.append((brand, condition))

        if len(brand_list) > 0:
            brand_str = ""
            for brand, condition in brand_list:
                brand_str += f"{brand} ({condition}), "

            log.info(
                f"[Pillage] {_file} is valid for the following "
                f"brands and conditions: {brand_str[:-2]}"
            )
            valid_file = True
            config_type = brand_list[0][0]
            if len(brand_list) > 1:
                config_type = "MULTIPLE"

    # If a valid file wasn't found using the specific brand conditions check for default files
    if not valid_file and "default" in config.PILLAGE:
        valid_file, condition = check_file_conditions(_file, config.PILLAGE["default"])
        if valid_file:
            log.info(f"[Pillage] {_file} is valid for DEFAULT condition {condition}")
            config_type = "DEFAULT"

    return valid_file, config_type


def check_file_conditions(_file: Path, conditions: dict[str, list]) -> tuple:
    found = False
    condition_type = ""

    if conditions.get("filenames"):
        for cond_fname in conditions["filenames"]:
            if _file.name.lower() == cond_fname.lower():
                condition_type = "FILENAME"
                found = True
                break

    if not found and conditions.get("extensions"):
        for cond_ext in conditions["extensions"]:
            if _file.suffix[1:].lower() == cond_ext.lower():
                condition_type = "EXTENSION"
                found = True
                break

    # TODO: Check for magic number

    return found, condition_type
