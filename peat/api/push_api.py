from pathlib import Path
from typing import Literal, get_args

from peat import PeatError, consts, datastore, log, module_api, utils
from peat.protocols import hosts_to_ips, sort_ips

from .scan_api import scan


def push(
    targets: list[str],
    comm_type: consts.AllowedCommTypes,
    device_types: list[str],
    input_source: Path | str,
    push_type: Literal["config", "firmware"],
    skip_scan: bool = False,
) -> bool:
    """
    Push (upload) configuration or firmware to devices.

    .. note::
       By default all targets are scanned and verified, and only the devices that
       are successfully verified are pushed to. This enables this function to be
       used without requiring a scan to be done and ensuring pushes are not
       performed to invalid devices. This behavior can be disabled by setting
       ``PUSH_SKIP_SCAN`` to True or passing ``--push-skip-scan`` on the CLI.

    Args:
        targets: Devices to push to, such as network hosts or serial ports
        comm_type: Method of communication for the push. Allowed values:

            - ``unicast_ip``
            - ``broadcast_ip``
            - ``serial``
        device_types: Names of device modules or module aliases to use. If
            scanning is disabled this should be a single device type.
        input_source: Path of the file to push, as a string
        push_type: Type of push being performed. Valid push types are
            "config" and "firmware".
        skip_scan: If device verification (scanning) should be skipped.
            NOTE: this currently only applies to unicast_ip devices.

    Returns:
        If the push was successful

    Raises:
        PeatError: If the push failed due to an issue with configuration
          or arguments, such as invalid device types or push type.
    """
    source = utils.check_file(input_source)
    if source is None:
        raise PeatError(f"bad input source '{source}'")

    if push_type not in get_args(consts.PushType):
        raise PeatError(
            f"Invalid '{push_type}' (supported types: {get_args(consts.PushType)})"
        )

    # TODO: make input a list of
    #   (device_id, device_comm_type, device_peat_module)

    # Skip scan on push (assume all devices online)
    if skip_scan:
        log.warning(f"Skipping verification scan and pushing to {len(targets)} targets")
        if len(device_types) > 1:
            raise PeatError(
                "more than 1 device type specified when PUSH_SKIP_SCAN is enabled"
            )
        modules = module_api.lookup_types(device_types, filter_attr="ip_methods")

        ips = sort_ips(hosts_to_ips(targets))
        if not ips:
            log.error("Push failed: no IP targets were valid")
            return False

        devices = []  # type: list[DeviceData]
        for ip in ips:
            dev = datastore.get(ip)
            dev._is_active = True
            dev._is_verified = True
            dev._module = modules[0]
            devices.append(dev)
    else:
        scan_summary = scan(targets, comm_type, device_types)  # type: ignore
        if not scan_summary or not scan_summary["hosts_verified"]:
            log.error("Push failed: no devices were found in scan")
            return False

        devices = datastore.verified  # type: list[DeviceData]

    log.info(f"Beginning push to {len(devices)} devices")
    for device in devices:
        try:
            push_result = device._module.push(
                dev=device,
                to_push=source,
                push_type=push_type,
            )
        except Exception:
            log.exception(f"Failed to push to {dev.get_id()}")
            return False

        if not push_result:
            return False

    log.info(f"Finished pushing to {len(devices)} devices")
    return True


__all__ = ["push"]
