import timeit
from operator import itemgetter

from peat import PeatError, __version__, config, consts, datastore, log, module_api, state, utils
from peat.protocols import hosts_to_ips, sort_ips

from .scan_api import scan


def pull(
    targets: list[str],
    comm_type: consts.AllowedCommTypes,
    device_types: list[str],
    skip_scan: bool = False,
) -> dict[str, dict | list | str | float | int] | None:
    """Pull from devices.

    Args:
        targets: Devices to pull from, such as network hosts or serial ports
        comm_type: Method of communication for the pull. Allowed values:

            - ``unicast_ip``
            - ``broadcast_ip``
            - ``serial``
        device_types: Names of device modules or module aliases to use
        skip_scan: If device verification (scanning) should be skipped.
            NOTE: this currently only applies to unicast_ip devices.

    Returns:
        :ref:`pull-summary` as a :class:`dict`, or :obj:`None` if an error occurred
    """
    if skip_scan:
        log.warning(f"Skipping verification scan and pulling from {len(targets)} targets")

        ips = sort_ips(hosts_to_ips(targets))
        if not ips:
            log.error("Pull failed: no IP targets were valid")
            state.error = True
            return None

        # Build per-IP module map from YAML config hosts
        host_module_map: dict = {}
        for host in config.HOSTS or []:
            ip = host.get("identifiers", {}).get("ip")
            peat_module = host.get("peat_module")
            if ip and peat_module:
                resolved = module_api.lookup_types([peat_module], filter_attr="ip_methods")
                if resolved:
                    host_module_map[ip] = resolved[0]

        # Fallback to the explicitly specified device types when no per-host mapping exists
        fallback_modules = module_api.lookup_types(device_types, filter_attr="ip_methods")
        if len(fallback_modules) > 1 and not host_module_map:
            raise PeatError(
                "More than 1 device type specified with --skip-scan and no per-host "
                "'peat_module' found in YAML config. Specify a single module using '-d' or "
                "add 'peat_module' to each host entry in the YAML config."
            )
        fallback_module = fallback_modules[0] if len(fallback_modules) == 1 else None

        devices = []
        for ip in ips:
            module = host_module_map.get(ip) or fallback_module
            if module is None:
                log.error(f"No module resolved for {ip}, unable to pull")
                state.error = True
                return None

            dev = datastore.get(ip)
            dev._is_active = True
            dev._is_verified = True
            dev._module = module
            devices.append(dev)

        if not devices:
            log.error("Pull failed: no valid devices to pull from")
            state.error = True
            return None
    else:
        scan_summary = scan(targets, comm_type, device_types)

        if not scan_summary or not scan_summary["hosts_verified"]:
            log.error("Pull failed: no devices were found")
            state.error = True
            return None

        # * Combine any duplicate devices *
        datastore.deduplicate()

        devices = datastore.verified

    # * Pull from all devices specified *
    log.info(f"Beginning pull for {len(devices)} devices")
    start_time = timeit.default_timer()
    pull_results = []

    for device in devices:
        try:
            successful = device._module.pull(device)
            if not successful:
                log.error(f"Pull failed from {device.get_id()}")
                state.error = True
                continue

            device.purge_duplicates(force=True)

            exported_data = device.elastic()
            pull_results.append(exported_data)

            if state.elastic:
                device.export_to_elastic()
        except Exception:
            log.exception(f"Failed to pull from {device.get_id()}")
            state.error = True

    pull_duration = timeit.default_timer() - start_time
    log.info(
        f"Finished pulling from {len(devices)} devices in {utils.fmt_duration(pull_duration)}"
    )

    # * Sort pull results by device ID for consistency *
    pull_results.sort(key=itemgetter("id"))

    # * Generate pull summary *
    pull_summary = {
        "peat_version": __version__,
        "peat_run_id": str(consts.RUN_ID),
        "pull_duration": pull_duration,
        "pull_modules": module_api.lookup_names(device_types),
        "pull_targets": targets if skip_scan else scan_summary["scan_targets"],
        "pull_original_targets": targets,
        "pull_devices": [dev.get_id() for dev in devices],
        "pull_comm_type": comm_type,
        "num_pull_results": len(pull_results),
        "pull_results": pull_results,
    }

    # * Save pull results to a file *
    utils.save_results_summary(pull_summary, "pull-summary")

    # * Push pull results summary to Elasticsearch *
    if state.elastic:
        log.info(
            f"Pushing pull result summary to Elasticsearch "
            f"(index basename: {config.ELASTIC_PULL_INDEX})"
        )

        if not state.elastic.push(config.ELASTIC_PULL_INDEX, pull_summary):
            log.error("Failed to push pull result summary to Elasticsearch")

    return pull_summary


__all__ = ["pull"]
