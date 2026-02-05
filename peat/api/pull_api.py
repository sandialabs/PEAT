import timeit
from operator import itemgetter

from peat import __version__, config, consts, datastore, log, module_api, state, utils

from .scan_api import scan


def pull(
    targets: list[str], comm_type: consts.AllowedCommTypes, device_types: list[str]
) -> dict[str, dict | list | str | float | int] | None:
    """Pull from devices.

    Args:
        targets: Devices to pull from, such as network hosts or serial ports
        comm_type: Method of communication for the pull. Allowed values:

            - ``unicast_ip``
            - ``broadcast_ip``
            - ``serial``
        device_types: Names of device modules or module aliases to use

    Returns:
        :ref:`pull-summary` as a :class:`dict`, or :obj:`None` if an error occurred
    """
    # TODO: option to skip scan and manually specify devices to pull
    scan_summary = scan(targets, comm_type, device_types)

    if not scan_summary or not scan_summary["hosts_verified"]:
        log.error("Pull failed: no devices were found")
        state.error = True
        return None

    # * Combine any duplicate devices *
    datastore.deduplicate()

    # TODO: hack. Make this list the user input if scan is skipped.
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
        f"Finished pulling from {len(devices)} devices "
        f"in {utils.fmt_duration(pull_duration)}"
    )

    # * Sort pull results by device ID for consistency *
    pull_results.sort(key=itemgetter("id"))

    # * Generate pull summary *
    pull_summary = {
        "peat_version": __version__,
        "peat_run_id": str(consts.RUN_ID),
        "pull_duration": pull_duration,
        "pull_modules": module_api.lookup_names(device_types),
        "pull_targets": scan_summary["scan_targets"],
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
