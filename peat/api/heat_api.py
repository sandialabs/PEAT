"""
HEAT: High-fidelity Extraction of Artifacts from Traffic.
"""

from peat import Elastic, config, log, state
from peat.heat import HEAT_EXTRACTORS


def heat_main() -> bool:
    # Determine which HEAT plugins to use (aka "protocols", aka "extractors)")
    # By default, attempt to use all available plugins. If the user configures
    # protocols, then down-select to those the user configured.
    # Do this before anything else so can reach error quicker if user misconfigured.
    if not config.HEAT_PROTOCOLS:
        extractors_to_use = HEAT_EXTRACTORS
    else:
        extractors_to_use = []

        # iterate over protocols the user configured
        matched = set()
        for protocol_name in config.HEAT_PROTOCOLS:
            for plugin in HEAT_EXTRACTORS:
                # partial and case-insensitive matching of name to extractor
                if protocol_name.lower() in plugin.__name__.lower():
                    extractors_to_use.append(plugin)
                    matched.add(protocol_name)

        # print error message if any protocols were configured but not found
        if matched != set(config.HEAT_PROTOCOLS):
            log.error(
                "The following HEAT protocols were configured but not found: "
                f"{', '.join(set(config.HEAT_PROTOCOLS) - matched).rstrip().rstrip(',')}\n"
                f"Available protocols: {', '.join(plugin.__name__ for plugin in HEAT_EXTRACTORS)}"
            )
            state.error = True
            return False

        if not extractors_to_use:
            log.error(
                "No HEAT protocol extractors matched the configured protocols. "
                "If you specified a list of protocols, make sure they match the "
                "name of a extractor.\n"
                f"Specified protocols: {', '.join(config.HEAT_PROTOCOLS)}\n"
                f"Available protocols: {', '.join(plugin.__name__ for plugin in HEAT_EXTRACTORS)}"
            )
            state.error = True
            return False

    # TODO: if --heat-file-only is specified, and FTP extractor, don't require elasticsearch
    if config.HEAT_ELASTIC_SERVER:
        es_obj = Elastic(config.HEAT_ELASTIC_SERVER)
    elif state.elastic:
        es_obj = state.elastic
    else:
        log.error(
            "Cannot run HEAT since no Elasticsearch server specified. "
            "You must provide an Elasticsearch server with Packetbeat "
            "data using either HEAT_ELASTIC_SERVER or ELASTIC_SERVER."
        )
        state.error = True
        return False

    run_result = False  # false if *all* plugins fail, otherwise true
    for extractor in extractors_to_use:
        plugin_instance = extractor(es_obj)
        result = plugin_instance.run()
        if result:
            run_result = True
        else:
            log.error(f"HEAT extractor '{extractor.__name__}' failed. See PEAT logs for details.")

    if not run_result:  # if all HEAT plugins failed, PEAT run failed
        log.error("All HEAT plugins failed")
        state.error = True
        return False

    return True
