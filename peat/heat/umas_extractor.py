"""
HEAT protocol extractor for the Schneider UMAS protocol.

UMAS packets in Elasticsearch will have the 'type' field set to 'umas'.

UMAS protocol fields

- modbus.transaction_identifier
- umas.connection_id
- umas.function_code
- umas.function_name
- umas.function_description
- umas.direction
- umas.data
- umas.block_id (only if umas.function_name is UPLOAD_BLOCK or DOWNLOAD_BLOCK)
- umas.block_len (only if umas.function_name is UPLOAD_BLOCK)
- umas.max_packet_size (only if umas.function_name is INITIALIZE_DOWNLOAD)
- umas.blocks_transferred (only if umas.function_name is END_UPLOAD or END_DOWNLOAD)

Authors

- Christopher Goes
- John Jacobellis
- Ryan Adams
"""

import binascii
import itertools
from collections import defaultdict

from peat import Interface, Service, config, datastore, log, state, utils
from peat.protocols.common import mac_to_vendor

from .heat_classes import HeatArtifact, HeatProtocol


class UmasExtractor(HeatProtocol):
    """HEAT protocol extractor for the Schneider UMAS protocol."""

    START_FUNCS = {"INITIALIZE_DOWNLOAD", "INITIALIZE_UPLOAD"}
    BLOCK_FUNCS = {"DOWNLOAD_BLOCK", "UPLOAD_BLOCK"}
    END_FUNCS = {"END_DOWNLOAD", "END_UPLOAD"}
    RESP_FUNCS = {"RESPONSE_OK", "RESPONSE_ERROR"}
    FUNCS = [*START_FUNCS, *BLOCK_FUNCS, *END_FUNCS, *RESP_FUNCS]

    def get_data(self) -> None:
        query = {
            "bool": {
                "must": [{"term": {"type": "modbus"}}],
                "filter": [{"terms": {"umas.function_name": self.FUNCS}}],
            }
        }
        body = {
            "query": query,
            # Sort in ascending order by modbus transaction ID
            "sort": [{"mbtcp.transaction_identifier": "asc"}],
        }

        self.elastic_data = self._search_es(body)

    def extract_blocks(self) -> None:
        log.info("Extracting artifact blocks...")
        ip_groups = defaultdict(list)
        for packet in self.elastic_data:
            # Set the device IP
            if packet["umas"]["direction"].lower() == "request":
                key = packet["destination"]["ip"]
            else:
                key = packet["source"]["ip"]
            ip_groups[key].append(packet)

        # Extract artifacts from groups
        artifact_buckets = defaultdict(list)
        for ip, group_pkts in ip_groups.items():
            log.info(f"Processing {len(group_pkts)} packets for {ip}")
            # Bucket artifacts by start and end block to handle
            # multiple artifacts from the same device
            start_locations = [
                loc
                for loc, pkt in enumerate(group_pkts)
                if pkt["umas"]["function_name"] in self.START_FUNCS
            ]
            stop_locations = [
                loc
                for loc, pkt in enumerate(group_pkts)
                if pkt["umas"]["function_name"] in self.END_FUNCS
            ]
            log.debug(
                f"[{ip}] {len(start_locations)} start locations, "
                f"{len(stop_locations)} stop locations"
            )
            if len(start_locations) != len(stop_locations):
                log.error(
                    f"[{ip}] Lengths of start locations and stop locations "
                    f"don't match. This indicates either a start or stop "
                    f"packet for the upload/download is missing. Skipping all "
                    f"packets for {ip} ({len(group_pkts)} packets)."
                )
                continue
            for start_loc, stop_loc in zip(start_locations, stop_locations):
                # bucket[0]: INITIALIZE_DOWNLOAD or INITIALIZE_UPLOAD
                # bucket[-1]: END_DOWNLOAD or END_UPLOAD (hence 'stop_loc + 1')
                bkt_iter = itertools.islice(group_pkts, start_loc, stop_loc + 1)
                bucket = list(bkt_iter)
                if not bucket:
                    log.warning(
                        f"Empty artifact packets for {ip}. "
                        f"start: {start_loc}, stop: {stop_loc}"
                    )
                    continue
                artifact_buckets[ip].append(bucket)
                # Print debugging info
                log.trace(f"[{ip}] Bucket size: {len(bucket)}")
                if config.DEBUG >= 2:
                    for bkt in bucket:
                        log.trace2(
                            f"\t({bkt['@timestamp']}) "
                            f"{bkt['mbtcp']['transaction_identifier']} - "
                            f"{bkt['umas']['function_name']}"
                        )
        log.info(f"Done with {len(ip_groups)} IP groups")

        for ip, artifact_bucket in artifact_buckets.items():
            for packets in artifact_bucket:
                # The partially constructed artifact + metadata
                # TODO: begin constructing artifact in a earlier for loop?
                #   Don't bucket by IP. Instead, bucket by artifact
                r_pkt = next(
                    (
                        p
                        for p in packets
                        if p["umas"]["function_name"] in self.RESP_FUNCS
                    ),
                    None,
                )
                if not r_pkt:
                    log.warning(f"No response packets found for {ip}")
                    continue
                start_time = utils.parse_date(packets[0]["@timestamp"])
                end_time = utils.parse_date(packets[-1]["@timestamp"])
                artifact = HeatArtifact(
                    packets=packets,
                    device_ip=r_pkt["source"]["ip"],
                    device_mac=r_pkt["source"].get("mac", ""),
                    device_oui=_cleanup_oui(r_pkt["source"].get("vendor", "")),
                    station_ip=r_pkt["destination"]["ip"],
                    station_mac=r_pkt["destination"].get("mac", ""),
                    station_oui=_cleanup_oui(r_pkt["destination"].get("vendor", "")),
                    start_time=start_time,
                    end_time=end_time,
                    duration=(end_time - start_time).total_seconds(),
                )
                # TODO: cleanup/deduplicate this logic
                # TODO: add vendor_id (manuf) and vendor_name (manuf_long)
                if artifact.device_mac:
                    dev_vend = mac_to_vendor(artifact.device_mac)
                    if dev_vend:
                        if dev_vend.manuf_long:
                            artifact.device_oui = dev_vend.manuf_long
                        elif dev_vend.manuf and not artifact.device_oui:
                            artifact.device_oui = dev_vend.manuf
                if artifact.station_mac:
                    station_vend = mac_to_vendor(artifact.station_mac)
                    if station_vend:
                        if station_vend.manuf_long:
                            artifact.station_oui = station_vend.manuf_long
                        elif station_vend.manuf and not artifact.station_oui:
                            artifact.station_oui = station_vend.manuf

                response_data = {}
                for pkt in packets:
                    transaction_id = pkt["mbtcp"]["transaction_identifier"]
                    if pkt["umas"]["function_name"] == "RESPONSE_ERROR":
                        log.warning(
                            f"[{ip}] RESPONSE_ERROR (transaction "
                            f"ID: {transaction_id}, timestamp: "
                            f"{pkt['@timestamp']})"
                        )
                    # Extract data from response oks
                    elif pkt["umas"]["function_name"] == "RESPONSE_OK":
                        response_data[transaction_id] = pkt["umas"].get("data", "")

                # Lookup to associate data in the download block from the response
                for pkt in packets:
                    block_id: int | None = pkt["umas"].get("block_id")
                    func: str = pkt["umas"]["function_name"]
                    if func in self.END_FUNCS:
                        artifact.expected_blocks = int(
                            pkt["umas"]["blocks_transferred"]
                        )
                        continue

                    # Skip blocks without data (e.g. INITIALIZE_DOWNLOAD)
                    if func not in self.BLOCK_FUNCS:
                        continue
                    # Check for null/non-positive block IDs (should never happen)
                    # NOTE: block IDs always start at 1, not 0
                    if not block_id:
                        log.error(f"[{artifact.id}] Bad {func} ID: {block_id}")
                        continue

                    # Set transfer type for the artifact (DOWNLOAD or UPLOAD)
                    if not artifact.direction:
                        artifact.direction = func.split("_", maxsplit=1)[0]

                    # Prevent duplicate blocks.
                    block_id = int(block_id)
                    if block_id in artifact.block_ids:
                        # The first block of a upload is sent twice, and
                        # I believe this can happen with a download as well.
                        # So, don't warn if it's the first block ID.
                        if block_id != 1:
                            log.warning(
                                f"[{artifact.id}] Duplicate block ID "
                                f"for {func}: {block_id}"
                            )
                        continue
                    artifact.block_ids.add(block_id)

                    if func == "DOWNLOAD_BLOCK":
                        # !! hack to exclude first 4 bytes (zero pad + len) !!
                        data = response_data[
                            pkt["mbtcp"]["transaction_identifier"]
                        ].replace(":", "")
                        if len(data) >= 8:
                            data = data[8:]  # 4 bytes => 8 nibbles
                    else:  # UPLOAD_BLOCK
                        data = pkt["umas"]["data"].replace(":", "")
                    block = {
                        "block_id": block_id,
                        "data": data,
                    }
                    artifact.blocks.append(block)
                log.trace(
                    f"[{artifact.id}] {artifact.direction}: expected "
                    f"{artifact.expected_blocks} blocks, got "
                    f"{len(artifact.blocks)} blocks",
                )
                log.trace2(
                    f"[{artifact.id}] Block IDs for {artifact.direction}: "
                    f"{artifact.block_ids}",
                )
                # Verify the number of blocks transferred matches the
                # amount of blocks expected, as indicated in the
                # END_DOWNLOAD or END_UPLOAD packet.
                if not artifact.expected_blocks:
                    log.warning(
                        f"[{artifact.id}] Unable to find END_DOWNLOAD or "
                        f"END_UPLOAD, expected number of blocks is unknown"
                    )
                elif artifact.expected_blocks != len(artifact.blocks):
                    log.warning(
                        f"[{artifact.id}] Number of blocks extracted does not "
                        f"match the number of blocks expected from the END "
                        f"packet! Got {len(artifact.blocks)}, expected "
                        f"{artifact.expected_blocks}"
                    )
                # Sort by block ID
                artifact.blocks.sort(key=lambda x: x["block_id"])
                self.artifacts.append(artifact)
        log.info("Finished artifact block extraction for all devices")

    def assemble_artifacts(self) -> None:
        log.info(f"Assembling {len(self.artifacts)} artifacts...")
        for artifact in self.artifacts:
            chunks = bytearray()
            for block in artifact.blocks:
                chunks.extend(binascii.unhexlify(block["data"]))
            artifact.reconstructed_artifact = bytes(chunks)
            start = artifact.start_time.strftime("%Y-%m-%d_%H-%M-%S")
            artifact.file_name = (
                f"{artifact.device_ip}_{artifact.station_ip}_"
                f"{artifact.direction}_{start}+{int(artifact.duration)}.apx"
            )

    def export_artifacts(self) -> None:
        log.info(f"Exporting {len(self.artifacts)} artifacts...")
        for artifact in self.artifacts:
            log.info(f"[{artifact.id} Exporting to {artifact.file_name}")
            artifact.file_path = config.HEAT_ARTIFACTS_DIR / artifact.file_name
            utils.write_file(
                artifact.reconstructed_artifact,
                artifact.file_path,
                overwrite_existing=False,
            )

    def parse_artifacts(self) -> None:
        log.info(f"Parsing {len(self.artifacts)} artifacts using PEAT...")
        # Don't lookup IPs in host's DNS, pointless and can leak information
        config.RESOLVE_HOSTNAME = False
        config.RESOLVE_IP = False
        config.RESOLVE_MAC = False
        for artifact in self.artifacts:
            self._parse_artifact(artifact)

    def _parse_artifact(self, artifact: HeatArtifact) -> None:
        log.info(f"Parsing artifact {artifact.id}")
        # Device (the PLC)
        # NOTE: it's possible to have multiple project files for same IP!
        #   Therefore, we use .add() instead of .get() to avoid annotating
        #   the same DeviceData object.
        dev = datastore.create(artifact.device_ip, "ip")
        dev._is_verified = True
        device_iface = Interface(
            type="ethernet",
            mac=artifact.device_mac,
            ip=artifact.device_ip,
        )
        dev.store("interface", device_iface)
        dev.populate_fields()
        mb_svc = Service(
            port=502,
            # TODO: add a "application" field to service model for "umas"?
            protocol="modbus_tcp",
            transport="tcp",
            status="verified",
        )
        dev.store("service", mb_svc, interface_lookup={"ip": artifact.device_ip})
        dev.populate_fields()
        # Do this so m340 isn't required for basic artifact extraction
        from peat import M340

        try:
            if config.HEAT_ARTIFACTS_DIR and artifact.file_path:
                M340.parse(to_parse=artifact.file_path, dev=dev)
            else:
                M340.parse(to_parse=artifact.reconstructed_artifact, dev=dev)
        except Exception:
            log.exception(
                f"[{artifact.id}] Failed to parse artifact due "
                f"to an unhandled exception"
            )
            state.error = True
        dev.related.ip.add(artifact.station_ip)
        if dev.logic.author:
            dev.related.user.add(dev.logic.author)
        M340.update_dev(dev)

        # The Station which programs the device, usually Unity Pro (or PEAT)
        # Generally a Engineering Workstation or a SCADA system
        # TODO: merge data for station (use datastore.get()),
        #   since it's likely the same device?
        station = datastore.create(artifact.station_ip, "ip")
        station_iface = Interface(
            type="ethernet",
            mac=artifact.station_mac,
            ip=artifact.station_ip,
        )
        station.store("interface", station_iface)
        # TODO: set station vendor ID to the short manuf string
        #   (e.g. "Dell" instead of "Dell, Inc.")
        station.description.vendor.name = artifact.station_oui
        uv = dev.extra.get("project_file_metadata", {}).get("unity_version", "")
        if not uv:
            uv = " or similar software"
        station.description.description = (
            f"Host that programmed the device at {artifact.device_ip}. "
            f"Likely a engineering workstation or SCADA server running "
            f"Unity Pro {uv}."
        )
        station.type = "PC"
        station.related.ip.add(artifact.device_ip)
        if dev.logic.author:
            station.related.user.add(dev.logic.author)
        station.populate_fields()
        if config.DEVICE_DIR:
            station.export_to_files()
        # TODO: "heat_results" file with all results, keyed by file?

        # Export parsed data to Elasticsearch
        if state.elastic:
            dev.export_to_elastic()
            station.export_to_elastic()

        # Generate OpenPLC project for every unique device IP
        if config.HEAT_ARTIFACTS_DIR:
            if not dev.logic.formats.get("tc6"):
                log.warning(
                    f"[{artifact.id}] No TC6 was generated, skipping "
                    f"generation of OpenPLC project"
                )
            else:
                dir_name = (
                    f"openplc-project_{dev.logic.name.replace(' ', '-')}_"
                    f"{dev.ip}_{artifact.end_time.timestamp()}"
                )
                dir_path = config.HEAT_ARTIFACTS_DIR / dir_name
                dev.options["m340"]["generate_openplc_project"] = dir_path
                proj_path = M340.generate_openplc_project(dev)
                if not proj_path:
                    log.error(f"[{artifact.id}] Failed OpenPLC project generation")


def _cleanup_oui(mac: str):
    # Older tshark (3.0.14) makes vendor names like "HewlettP_00:00:00"
    # Modern tshark (3.2.3) is like "Hewlett Packard"
    if mac.count("_") == 1 and mac.count(":") == 2:
        return mac.split("_", maxsplit=1)[0]
    return mac


__all__ = ["UmasExtractor"]
