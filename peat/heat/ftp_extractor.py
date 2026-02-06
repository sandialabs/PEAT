"""
HEAT protocol extractor for the FTP protocol for SEL devices.

Authors

- Walter Weiffenbach
- Christopher Goes
"""

import json
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from peat import Elastic, Interface, config, datastore, log, state, utils
from peat.modules.sel.relay_parse import (
    parse_cser,
    parse_ser,
    process_events,
    process_info_into_dev,
)

from .heat_classes import FTPHeatArtifact, HeatArtifact, HeatProtocol


class FTPExtractor(HeatProtocol):
    """
    HEAT protocol extractor for the FTP protocol for SEL devices.
    """

    def __init__(self, es_obj: Elastic):
        self.logdirs = []
        self.pcap_filenames = []

        # find zeek binary, and if not found, fallback
        # to the hardcoded path.
        self.zeek_bin_path = shutil.which("zeek")
        if not self.zeek_bin_path:
            self.zeek_bin_path = "/opt/zeek/bin/zeek"

        super().__init__(es_obj)

    def get_log_dir(self, f: str) -> str:
        """get directory path for a pcap's zeek logs."""
        return f"{config.ZEEK_LOGDIR}/zeek_{f.replace('.', '_')}"

    def get_data(self) -> None:
        if not config.NO_RUN_ZEEK:
            # get pcap directory from argument
            pcaps_dir = config.PCAPS

            if not pcaps_dir:
                log.warning("No PCAP directory specified (--pcaps), defaulting to './pcaps'")
                pcaps_dir = Path("./pcaps").resolve()

            if not pcaps_dir.is_dir():
                log.error(
                    f"PCAPS directory {pcaps_dir} doesn't exist or isn't a directory. Aborting..."
                )
                state.error = True
                return

            pcap_files = os.listdir(pcaps_dir)
            if not pcap_files:
                log.error(f"PCAP folder '{pcaps_dir}' is empty. Aborting...")
                state.error = True
                return

            # get pcaps
            log.info(f"Reading pcap files from {pcaps_dir}")
            for f in pcap_files:
                if ".pcap" in f:
                    # store the pcap information
                    # we have to use elastic_data here to the heat_protocol
                    # superclass does not cause execution to halt.
                    self.elastic_data.insert(0, str(pcaps_dir) + "/" + f)
                    self.pcap_filenames.insert(0, f)
                    self.logdirs.insert(0, self.get_log_dir(f))

            log.info(f"Extracting artifacts from {len(self.elastic_data)} PCAP files")

            # run zeek to get data logs
            # clean zeek log dir
            if not config.ZEEK_LOGDIR.exists():
                config.ZEEK_LOGDIR.mkdir()

            # for each pcap, process it
            for i in range(len(self.elastic_data)):
                # if the zeek data already exists, don't run zeek because it is expensive
                if os.path.exists(self.logdirs[i]):
                    log.debug(f"Zeek already ran for {self.logdirs[i]}. Skipping...")
                    continue

                # self.elastic_data[i] is the absolute path to the PCAP file
                log.info(f"Running Zeek on {self.elastic_data[i]}")

                # init the logdir for this pcap
                logdir = self.logdirs[i]
                os.mkdir(logdir)

                # TODO: copy the PCAP file that was parsed to results

                # execute zeek
                # the zeek script configures file extraction
                zeek_result = subprocess.run(
                    args=[
                        self.zeek_bin_path,
                        "-C",
                        "-r",
                        self.elastic_data[i],
                        f"default_logdir={logdir}",
                        "LogAscii::use_json=T",
                        "/PEAT/peat/heat/ftp_extractor_zeek_script.zeek",
                    ],
                    check=False,
                    capture_output=True,
                )

                # if the command failed, skip this pcap and error
                if zeek_result.returncode != 0:
                    state.error = True
                    log.error(
                        f"Unable to execute Zeek for {self.elastic_data[i]} "
                        f"(exit code: {zeek_result.returncode})"
                    )
                    log.debug(f"zeek stdout: {zeek_result.stdout}")
                    log.debug(f"zeek stderr: {zeek_result.stderr}")
                    continue

                # if files were extracted, move them into the log dir
                if os.path.exists("extract_files"):
                    shutil.move("extract_files", f"{logdir}/extract_files/")
                    try:
                        shutil.move("conn.log", logdir)
                        shutil.move("files.log", logdir)
                        shutil.move("ftp.log", logdir)
                    except FileNotFoundError as e:
                        log.error(f"Unable to move extracted files to correct dir: {e}")
                        state.error = True
                        return
                else:
                    log.error(f"No files were extracted from {self.elastic_data[i]}")

                # Cleanup empty zeek directories
                utils.clean_empty_dirs(config.ZEEK_LOGDIR)
        else:
            if not config.ZEEK_DIR:
                log.error("ZEEK_DIR (--zeek-dir) not specified. Aborting...")
                state.error = True
                return

            if not config.ZEEK_DIR.is_dir():
                log.error(f"{config.ZEEK_DIR} doesn't exist or is not a directory. Aborting...")
                state.error = True
                return

            self.elastic_data.insert(0, config.ZEEK_DIR)

            log.info(f"Extracting artifacts from {config.ZEEK_DIR} as Zeek directory")

    def nth_index(self, haystack, needle, n) -> int:
        # get the nth index of a needle string in a haystack string
        start = haystack.find(needle)
        while start >= 0 and n > 1:
            start = haystack.find(needle, start + len(needle))
            n -= 1
        return start

    def make_json(self, file) -> list | None:
        # read a zeek json file into a python array of dicts
        if not os.path.exists(file):
            log.error("Path does not exist")
            return None

        log_json = []
        with open(file) as log_fp:
            for line in log_fp.readlines():
                log_json.insert(0, json.loads(line))

        return log_json

    def extract_blocks(self) -> None:
        process_dirs = []
        if not config.NO_RUN_ZEEK:
            for pcap_file in self.pcap_filenames:
                process_dirs.insert(0, self.get_log_dir(pcap_file))
        else:
            process_dirs.insert(0, config.ZEEK_DIR)
        prev_num_artifacts = 0
        # for each pcap
        for logdir in process_dirs:
            # init dirs, files, and log data

            files_logfile = f"/{logdir}/files.log"
            conn_logfile = f"/{logdir}/conn.log"
            ftp_logfile = f"/{logdir}/ftp.log"

            files_log = self.make_json(files_logfile)
            conn_log = self.make_json(conn_logfile)
            ftp_log = self.make_json(ftp_logfile)

            # if we successfully got the logs
            if files_log is not None and conn_log is not None and ftp_log is not None:
                # for each file in the file log
                for file_log_json in files_log:
                    conn_json = None
                    ftp_json = None

                    # if the file is from FTP
                    if file_log_json["source"] == "FTP_DATA":
                        # search for the connection id associated with the
                        # extracted file and the ftp log entry associated
                        conn_id = None
                        for ftp_log_json in ftp_log:
                            if (
                                ftp_log_json["command"] == "RETR"
                                or ftp_log_json["command"] == "STOR"
                            ) and ftp_log_json["fuid"] == file_log_json["fuid"]:
                                conn_id = ftp_log_json["uid"]
                                ftp_json = ftp_log_json
                                break

                        if conn_id is None:
                            # we only care about files from STOR and RETR command
                            # because other extracted files may not be actually
                            # artifacts we want.
                            log.debug(
                                f"No upload or download found for "
                                f"zeek file {file_log_json['extracted']}. "
                                f"This may be output from a non STOR or RETR command."
                            )
                            continue

                        # search for the connection log entry by the connection id
                        for conn_log_json in conn_log:
                            if conn_log_json["uid"] == conn_id:
                                conn_json = conn_log_json
                                break

                        # move on to next file if conn_log_json is none
                        if conn_json is None:
                            break

                        # assemble the artifact
                        # TODO: fix OUIs
                        start_time = datetime.fromtimestamp(conn_json["ts"])
                        end_time = datetime.fromtimestamp(conn_json["ts"] + conn_json["duration"])
                        dev_mac = None
                        stat_mac = None

                        try:
                            dev_mac = conn_json["resp_l2_addr"]
                            stat_mac = conn_json["orig_l2_addr"]
                        except KeyError:
                            dev_mac = ""
                            stat_mac = ""

                        artifact = FTPHeatArtifact(
                            device_ip=conn_json["id.resp_h"],
                            device_mac=dev_mac,
                            device_oui=_cleanup_oui(dev_mac),
                            station_ip=conn_json["id.orig_h"],
                            station_mac=stat_mac,
                            station_oui=_cleanup_oui(stat_mac),
                            start_time=start_time,
                            end_time=end_time,
                            duration=conn_json["duration"],
                            artifact_name=ftp_json["arg"][
                                self.nth_index(ftp_json["arg"], ".", 4) + 2 :
                            ],
                            zeek_name=f"{logdir}/extract_files/{file_log_json['extracted']}",
                        )

                        if ftp_log_json["command"] == "STOR":
                            artifact.direction = "UPLOAD"
                        else:
                            artifact.direction = "DOWNLOAD"

                        artifact.file_name = (
                            f"[{artifact.device_ip}_{artifact.station_ip}]_"
                            f"{artifact.direction}_{str(start_time).replace(' ', '_')}"
                            f"+{int(artifact.duration)}_"
                            f"{artifact.artifact_name.replace('/', '_')}"
                        )
                        artifact.file_name = str.replace(artifact.file_name, ":", "_")
                        self.artifacts.insert(0, artifact)
            else:
                if files_log is None:
                    log.warning(f"Failed to load files.log from {logdir}")
                if conn_log is None:
                    log.warning(f"Failed to load conn.log from {logdir}")
                if ftp_log is None:
                    log.warning(f"Failed to load ftp.log from {logdir}")
                continue

            if not config.NO_RUN_ZEEK:
                log.info(
                    f"Found {len(self.artifacts) - prev_num_artifacts} "
                    f"FTP artifacts in {pcap_file}"
                )
            else:
                log.info(
                    f"Found {len(self.artifacts) - prev_num_artifacts} "
                    f"FTP artifacts zeek log {config.ZEEK_DIR}"
                )

            prev_num_artifacts = len(self.artifacts)

    def assemble_artifacts(self) -> None:
        # since we assemble artifacts in extract_blocks,
        # this is unnecessary but must be implemented.
        # log.info(f"Assembling {len(self.artifacts)} artifacts...")
        return

    def export_artifacts(self) -> None:
        log.info(f"Exporting {len(self.artifacts)} artifacts...")

        if not config.HEAT_ARTIFACTS_DIR.exists():
            config.HEAT_ARTIFACTS_DIR.mkdir()

        # regex to ensure the file is a txt file
        txtRegex = re.compile(r".*\.(txt|TXT)")
        # for each artifact
        for artifact in self.artifacts:
            log.info(f"[{artifact.id} Exporting to {artifact.file_name}")
            artifact.file_path = config.HEAT_ARTIFACTS_DIR / artifact.file_name

            # if the file is a text file, use the utils to write the file
            if txtRegex.search(artifact.artifact_name):
                with open(artifact.zeek_name) as zeek_file:
                    content = zeek_file.read()
                    utils.write_file(content, artifact.file_path, overwrite_existing=False)
            else:
                # otherwise, use this logic to do an equivalent action for a non-string file
                fp = utils.dup_path(artifact.file_path)
                if os.path.exists(artifact.file_path):
                    log.debug(
                        f"File {artifact.file_path} already exists. Writing to {fp} instead."
                    )
                shutil.copy(artifact.zeek_name, artifact.file_path)

    def parse_artifacts(self) -> None:
        log.info(f"Parsing {len(self.artifacts)} artifacts using PEAT...")

        # Don't lookup IPs in host's DNS, pointless and can leak information
        config.RESOLVE_HOSTNAME = False
        config.RESOLVE_IP = False
        config.RESOLVE_MAC = False

        txtRegex = re.compile(r"\.(txt|TXT)")
        setorserRegex = re.compile(r"(((SET|set)_.*)|(c?ser|C?SER))\.(txt|TXT)")

        for artifact in self.artifacts:
            if txtRegex.search(artifact.artifact_name):
                if setorserRegex.search(artifact.artifact_name):
                    self._parse_artifact(artifact)
                else:
                    log.debug(f"Unable to parse non-settings artifact {artifact.artifact_name}")
            else:
                try:
                    log.debug(
                        f"Unable to parse artifact with unsupported "
                        f"extension: {artifact.file_name}"
                    )
                except ValueError:
                    log.debug(
                        f"Unable to parse artifact with unknown format: {artifact.file_name}"
                    )

    def _parse_artifact(self, artifact: HeatArtifact) -> None:
        log.info(f"Parsing artifact {artifact.file_name}")

        # Device (the relay)
        # NOTE: it's possible to have multiple project files for same IP!
        #   Therefore, we use .add() instead of .get() to avoid annotating
        #   the same DataManager object.
        dev = datastore.create(artifact.device_ip, "ip")
        dev._is_verified = True
        device_iface = Interface(
            type="ethernet",
            mac=artifact.device_mac,
            ip=artifact.device_ip,
        )
        dev.store("interface", device_iface)
        dev.populate_fields()

        serRegex = re.compile(r"(ser|SER)\.(txt|TXT)")
        cserRegex = re.compile(r"(cser|CSER)\.(TXT|txt)")

        # Do this so SELRelay isn't required for basic artifact extraction
        from peat import SELRelay

        if cserRegex.search(artifact.artifact_name):
            with open(artifact.file_path) as f:
                cser_data = f.read().strip()
                events, info = parse_cser(cser_data.splitlines())

                if not events:
                    log.warning(f"No CSER.TXT events from {dev.ip}")
                if info:
                    process_info_into_dev(info, dev)
                if events:
                    process_events(events, dev, dataset="cser")

        elif serRegex.search(artifact.artifact_name):
            with open(artifact.file_path) as f:
                ser_data = f.read().strip()
                events, info = parse_ser(ser_data.splitlines())

                if not events:
                    log.warning(f"No SER.TXT events from {dev.ip}")
                if info:
                    process_info_into_dev(info, dev)
                if events:
                    process_events(events, dev, dataset="ser")
        else:
            try:
                if config.HEAT_ARTIFACTS_DIR and artifact.file_path:
                    SELRelay.parse(to_parse=artifact.file_path, dev=dev)
                else:
                    SELRelay.parse(to_parse=artifact.reconstructed_artifact, dev=dev)
            except Exception:
                log.exception(
                    f"[{artifact.id}] Failed to parse artifact due to an unhandled exception"
                )
                state.error = True
        dev.related.ip.add(artifact.station_ip)
        if dev.logic.author:
            dev.related.user.add(dev.logic.author)
        SELRelay.update_dev(dev)

        # The Station which programs the device
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
        station.description.description = (
            f"Host that programmed the device at {artifact.device_ip}. "
            f"Likely a engineering workstation or SCADA server."
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


def _cleanup_oui(mac: str) -> str:
    # Older tshark (3.0.14) makes vendor names like "HewlettP_c0:b9:20"
    # Modern tshark (3.2.3) is like "Hewlett Packard"
    if mac.count("_") == 1 and mac.count(":") == 2:
        return mac.split("_", maxsplit=1)[0]
    return mac


__all__ = ["FTPExtractor"]
