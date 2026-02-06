from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from peat import Elastic, config, log, utils

# TODO: unit tests
# - CLI commands and all arguments (e.g. --file-only)
# - Python APIs and all settings
# - Expected files are created with expected data
# - Expected elastic exports are created
# - Separate elastic servers work for import and export

# TODO:
# - Type annotations are messy with circular references/imports
# - Use Pydantic models instead of dataclasses
# - Remove redundant fields in TelnetHeatArtifact that are defined in HeatArtifact


@dataclass
class HeatArtifact:
    """Data and metadata that make up an artifact extracted by HEAT."""

    packets: list[dict] = field(default_factory=list)
    """Raw packets associated with the artifact."""

    blocks: list[dict] = field(default_factory=list)
    """List of dicts with the following keys: ``block_id``, ``data``."""

    block_ids: set[int] = field(default_factory=set)
    """Unique block IDs."""

    # Info for the PLC (e.g. a Modicon M340)
    device_ip: str = ""
    device_mac: str = ""
    device_oui: str = ""

    # Info for the "Station" (does the downloading/uploading, e.g. Unity Pro)
    station_ip: str = ""
    station_mac: str = ""
    station_oui: str = ""

    direction: str = ""
    """DOWNLOAD or UPLOAD."""

    start_time: datetime = None
    end_time: datetime = None
    duration: float = 0.0

    expected_blocks: int = 0
    """blocks expected based on ``END_*`` packet."""

    reconstructed_artifact: bytes = b""
    file_name: str = ""
    file_path: Path = None

    @property
    def id(self) -> str:
        end = ""
        if self.end_time:
            end = str(int(self.end_time.timestamp()))
        return "_".join((self.device_ip, self.station_ip, end))


@dataclass
class FTPHeatArtifact(HeatArtifact):
    """Data and metadata that make up an artifact extracted by HEAT."""

    # TODO: type annotations get messy with circular references/imports
    # TODO: artifact classes would be a great place to start using pydantic
    artifact_name: str = ""
    reconstructed_artifact: str = ""
    zeek_name: str = ""

    @property
    def id(self) -> str:
        end = ""
        if self.end_time:
            end = str(int(self.end_time.timestamp()))
        return "_".join((self.device_ip, self.station_ip, end, self.artifact_name))


@dataclass
class TelnetHeatArtifact(HeatArtifact):
    packets: list[dict] = field(default_factory=list)
    """Raw packets associated with the artifact."""

    # The PLC (e.g. a Modicon M340)
    source_ip: str = ""
    source_mac: str = ""
    source_oui: str = ""

    # The "Station" (does the downloading/uploading, e.g. Unity Pro)
    dest_ip: str = ""
    dest_mac: str = ""
    dest_oui: str = ""
    direction: str = ""  # DOWNLOAD or UPLOAD

    start_time: datetime = None
    end_time: datetime = None
    duration: float = 0.0
    reconstructed_artifact: bytes = b""
    file_name: str = ""
    file_path: Path = None

    artifact_file_name: str = ""
    command: str = ""

    bytestream: bytes = b""
    start: int = 0
    stop: int = -1

    @property
    def id(self) -> str:
        end = ""
        if self.end_time:
            end = str(int(self.end_time.timestamp()))
        return "_".join(
            (
                self.source_ip,
                str(self.dest_ip),
                str(self.direction),
                str(self.artifact_file_name),
                str(self.start),
                str(self.stop),
                end,
            )
        )


@dataclass
class S7commHeatArtifact(HeatArtifact):
    raw_data: str = ""
    file_path: Path = None
    filename: str = ""
    reconstructed_artifact: str = ""


class HeatProtocol(ABC):
    """
    Base class defining a protocol extractor for HEAT.

    Authors

    - Christopher Goes
    - Ryan Adams
    """

    def __init__(self, es_obj: Elastic):
        # Elastic instance
        self.es_obj: Elastic = es_obj
        # Elasticsearch data - these are the parsed packets
        self.elastic_data: list[dict[str, Any]] = []
        # Reconstructed artifacts and their metadata
        self.artifacts: list[HeatArtifact] = []

    def run(self) -> bool:
        # Call the functions to extract traffic
        self.get_data()
        if not self.elastic_data:
            log.error(
                "No Packetbeat data found for HEAT. Perhaps the date "
                "range or IP exclusion list is too restrictive?"
            )
            return False
        self.extract_blocks()
        if not self.artifacts:
            log.warning("No artifacts were extracted, exiting...")
            return False
        self.assemble_artifacts()
        if config.HEAT_ARTIFACTS_DIR:
            self.export_artifacts()
        else:
            log.warning("HEAT_ARTIFACTS_DIR is disabled, artifacts will not be exported to files")
        if not config.HEAT_FILE_ONLY:
            self.parse_artifacts()
        return True

    def _search_es(self, body: dict) -> list[dict[str, Any]]:
        if "bool" not in body["query"]:
            body["query"]["bool"] = {}
        if config.HEAT_DATE_RANGE:
            log.info(f"HEAT date range: {config.HEAT_DATE_RANGE}")
            if "filter" not in body["query"]["bool"]:
                body["query"]["bool"]["filter"] = []
            start_ts, end_ts = config.HEAT_DATE_RANGE.split(" - ")
            body["query"]["bool"]["filter"].append(
                {
                    "range": {
                        "@timestamp": {
                            "gte": Elastic.convert_tstamp(start_ts),
                            "lte": Elastic.convert_tstamp(end_ts),
                            # "format": "strict_date_optional_time"
                        }
                    }
                }
            )
        if config.HEAT_EXCLUDE_IPS:
            log.warning(
                f"Excluding {len(config.HEAT_EXCLUDE_IPS)} IPs "
                f"from HEAT search: {config.HEAT_EXCLUDE_IPS}"
            )
            if "must_not" not in body["query"]["bool"]:
                body["query"]["bool"]["must_not"] = []
            body["query"]["bool"]["must_not"].extend(
                [
                    {"terms": {"source.ip": config.HEAT_EXCLUDE_IPS}},
                    {"terms": {"destination.ip": config.HEAT_EXCLUDE_IPS}},
                ]
            )
        if config.HEAT_ONLY_IPS:
            log.warning(
                f"Limiting HEAT search to only include "
                f"{len(config.HEAT_ONLY_IPS)} IPs: "
                f"{config.HEAT_ONLY_IPS}"
            )
            if "must" not in body["query"]["bool"]:
                body["query"]["bool"]["must"] = []
            body["query"]["bool"]["must"].append(
                {
                    "bool": {
                        "should": [
                            {"terms": {"source.ip": config.HEAT_ONLY_IPS}},
                            {"terms": {"destination.ip": config.HEAT_ONLY_IPS}},
                        ]
                    }
                }
            )
        es_data = self.es_obj.search(index=config.HEAT_INDEX_NAMES, body=body)
        log.info(f"{len(es_data)} Elasticsearch query results")
        if config.DEBUG >= 2 and config.HEAT_ARTIFACTS_DIR:
            file_path = config.HEAT_ARTIFACTS_DIR / "raw-elastic-data.json"
            utils.write_file(es_data, file_path, format_json=False)
        return es_data

    @abstractmethod
    def get_data(self) -> None:
        """Retrieve Eratosthenes Packetbeat data from the Elasticsearch server."""
        raise NotImplementedError

    @abstractmethod
    def extract_blocks(self) -> None:
        """Parses and sorts Elasticsearch data, then extracts protocol blocks."""
        raise NotImplementedError

    @abstractmethod
    def assemble_artifacts(self) -> None:
        """Assembles blocks into artifacts to pass to PEAT for parsing."""
        raise NotImplementedError

    @abstractmethod
    def export_artifacts(self) -> None:
        """Export artifacts to files and/or Elasticsearch."""
        raise NotImplementedError

    @abstractmethod
    def parse_artifacts(self) -> None:
        """Parse constructed artifacts using PEAT."""
        raise NotImplementedError


__all__ = ["HeatArtifact", "HeatProtocol"]
