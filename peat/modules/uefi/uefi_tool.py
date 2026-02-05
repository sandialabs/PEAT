"""
PEAT module for a UEFI SPIExtract Dump.
Right now this tool will parse *spi.*.txt files and *hashes.json files.

Authors

- Danyelle Loffredo
- Tarun Menon
"""

from pathlib import Path

from peat import DeviceData, DeviceModule, datastore
from peat.modules.uefi.uefi_hash_parse import parse_hash
from peat.modules.uefi.uefi_spi_parse import parse_file


class UEFI(DeviceModule):
    device_type = "UEFI"
    filename_patterns = ["spi*.txt", "*hashes*.json"]

    can_parse_dir = True
    module_aliases = ["UEFI", "uefi"]

    @classmethod
    def _parse(
        cls, file: Path, dev: DeviceData | None = None
    ) -> DeviceData | None:
        if not dev:
            dev = datastore.get(f"uefi_{file.stem.lower()}", "id")

        if "hashes" in str(file):
            try:
                hashes_to_append = parse_hash(file)
                dev.uefi_hashes.extend(hashes_to_append)
                dev.write_file(hashes_to_append, "parsed-files.json")
            except Exception as ex:
                cls.log.debug(f"no hash files: {ex}")
                pass
        else:
            try:
                files_to_append = parse_file(file)
                dev.uefi_image.extend(files_to_append)

                for _fileobject in files_to_append:
                    _fileobject.created = None

                dev.write_file(files_to_append, "parsed-files.json")
            except Exception as ex:
                cls.log.debug(f"No spi files: {ex}")
                pass

        cls.update_dev(dev)

        return dev


__all__ = ["UEFI"]
