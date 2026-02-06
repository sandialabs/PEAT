from typing import Any

from peat import log

from .data_utils import DeepChainMap, merge_models
from .models import DeviceData


class Datastore:
    """
    `Registry <https://martinfowler.com/eaaCatalog/registry.html>`__
    of :class:`~peat.data.models.DeviceData` instances.
    """

    objects: list[DeviceData] = None
    """:class:`~peat.data.models.DeviceData` instances in this datastore."""

    global_options: dict[str, Any] = None
    """
    Options that will be applied and used by all devices in this datastore.
    Changes to the values in this :class:`dict` will be reflected in the
    options of all devices in this datastore.
    """

    def __init__(self) -> None:
        self.objects = []
        self.global_options = {}
        self._data_obj: DeviceData | None = None

    def create(self, ident: str, ident_type: str) -> DeviceData:
        """
        Create a new :class:`~peat.data.models.DeviceData`
        instance, add it to the datastore, and return it.
        """
        dev_data = DeviceData(**{ident_type: ident})
        self.objects.append(dev_data)
        return dev_data

    def get(self, ident: str, ident_type: str = "ip") -> DeviceData:
        """
        Get a :class:`~peat.data.models.DeviceData` instance from the datastore.

        .. warning::
           If you want to search for an existing device and fail if one isn't found,
           then use :meth:`~peat.data.store.Datastore.search` instead.

        .. code-block:: python
           :caption: Examples of ``datastore.get()``

           >>> from pprint import pprint
           >>> from peat import SCEPTRE, datastore

           >>> device = datastore.get("192.0.2.20")
           >>> device.ip
           '192.0.2.20'

           >>> device = datastore.get("192.0.2.123")  # doctest: +SKIP
           >>> SCEPTRE.pull(device)  # doctest: +SKIP
           >>> pprint(device.export())  # doctest: +SKIP
           >>> parsed_name = "relay_1"  # Name extracted from the pulled config
           >>> device = datastore.get(parsed_name, "name")  # doctest: +SKIP
           >>> device.data.name == parsed_name  # doctest: +SKIP
           True

        Args:
            ident: Identifier to search for, such as ``192.168.0.1``
            ident_type: What ``ident`` is, e.g. ``"serial_port"`` or ``"ip"``

        Returns:
            The :class:`~peat.data.models.DeviceData` object found or a new
            object if there wasn't a device found that matched the arguments.
        """
        dev = self.search(ident, ident_type)

        if dev:
            return dev

        return self.create(ident, ident_type)

    def search(self, ident: str, ident_type: str) -> DeviceData | None:
        """
        Search for the device with a given identifier.

        Example: During passive scanning a device was initialized with a MAC
        which gets resolved to a IP. Later during active scanning, we want
        to add information to the device. We can look it up by it's IP,
        even if it was originally added to the datastore using it's MAC.

        Args:
            ident: Identifier to search for, such as ``192.168.0.1``
            ident_type: What ``ident`` is, e.g. ``"serial_port"`` or ``"ip"``

        Returns:
            The :class:`~peat.data.models.DeviceData` found or
            :obj:`None` if the search failed
        """
        for obj in self.objects:
            if getattr(obj, ident_type, None) == ident:
                return obj

        return None

    def remove(self, to_remove: DeviceData) -> bool:
        """
        Remove a device from the datastore.

        Args:
            to_remove: :class:`~peat.data.models.DeviceData` instance to remove

        Returns:
            If the device was successfully found and removed
        """
        for i in range(len(self.objects)):
            if self.objects[i] is to_remove:
                del self.objects[i]
                return True

        return False

    def prune_inactive(self) -> None:
        """Remove inactive devices from the datastore (``dev._is_active == False``)."""
        if not self.objects:
            return

        inactive_devs = [x for x in self.objects if not x._is_active]

        for dev in inactive_devs:
            self.remove(dev)

        log.debug(f"Pruned {len(inactive_devs)} inactive devices from datastore")

    def deduplicate(self, prune_inactive: bool = True) -> None:
        """
        Cleanup duplicate devices in the datastore.

        Duplicates are only merged if they have the same IP, MAC or serial port.

        Any duplicates found are merged into a single
        :class:`~peat.data.models.DeviceData` object,
        and the additional copies are removed from the list of objects.

        Args:
            prune_inactive: If inactive devices should be removed before
              beginning deduplication
        """
        if not self.objects:
            return

        if prune_inactive:
            self.prune_inactive()

        # Only log at INFO level if there are enough objects to possibly make it lag
        msg = f"Searching for duplicates in {len(self.objects)} objects..."
        if len(self.objects) > 2:
            log.info(msg)
        else:
            log.debug(msg)

        for obj in self.objects:
            obj.purge_duplicates()

        deduped = []  # type: list[DeviceData]
        removed = set()  # type: set[int]

        for obj in self.objects:
            # Object was removed as a duplicate
            if id(obj) in removed:
                continue

            # Compare anything that isn't the object
            # and wasn't already removed as a duplicate
            for comp in self.objects:
                if id(comp) in removed or comp is obj:
                    continue

                if obj.is_duplicate(comp):
                    log.info(f"Merging duplicate {comp.get_id()} into {obj.get_id()}")

                    # TODO: copy/merge stuff other than the data, e.g. options?
                    # TODO: delete duplicate timeseries document from Elasticsearch
                    # Merge in data from the duplicate
                    merge_models(obj, comp)
                    obj._is_deduplicated = False

                    # Purge any new duplicates from the now-merged object
                    obj.purge_duplicates()

                    # Add duplicate to exclusion list
                    removed.add(id(comp))

            deduped.append(obj)

        self.objects = deduped  # Replace objects list with de-duped objects

        log.debug(
            f"Finished deduplicating objects, {len(removed)} duplicates were merged and removed"
        )

    @property
    def verified(self) -> list[DeviceData]:
        """Devices that have been verified (``dev._is_verified == True``)."""
        return [d for d in self.objects if d._is_verified]

    @property
    def device_options(self) -> DeepChainMap:
        """
        Get global options with module defaults and injects applied.

        This is a hack, to be sure, but refactoring will take more time than it's worth.
        """
        if not self._data_obj:
            self._data_obj = DeviceData()

        return self._data_obj._options


#: Global singleton for managing :class:`~peat.data.models.DeviceData`
#: instances and making them available throughout PEAT.
datastore = Datastore()


__all__ = ["Datastore", "datastore"]
