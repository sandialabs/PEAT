from __future__ import annotations

import copy
from collections import ChainMap
from collections.abc import Callable
from operator import attrgetter
from typing import Any

from peat import PeatError, config, log, utils

from .base_model import BaseModel


class DeepChainMap(ChainMap):
    """
    Variant of :class:`collections.ChainMap` that supports edits of
    nested :class:`dict` objects.

    In PEAT, this is used for providing nested sets of device and protocol
    options (configurations) with the ability the modify the underlying
    sources (e.g. a set of global runtime defaults) and still preserve
    the order of precedence and transparent overriding (e.g. options
    configured at runtime for a specific device will still override the
    global defaults, even though the global defaults were also modified
    at runtime).

    Nested objects can override keys at various levels without overriding
    the parent structure. This is best explained via examples.

    .. code-block:: python

       >>> from peat.data.data_utils import DeepChainMap
       >>> layer1 = {}
       >>> layer2 = {"key": 9999}
       >>> layer3 = {"deep_object": {"deep_key": "The Deep"}}
       >>> deep_map = DeepChainMap(layer1, layer2, layer3)
       >>> deep_map["key"]
       9999
       >>> layer1["key"] = -1111
       >>> deep_map["key"]
       -1111
       >>> layer2["key"]
       9999
       >>> deep_map["deep_object"]["deep_key"]
       'The Deep'
       >>> layer1["deep_object"] = {"another_key": "another_value"}
       >>> deep_map["deep_object"]["deep_key"]
       'The Deep'
       >>> deep_map["deep_object"]["another_key"]
       'another_value'
    """

    def __getitem__(self, key):
        values = []
        for mapping in self.maps:
            try:
                values.append(mapping[key])
            except KeyError:
                pass
        if not values:
            return self.__missing__(key)
        first = values.pop(0)
        rv = first
        if isinstance(first, dict):
            values = [x for x in values if isinstance(x, dict)]
            if values:
                values.insert(0, first)
                rv = self.__class__(*values)
        return rv

    def to_dict(self, to_convert: DeepChainMap | None = None) -> dict:
        """Create a copy of the object as a normal :class:`dict`."""
        if to_convert is None:
            to_convert = self

        converted = {}

        for key, value in dict(to_convert).items():
            if isinstance(value, DeepChainMap):
                converted[key] = self.to_dict(value)
            else:
                converted[key] = value

        return converted


def lookup_by_str(container: list[BaseModel], value: BaseModel, lookup: str) -> int | None:
    """
    String of attribute to search for, e.g. ``"ip"`` to lookup interfaces
    using ``Interface.ip`` attribute on the value.
    """
    if not container:
        return None

    if hasattr(value, lookup) and not value.is_default(lookup):
        value_to_find = getattr(value, lookup)
        if value_to_find not in [None, ""]:
            return find_position(container, lookup, value_to_find)

    return None


def find_position(obj: list[BaseModel], key: str, value: Any) -> int | None:
    """Find if and where an object with a given value is in a :class:`list`."""
    for index, item in enumerate(obj):
        if getattr(item, key, None) == value:
            return index

    return None


def match_all(obj_list: list[BaseModel], value: dict[str, Any]) -> int | None:
    """Search the list for objects where all values in value match."""
    if not value:
        return None

    for loc, item in enumerate(obj_list):
        # If all the values match their corresponding entries in item
        # then return it's location
        vals = item.dict(exclude_defaults=True, exclude_none=True)
        if all(vals.get(key) == value[key] for key in value.keys()):
            return loc

    return None


def strip_empty_and_private(
    obj: dict, strip_empty: bool = True, strip_private: bool = True
) -> dict:
    """Recursively removes empty values and keys starting with ``_``."""
    new = {}
    for key, value in obj.items():
        if strip_private and _is_private(key):
            continue

        elif strip_empty:
            # NOTE: checking type is required to prevent stripping "False", "-1", etc.
            if _is_empty(value):
                continue

            if isinstance(value, dict):
                stripped = strip_empty_and_private(value, strip_empty, strip_private)

                if strip_empty and not stripped:
                    continue
                else:
                    new[key] = stripped
            elif isinstance(value, list):
                # NOTE: lists are not recursively stripped
                new[key] = [
                    (
                        strip_empty_and_private(v, strip_empty, strip_private)
                        if isinstance(v, dict)
                        else v
                    )
                    for v in value
                    if not _is_empty(v)
                ]
            elif isinstance(value, set):
                for empty_val in ["", None]:
                    if empty_val in value:
                        value.remove(empty_val)

                if value:
                    new[key] = value
            else:
                new[key] = value
        else:
            new[key] = value

    return new


def _is_empty(v: Any | None) -> bool:
    return bool(v is None or (isinstance(v, (str, bytes, dict, list, set)) and not v))


def _is_private(key: Any) -> bool:
    return bool(isinstance(key, str) and key.startswith("_"))


def strip_key(obj: dict, bad_key: str) -> dict:
    """
    Recursively removes all matching keys from a :class:`dict`.

    .. warning::
       This will NOT strip values out of a :class:`list` of :class:`dict`!
    """
    new = {}

    for key, value in obj.items():
        if key != bad_key:
            if isinstance(value, dict):
                new[key] = strip_key(value, bad_key)
            else:
                new[key] = value

    return new


def only_include_keys(obj: dict, allowed_keys: str | list[str]) -> dict:
    """
    Filters any keys that don't match the allowed list of keys.
    """
    new = {}
    if isinstance(allowed_keys, str):
        allowed_keys = [allowed_keys]

    for key, value in obj.items():
        if key in allowed_keys:
            new[key] = value

    return new


def compare_dicts(d1: dict | None, d2: dict | None, keys: list[str]) -> bool:
    if not d1 or not d2 or not keys:
        raise PeatError("bad compare_dicts args")

    for key in keys:
        if d1.get(key) is None or d2.get(key) is None:
            continue
        if d1.get(key) != d2.get(key):
            return False

    return True


def dedupe_model_list(current: list[BaseModel]) -> list[BaseModel]:
    """
    Deduplicates a :class:`list` of :class:`~peat.data.base_model.BaseModel`
    objects while preserving the original order.

    Models that are a subset of another (contains some keys and values)
    will be merged together and their values combined.

    Args:
        current: list of models to deduplicate

    Returns:
        List of deduplicated items
    """

    # Don't bother with empty or single-element lists
    if not current or len(current) < 2:
        return current

    if not isinstance(current[0], BaseModel):
        raise PeatError(f"expected BaseModel for dedupe_model_list, got {type(current[0])}")

    # hack to prevent recursive imports (data_utils.py/models.py)
    model_type = current[0].__repr_name__()  # type: str

    # Convert all models to dicts once at the start. Pydantic model comparisons
    # convert to a dict under the hood on every comparison, which is very slow.
    # The id() of each model is used as its key, since it's cheap to hash.
    model_cache = {id(m): m for m in current}  # type: dict[int, BaseModel]
    model_dicts = {id(m): m.dict(exclude_defaults=True, exclude_none=True) for m in current}  # type: dict[int, dict]

    # Services have a special case where a "verified" or "open" service is
    # merged into another with the same port and protocol even if it's not a
    # subset, which changes the merged model. These lists are small, so use
    # the pairwise comparison for them.
    if model_type == "Service":
        duplicates = _find_duplicate_services(model_cache, model_dicts)
    else:
        duplicates = _find_duplicate_models(model_cache, model_dicts)

    # Create a de-duplicated list of objects
    # by excluding those that were marked as duplicate
    deduped = [model for model_id, model in model_cache.items() if model_id not in duplicates]  # type: list[BaseModel]

    if duplicates and config.DEBUG:
        log.trace(
            f"Removed {len(duplicates)} duplicates from list of {len(current)} "
            f"{model_type} items ({len(deduped)} items remaining in list)"
        )

    return deduped


def _freeze(value: Any) -> Any:
    """
    Convert a value from a model dict into a hashable form.

    Values that are equal are guaranteed to have equal frozen forms.
    The reverse isn't guaranteed (e.g. a list and tuple with the same
    items), so matches found using frozen values must still be checked
    against the original values.

    Raises:
        TypeError: If the value is or contains a value that isn't hashable.
            These can't be indexed, since they can be equal to values with
            a different type (e.g. ``bytearray(b"a") == b"a"``).
    """
    if isinstance(value, dict):
        return frozenset((k, _freeze(v)) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(value)
    hash(value)
    return value


def _index_models(
    comp_dicts: dict[int, dict], duplicates: set[int], unindexed: set[str]
) -> tuple[dict[tuple, dict[int, None]], dict[int, list[tuple]]]:
    """
    Index every (key, value) pair of the models that aren't duplicates.

    Keys with a value that can't be hashed in any model are added to
    ``unindexed`` and aren't indexed for any model.

    Returns:
        The index of (key, frozen value) => IDs of models with that pair,
        in list order (dicts are used instead of sets to preserve order
        with O(1) deletes), and the indexed pairs of each model.
    """
    frozen = {}  # type: dict[int, dict[str, Any]]
    for model_id, model_dict in comp_dicts.items():
        if model_id in duplicates:
            continue

        frozen[model_id] = {}
        for key, value in model_dict.items():
            try:
                frozen[model_id][key] = _freeze(value)
            except TypeError:
                unindexed.add(key)

    index = {}  # type: dict[tuple, dict[int, None]]
    model_pairs = {}  # type: dict[int, list[tuple]]
    for model_id, values in frozen.items():
        pairs = [(k, v) for k, v in values.items() if k not in unindexed]
        model_pairs[model_id] = pairs
        for pair in pairs:
            index.setdefault(pair, {})[model_id] = None

    return index, model_pairs


def _find_duplicate_models(
    model_cache: dict[int, BaseModel], model_dicts: dict[int, dict]
) -> set[int]:
    """
    Find models that are equal to or a subset of another model in the list,
    and merge them into the first such model in the list.

    Comparing every model with every other model is O(n^2), which takes
    dozens of minutes for lists with tens of thousands of items, like
    registers on a large relay config (sandialabs/PEAT#20). Instead, every
    (key, value) pair is indexed to the models containing it. A model can
    only be a subset of models that contain all of its pairs, so only the
    models containing its rarest pair need to be checked. This makes
    deduplication close to O(n) for most lists in PEAT.

    The result is identical to comparing all pairs: each model (using its
    original values) is merged into the first model in the list that hasn't
    already been merged into another and is equal to or a superset of it.
    Merging a model into a superset of it shouldn't change the superset,
    but if :func:`merge_models` does change it, the updated values are used
    for the remaining comparisons and the index is rebuilt, so the result
    still matches a pairwise comparison.

    Returns:
        IDs of the models that were merged and should be removed
    """
    duplicates = set()  # type: set[int]

    # Values to compare items against, updated when a model is merged into
    comp_dicts = dict(model_dicts)  # type: dict[int, dict]
    unindexed = set()  # type: set[str]
    index, model_pairs = _index_models(comp_dicts, duplicates, unindexed)

    # Models that aren't duplicates, in list order
    remaining = dict.fromkeys(model_dicts)  # type: dict[int, None]

    for item_id, item_dict in model_dicts.items():
        pairs = []
        for key, value in item_dict.items():
            if key in unindexed:
                continue
            try:
                pairs.append((key, _freeze(value)))
            except TypeError:
                continue

        if pairs:
            # Only models containing the rarest pair can be a superset
            candidates = min((index.get(p, {}) for p in pairs), key=len)
        else:
            # Empty models (or with only unindexed values) could be a subset
            # of any model. For empty models, the first one checked matches.
            candidates = remaining

        for comp_id in candidates:
            if comp_id == item_id:
                continue

            comp_dict = comp_dicts[comp_id]

            # If they're equal, or item is a subset of comp, it's a duplicate.
            # Using subset with "dict.items()": https://stackoverflow.com/a/41579450
            if len(item_dict) <= len(comp_dict) and item_dict.items() <= comp_dict.items():
                # Model was merged, so remove it from future checks
                duplicates.add(item_id)
                del remaining[item_id]
                for pair in model_pairs.pop(item_id):
                    del index[pair][item_id]

                if item_dict != comp_dict:
                    # Update the underlying model which will be in the results
                    merge_models(model_cache[comp_id], model_cache[item_id])

                    new_dict = model_cache[comp_id].dict(exclude_defaults=True, exclude_none=True)
                    if new_dict != comp_dict:
                        comp_dicts[comp_id] = new_dict
                        index, model_pairs = _index_models(comp_dicts, duplicates, unindexed)
                break

    return duplicates


def _find_duplicate_services(
    model_cache: dict[int, BaseModel], model_dicts: dict[int, dict]
) -> set[int]:
    """
    Pairwise deduplication of :class:`~peat.data.models.Service` models.

    In addition to merging services that are a subset of another,
    if a service has a "status" of "verified", or "open" while the
    other is "closed", and the port and protocol match, then the
    services are merged and the status is preserved.

    Returns:
        IDs of the models that were merged and should be removed
    """
    duplicates = set()  # type: set[int]
    outer_dicts = model_dicts
    inner_dicts = copy.deepcopy(model_dicts)  # type: dict[int, dict]

    for item_id, item_dict in outer_dicts.items():
        if item_id in duplicates:
            continue  # outer loop

        for comp_id, comp_dict in inner_dicts.items():
            # Skip if it's in the excluded set or it's the same item
            if comp_id in duplicates or comp_id == item_id:
                continue  # inner loop

            # If they're equal, it's a duplicate
            elif item_dict == comp_dict:
                duplicates.add(item_id)  # add to set of duplicates
                del inner_dicts[item_id]  # remove from future comparisons
                break  # inner loop

            # If item is a subset of comp, then merge them
            # If "status" is "verified", or "open" vs "closed", preserve that value
            elif (item_dict.items() < comp_dict.items()) or (
                (
                    comp_dict.get("status") == "verified"
                    or (comp_dict.get("status") == "open" and item_dict.get("status") == "closed")
                )
                and compare_dicts(item_dict, comp_dict, ["port", "protocol"])
            ):
                # Update the underlying model which will be in the results
                merge_models(model_cache[comp_id], model_cache[item_id])

                # Update the cached dict value to use for remaining comparisons
                inner_dicts[comp_id] = model_cache[comp_id].dict(
                    exclude_defaults=True, exclude_none=True
                )

                # Model was merged, so remove it from future checks
                duplicates.add(item_id)  # add to set of duplicates
                del inner_dicts[item_id]  # remove from future comparisons
                break  # inner loop

    return duplicates


def none_aware_attrgetter(attrs: tuple[str]) -> Callable:
    """
    Variant of ``operator.attrgetter()`` that
    handles values that may be :obj:`None`.
    """

    def g(obj) -> tuple:
        pairs = []

        for attr in attrs:
            value = getattr(obj, attr)
            pairs.append(value is None)
            pairs.append(value)

        return tuple(pairs)

    return g


def sort_model_list(model_list: list[BaseModel]) -> None:
    """
    In-place sort of a :class:`list` of models.

    The attribute ``_sort_by_fields`` on the first model
    in the list is used to sort the models.

    Raises:
        PeatError: invalid type in list or ``_sort_by_fields``
        is undefined on the model being sorted
    """
    if not model_list or len(model_list) < 2:
        return

    if not isinstance(model_list[0], BaseModel):
        raise PeatError(f"expected BaseModel for sort_model_list, got {type(model_list[0])}")

    if not getattr(model_list[0], "_sort_by_fields", None):
        raise PeatError(
            f"No '_sort_by_fields' attribute on model class "
            f"'{model_list[0].__repr_name__()}' to use for sorting"
        )

    if config.DEBUG >= 3:
        log.debug(f"Sorting '{model_list[0].__repr_name__()}' list with {len(model_list)} items")

    model_list.sort(key=none_aware_attrgetter(model_list[0]._sort_by_fields))


def merge_models(dest: BaseModel, source: BaseModel) -> None:
    """
    Copy values from one model to another.
    """
    if not dest or not source:
        return

    if not isinstance(source, BaseModel):
        raise PeatError(f"non-model source: {source}")

    dst_type = dest.__repr_name__()  # type: str
    src_type = source.__repr_name__()  # type: str

    if dst_type != src_type:
        raise PeatError(f"merge_models: '{dst_type}' != '{src_type}'")

    # TODO: hack to make DeviceData merging work
    if dst_type == "DeviceData":
        if source.module:
            for mod_to_merge in source.module:
                # If there's an existing module in same slot, merge the contents
                for curr_mod in dest.module:
                    if curr_mod is mod_to_merge:
                        break  # already in the list, nothing to merge

                    if (
                        curr_mod.slot and mod_to_merge.slot and curr_mod.slot == mod_to_merge.slot
                    ) or (
                        curr_mod.serial_number
                        and mod_to_merge.serial_number
                        and curr_mod.serial_number == mod_to_merge.serial_number
                    ):
                        merge_models(curr_mod, mod_to_merge)
                        break
                # Append the module
                else:
                    dest.module.append(mod_to_merge)

            # Modules without a slot or serial number can't be matched above,
            # so merge any that are equal to or a subset of another module
            # (the same as any other list of models) instead of duplicating them
            dest.module[:] = dedupe_model_list(dest.module)
            dest.module.sort(key=attrgetter("slot"))  # Sort modules by Slot ID

    # WARNING: do NOT call source.dict(...) here!
    # dict(source) converts just the top-level model to a dict, not sub-models.
    # source.dict(...) will convert all sub-models to dicts, which is no bueno.
    source_dict = dict(source)

    overwrite = False

    if dst_type == "Service" and (
        source_dict.get("status") == "verified"
        or (source_dict.get("status") == "open" and dest.status == "closed")
    ):
        overwrite = True

    for attr, new_value in source_dict.items():
        # If it's None for some reason (e.g. a default), we don't care
        if new_value is None:
            continue

        if not hasattr(dest, attr):
            raise PeatError(f"No attribute for key '{attr}'. Value: {new_value}")

        # !! hack to make DeviceData merging work !!
        if dst_type == "DeviceData" and attr == "module":
            continue

        current_value = getattr(dest, attr)

        # Skip if the values match
        # Skip if the source is a default model
        if new_value == current_value or (
            isinstance(source, BaseModel) and source.is_default(attr)
        ):
            continue

        # If they're models (e.g., "Hardware"), use merge_models to handle the merging
        elif isinstance(current_value, BaseModel):
            merge_models(current_value, new_value)

        # Merge dicts, preserving existing values
        # NOTE: this is usually ".extra" fields
        elif isinstance(current_value, dict):
            utils.merge(current_value, new_value, no_copy=True)

        # Sets automatically remove duplicate values
        elif isinstance(current_value, set):
            current_value.update(new_value)

        # Combine, deduplicate, and sort lists
        elif isinstance(current_value, list):
            if current_value and new_value:
                if isinstance(current_value[0], BaseModel):
                    current_value.extend(new_value)
                    # NOTE: dedupe_model_list() returns a new list, it doesn't
                    # modify the list in-place, so update the list in-place.
                    current_value[:] = dedupe_model_list(current_value)
                    sort_model_list(current_value)
                else:
                    for new_item in new_value:
                        if not any(new_item == c for c in current_value):
                            current_value.append(new_item)
            elif new_value:
                setattr(dest, attr, new_value)

        # If the destination value is a default value, then copy the value
        # This won't overwriting existing values on destination
        # NOTE: using setattr() will also trigger value validation by Pydantic
        elif dest.is_default(attr):
            setattr(dest, attr, new_value)

        elif overwrite:
            msg = (
                f"Changed existing value for field '{attr}' with "
                f"'{new_value}' (old value: '{current_value}')"
            )
            if attr == "status":
                log.debug(msg)
            else:
                log.warning(msg)

            setattr(dest, attr, new_value)

        elif config.DEBUG >= 4:
            log.warning(
                f"Skipping merge of existing non-default attribute '{attr}' for "
                f"'{dest.__class__.__name__}' model (new_value={new_value} "
                f"current_value={current_value})"
            )
