import os
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from io import BytesIO
from typing import BinaryIO

from peat import log

# Type alias helpers
OptionalBytes = int | None
MagicTuple = tuple[OptionalBytes, ...]
FileCheck = Callable[[BinaryIO], bool]
SourceInput = str | os.PathLike | bytes | bytearray | memoryview | BinaryIO | None


@contextmanager
def _as_byte_stream(source: SourceInput) -> Iterator[BinaryIO]:
    """
    Normalize various input into a binary stream whose .read() returns bytes.

    If this function opens the stream, it closes it.
    If the caller passed an existing stream, it leaves it open.
    """

    # Path-like input
    if isinstance(source, (str, os.PathLike)):
        with open(source, "rb") as f:
            yield f
        return

    # Bytes-like input
    if isinstance(source, memoryview):
        yield BytesIO(source.tobytes())
        return
    if isinstance(source, (bytes, bytearray)):
        yield BytesIO(source)
        return

    # Existing file-like object
    if hasattr(source, "read"):
        yield source
        return

    raise TypeError(f"Unsupported input type: {type(source)}")


@dataclass(slots=True, frozen=True)
class FileSignature:
    """
    Logic necessary to track and validate file signatures. Each instance is a singular checker, but
    all contained checks must match/pass for the signature to be considered a match.

    Invalid signatures will always fail to match.

    Supported check types:
    - magic_number: A str of hex characters to search for at the beginning, ?? is a wildcard
    - xml_tags: A [str] of XML tags to search for, ordered list
    - substrings: A [str | bytes] of substrings to search for, ordered list
    - custom_check: A function for custom checking, a [Path] is passed and it returns True/False
    """

    default_filename: str
    magic_number: str | None = None
    xml_tags: list[str] | None = None
    substrings: list[str | bytes] | None = None
    custom_check: FileCheck | None = None

    _magic_number: MagicTuple = field(init=False, repr=False)
    _valid: bool = field(init=False, repr=False)

    def __post_init__(cls) -> None:
        object.__setattr__(cls, "_magic_number", None)
        object.__setattr__(cls, "_valid", False)

        has_magic_number = cls.magic_number is not None and cls.magic_number != ""
        has_xml_tags = not cls._is_empty(cls.xml_tags)
        has_substrings = not cls._is_empty(cls.substrings)
        has_custom_check = cls.custom_check is not None

        if not (has_magic_number or has_xml_tags or has_substrings or has_custom_check):
            log.warning(
                "Invalid FileSignature: no signature check provided."
                " This signature should never match."
            )
            return

        if has_magic_number:
            magic_bytes = cls._parse_magic_number(cls.magic_number)
            if magic_bytes is None:
                log.warning(
                    f"Invalid FileSignature: magic_number is invalid: {cls.magic_number}."
                    " This signature should never match."
                )
                return
            object.__setattr__(cls, "_magic_number", magic_bytes)

        object.__setattr__(cls, "_valid", True)

    @staticmethod
    def _is_empty(data: list[str] | MagicTuple) -> bool:
        """
        Returns
        - False if populated and valid (not empty, only None or "", etc.)
        - True if empty (or invalid)
        """

        if isinstance(data, list):
            return not any(data or [])
        if isinstance(data, tuple):
            return not any(data) or all(x == 0 for x in data)
        return True  # did not check; so assume empty

    @staticmethod
    def _parse_magic_number(pattern: str) -> MagicTuple | None:
        """
        Convert magic-number hex string to a tuple of byte values. A double question mark (??)
        token is a wildcard byte (0x00-0xFF).

        Example:
            "1234??abcd"

        Becomes:
            [0x12, 0x34, None, 0xab, 0xcd]

        Returns None if the pattern is invalid.
        """

        # Explicit check/fail for anything but string.
        # Alternative pathing gets complex for minimal gain.
        if isinstance(pattern, str):
            magic_number = pattern
        else:
            return None

        # Sanity checks
        if magic_number is None or len(magic_number) == 0 or len(magic_number) % 2 != 0:
            return None

        pattern: list[OptionalBytes] = []
        for i in range(0, len(magic_number), 2):
            byte_str = magic_number[i : i + 2]
            if byte_str == "??":
                pattern.append(None)
                continue
            if "?" in byte_str:
                return None
            try:
                pattern.append(int(byte_str, 16))
            except ValueError:
                return None

        # Ensure at least one not None
        if not any(p is not None for p in pattern):
            return None

        return tuple(pattern)

    def matches(cls, source: SourceInput) -> bool:
        """
        Checks signature against a path-like, bytes-like, or binary file-like source.

        Returns
        - True if the data stream matches this signature (all patterns)
        - False otherwise (failures or no valid tests)
        """
        if not cls._valid or not source:
            return False
        try:
            results = []
            with _as_byte_stream(source) as stream:
                results.append(cls._matches_magic_number(stream, cls._magic_number))
                stream.seek(0)
                results.append(cls._matches_xml_tags(stream, cls.xml_tags))
                stream.seek(0)
                results.append(cls._matches_substrings(stream, cls.substrings))
                stream.seek(0)
                results.append(cls._matches_custom_check(stream, cls.custom_check))
                stream.seek(0)

            log.debug(f"Signature results: {results}")
            return (
                bool(results)  # test not all None (at least one ran)
                and all(r is not False for r in results)  # test no False (no failures)
            )
        except Exception as e:
            log.warning(f"Unexpected exception during file signature checks: {e}")
            return False

    def _matches_magic_number(cls, data: BinaryIO, magic_bytes: MagicTuple | None) -> bool | None:
        """
        Checks data for magic bytes.  Fuzzy matches (e.g., within the first X bytes) is not
        supported.

        Returns
        - None if test skipped
        - True IFF all tests pass
        - False if any test fails or not tried
        """
        log.trace(f"Magic bytes check: {magic_bytes}")
        if cls._is_empty(magic_bytes):
            return None
        byte_size = len(magic_bytes)
        file_start = data.read(byte_size)
        if len(file_start) != byte_size:
            return False
        for file_byte, magic_byte in zip(file_start, magic_bytes, strict=True):
            if magic_byte is not None and file_byte != magic_byte:
                return False
        return True

    def _matches_xml_tags(cls, data: BinaryIO, tags: [str]) -> bool | None:
        """
        Checks data for XML tags.  Note that this does not ensure valid XML, so invalid XML may
        still match depending on if/how python's `xml.etree.ElementTree.iterparse()` logic
        processes it.

        Returns
        - None if test skipped
        - True IFF all tests pass
        - False if any test fails or not tried
        """
        log.trace(f"XML tags check: {tags}")
        if cls._is_empty(tags):
            return None
        index_count = 0
        match_need_count = len(tags)
        try:
            for _, elem in ET.iterparse(data, events=("start",)):
                # well formed; iterparse should only return one tag per iteration, so one match
                if elem.tag == tags[index_count]:
                    index_count += 1
                if index_count == match_need_count:
                    return True
        except Exception as ex:
            log.debug(f"XML parsing exception: {ex}")

        return False

    def _matches_substrings(
        cls,
        data: BinaryIO,
        substrings: [str | bytes],
        encoding: str = "utf-8",
    ) -> bool | None:
        """
        Checks data for byte substrings.  If the list has a str object, it will instead use they
        byte string as returned from `str.encode()` with the targeted `encoding`.

        Returns
        - None if test skipped
        - True IFF all tests pass
        - False if any test fails or not tried
        """
        log.trace(f"Strings check: {substrings}")
        if cls._is_empty(substrings):
            return None
        # sanity check and normalize pattern list to byte substrings
        byte_substrings: [bytes] = []
        for s in substrings:
            if isinstance(s, str):
                byte_substrings.append(s.encode(encoding))
            else:  # bytes or otherwise
                byte_substrings.append(s)
        index_count = 0
        match_need_count = len(byte_substrings)
        for line in data:
            # not well formed; a "line" could contain multiple matches
            pos = 0
            while (
                index_count < match_need_count
                and (found := line.find(byte_substrings[index_count], pos)) != -1  # search, record
            ):
                pos = found + len(byte_substrings[index_count])  # move past found string
                index_count += 1
            if index_count == match_need_count:
                return True

        return False

    def _matches_custom_check(cls, data: BinaryIO, custom_check: FileCheck | None) -> bool | None:
        """
        Checks data using caller's function.  The data passed to the function is a byte stream.

        Returns
        - None if test skipped
        - True IFF all tests pass
        - False if any test fails or not tried
        """
        log.trace(f"Custom check: {custom_check}")
        if custom_check is None:
            return None
        if not custom_check(data):
            return False
        return True


__all__ = ["FileSignature"]
