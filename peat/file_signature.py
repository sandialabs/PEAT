import os
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from io import BytesIO
from typing import Any, BinaryIO, Final, Self, TypeAlias

from pydantic import (
    BaseModel,
    ConfigDict,
    PrivateAttr,
    StrictBool,
    StrictBytes,
    StrictInt,
    StrictStr,
)

try:
    from pydantic import model_validator

    PYDANTIC_V2 = True
except ImportError:
    PYDANTIC_V2 = False

    def model_validator(*args: Any, **kwargs: Any) -> Callable:  # noqa: ARG001
        def decorator(func: Callable) -> Callable:
            return func

        return decorator


from peat import log

# TODO after Pydantic v2 issue resolved:
# - remove alternate v1 flows
# - annotate custom types with TypeAlias (like MagicTuple); doing prior caused static analyzers
#   to be confused

# Type alias helpers
if PYDANTIC_V2:
    OptionalBytes = int | None
    FileCheck = Callable[[BinaryIO], bool]
    SourceInput = str | os.PathLike | bytes | bytearray | memoryview | BinaryIO | None
else:
    OptionalBytes = StrictInt | None
    FileCheck = Callable[[BinaryIO], StrictBool]
    SourceInput = StrictStr | os.PathLike | StrictBytes | bytearray | memoryview | BinaryIO | None
MagicTuple: TypeAlias = tuple[OptionalBytes, ...]


@contextmanager
def _as_byte_stream(source: SourceInput) -> Iterator[BinaryIO]:
    """
    Normalize various input into a binary stream whose ``.read()`` returns bytes.

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
    if hasattr(source, "read") and source:
        yield source
        return

    raise TypeError(f"Unsupported input type: {type(source)}")


SCHEMA_EXTRA: Final[dict] = {
    "anyOf": [
        {
            "required": ["magic_number"],
            "properties": {
                "magic_number": {
                    "type": "string",
                    "minLength": 1,
                }
            },
        },
        {
            "required": ["xml_tags"],
            "properties": {
                "xml_tags": {
                    "type": "array",
                    "minItems": 1,
                }
            },
        },
        {
            "required": ["substrings"],
            "properties": {
                "substrings": {
                    "type": "array",
                    "minItems": 1,
                }
            },
        },
        {
            "required": ["custom_check"],
            "properties": {
                "custom_check": {
                    "not": {
                        "type": "null",
                    }
                }
            },
        },
    ]
}


class FileSignature(BaseModel):
    """
    Provides the logic necessary to track and validate file signatures for supported devices.

    That is, a :class:`~peat.file_signature.FileSignature` is some combination of checks which
    examine the contents of a data stream to confirm that it is of a specific form and is from a
    specific supported device.
    Each instance is a singular checker, but all non-:data:`None` checks must match/pass for the
    signature to be considered a match.

    Supported check types:
        - Magic Number, :attr:`~peat.file_signature.FileSignature.magic_number`
        - XML Tags, :attr:`~peat.file_signature.FileSignature.xml_tags`
        - Substrings, :attr:`~peat.file_signature.FileSignature.substrings`
        - Custom Function, :attr:`~peat.file_signature.FileSignature.custom_check`

    Raises:
        ValueError
            If the file signature is considered invalid from the provided values.
    """

    #: Pydantic configuration.
    #: Rejects unknown fields and makes instances immutable.
    if PYDANTIC_V2:
        model_config: ConfigDict = ConfigDict(
            frozen=True,
            strict=True,
            extra="forbid",
            arbitrary_types_allowed=True,
            json_schema_extra=SCHEMA_EXTRA,
        )
    else:

        class Config:
            frozen = True
            extra = "forbid"
            arbitrary_types_allowed = True
            schema_extra = SCHEMA_EXTRA

    default_filename: str
    """
    A string file name value to be associated with this signature.

    This value is not used to confirm the signature, but required to associate the checks to a
    specific file.
    """

    if PYDANTIC_V2:
        magic_number: str | None = None
    else:
        magic_number: StrictStr | None = None
    """
    A string of hex characters to search for starting at the beginning of the data stream.

    A ``??`` (double question mark) can be used as a wildcard character.
    """

    if PYDANTIC_V2:
        xml_tags: tuple[str, ...] | None = None
    else:
        xml_tags: tuple[StrictStr, ...] | None = None
    """
    A tuple of strings of XML tags to search for in the data stream.

    Strings are matched sequentially and each string must occur after the previous match.
    """

    if PYDANTIC_V2:
        substrings: tuple[str | bytes, ...] | None = None
    else:
        substrings: tuple[StrictStr | StrictBytes, ...] | None = None
    """
    A tuple of strings or bytes to search for as substrings in the data stream.

    Strings are matched sequentially and each string must occur after the previous match.
    Matching is not limited to whole words.
    For example, ``in`` will match for either ``in`` or ``dine``.
    """

    custom_check: FileCheck | None = None
    """
    A function which will perform the user-defined checks on a data stream.

    A :class:`~typing.BinaryIO` is passed to the function and a :class:`bool` representing
    pass/fail is expected.
    """

    #: Normalized ``magic_number`` as a tuple of bytes
    _magic_number: MagicTuple | None = PrivateAttr(default=None)

    if not PYDANTIC_V2:

        def __init__(self, **data: Any) -> None:
            super().__init__(**data)
            self.require_at_least_one_checker()
            self.validate_magic_number()

    @model_validator(mode="after")
    def require_at_least_one_checker(self) -> Self:
        """
        Perform domain specific, post-initialization validation.

        This ensures at least one check type has been provided.
        """
        has_magic_number = bool(self.magic_number)
        has_xml_tags = bool(self.xml_tags)
        has_substrings = bool(self.substrings)
        has_custom_check = self.custom_check is not None

        if not (has_magic_number or has_xml_tags or has_substrings or has_custom_check):
            raise ValueError("Invalid FileSignature: no signature check provided.")

        return self

    @model_validator(mode="after")
    def validate_magic_number(self) -> Self:
        """
        Perform domain specific, post-initialization validation.

        This validates and normalizes the provided magic number.
        """
        self._magic_number = None
        if not bool(self.magic_number):
            return self

        magic_bytes = self._parse_magic_number(self.magic_number)
        if magic_bytes is None:
            raise ValueError(
                f"Invalid FileSignature: magic_number is invalid: {self.magic_number}."
            )
        self._magic_number = magic_bytes
        return self

    @staticmethod
    def _is_empty(data: tuple[str | bytes, ...] | MagicTuple) -> bool:
        """
        Checks if `data` is considered empty.

        Returns:
            - :data:`False` if populated and valid (not empty, not only :data:`None` or ``""``,
              etc.)
            - :data:`True` if empty (or invalid/unsupported)
        """

        # Allow a malformed tuple `("str")` which becomes `"str"`
        if isinstance(data, str):
            return not data.strip()
        if isinstance(data, bytes):
            return data == b""
        if isinstance(data, tuple):
            return not any(data) or all(x == 0 for x in data)
        return True  # did not check; so assume empty

    @staticmethod
    def _parse_magic_number(pattern: str | None) -> MagicTuple | None:
        """
        Convert `pattern`, a magic number hex string, to a consistent format, tuple of bytes, for
        other checks within this object.

        A double question mark (``??``) is considered a wildcard byte (``0x00``-``0xFF``) and will
        be mapped to a :data:`None` value in the tuple.

        Example:

        .. code-block:: python

            _parse_magic_number("1234??abcd")
            [18, 52, None, 171, 205]
            # which is equivalent to: [0x12, 0x34, None, 0xab, 0xcd]

        Returns:
            - :data:`None` if the pattern is invalid.
            - A tuple of :class:`int` or :data:`None` values if valid.
        """

        # Sanity checks
        if not isinstance(pattern, str) or not pattern or len(pattern) % 2:
            return None

        magic_number = pattern

        hex_list: list[OptionalBytes] = []
        for i in range(0, len(magic_number), 2):
            byte_str = magic_number[i : i + 2]
            if byte_str == "??":
                hex_list.append(None)
                continue
            if "?" in byte_str:
                return None
            try:
                hex_list.append(int(byte_str, 16))
            except ValueError:
                return None

        # Ensure at least one not None
        hex_tuple = tuple(hex_list)
        if FileSignature._is_empty(hex_tuple):
            return None
        else:
            return hex_tuple

    def matches(self, source: SourceInput) -> bool:
        """
        Checks this signature against a path-like, bytes-like, or binary file-like `source`.

        Returns:
            - :data:`True` if this signature matches (all patterns)
            - :data:`False` otherwise (failures or no valid checks)
        """
        if not source:
            return False
        try:
            results = []
            with _as_byte_stream(source) as stream:
                results.append(self._matches_magic_number(stream, self._magic_number))
                stream.seek(0)
                results.append(self._matches_xml_tags(stream, self.xml_tags))
                stream.seek(0)
                results.append(self._matches_substrings(stream, self.substrings))
                stream.seek(0)
                results.append(self._matches_custom_check(stream, self.custom_check))
                stream.seek(0)

            log.debug(f"Signature results: {results}")
            return (
                bool(results)  # test not all None (at least one ran)
                and all(r is not False for r in results)  # test no False (no failures)
            )
        except Exception as e:
            log.warning(f"Unexpected exception during file signature checks: {e}")
            return False

    def _matches_magic_number(self, data: BinaryIO, magic_bytes: MagicTuple | None) -> bool | None:
        """
        Checks if `data` begins with `magic_bytes`.

        For clairty, a fuzzy match (e.g., within the first X bytes) is not supported.

        Returns:
            - :data:`None` if check skipped
            - :data:`True` if and only if all tests pass
            - :data:`False` if any test fails or not tried
        """
        log.trace3(f"Magic bytes check: {magic_bytes}")
        if magic_bytes is None or self._is_empty(magic_bytes):
            return None
        byte_size = len(magic_bytes)
        file_start = data.read(byte_size)
        if len(file_start) != byte_size:
            return False
        for file_byte, magic_byte in zip(file_start, magic_bytes, strict=True):
            if magic_byte is not None and file_byte != magic_byte:
                return False
        return True

    def _matches_xml_tags(self, data: BinaryIO, tags: tuple[str, ...] | None) -> bool | None:
        """
        Checks if `data` contains all `tags`.

        Note that this does not ensure valid XML.
        Invalid XML may still match depending on if/how Python's
        :func:`xml.etree.ElementTree.iterparse` logic processes it.

        Returns:
            - :data:`None` if check skipped
            - :data:`True` if and only if all tests pass
            - :data:`False` if any test fails or not tried
        """
        log.trace3(f"XML tags check: {tags}")
        if tags is None or self._is_empty(tags):
            return None
        if isinstance(tags, str):
            tags = tuple(tags)
        index_count = 0
        match_need_count = len(tags)
        try:
            for _, elem in ET.iterparse(data, events=("start",)):  # noqa: S314 - expat ignores external entities
                # well formed; iterparse should only return one tag per iteration, so one match
                if elem.tag == tags[index_count]:
                    index_count += 1
                if index_count == match_need_count:
                    return True
        except Exception as ex:
            log.debug(f"XML parsing exception: {ex}")

        return False

    def _matches_substrings(
        self,
        data: BinaryIO,
        substrings: tuple[str | bytes, ...] | None,
        encoding: str = "utf-8",
    ) -> bool | None:
        """
        Checks if `data` contains all `substrings`.

        If `substrings` contains a :class:`str`, this will first convert the string to bytes, as
        returned from :meth:`str.encode` with the targeted `encoding`, before attempting to perform
        any matching logic.

        Returns:
            - :data:`None` if check skipped
            - :data:`True` if and only if all tests pass
            - :data:`False` if any test fails or not tried
        """
        log.trace3(f"Strings check: {substrings}")
        if substrings is None or self._is_empty(substrings):
            return None
        if isinstance(substrings, str):
            substrings = tuple(substrings)
        # sanity check and normalize pattern list to byte substrings
        byte_substrings: list[bytes] = []
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

    def _matches_custom_check(self, data: BinaryIO, custom_check: FileCheck | None) -> bool | None:
        """
        Checks return value of `custom_check` after passing it `data`.

        Returns:
            - :data:`None` if `custom_check` is :data:`None`
            - :data:`True` if and only if `custom_check` returns :data:`True`
            - :data:`False` if `custom_check` returns :data:`False` or otherwise fails
        """
        log.trace3(f"Custom check: {custom_check}")
        if custom_check is None:
            return None
        try:
            return custom_check(data) is True
        except Exception as ex:
            log.warning(f"Custom check threw exception: {ex}")
            return False


__all__ = ["FileSignature"]
