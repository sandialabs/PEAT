"""
Test suite for peat/file_signature.py module.

This module tests the FileSignature class which is responsible for validating file signatures based
on various criteria, including:
- magic numbers
- XML tags
- substrings
- custom function logic
"""

import io
from pathlib import Path
from typing import BinaryIO

import pytest

from peat.file_signature import FileSignature


class TestMagicNumberSignatures:
    """Test magic number signature related functionality."""

    def test_magic_number_valid_signature(self):
        """Test that a signature with a valid magic number is valid."""
        sig = FileSignature(default_filename="test.file", magic_number="12345678")
        assert sig._valid is True
        assert sig._magic_number == (0x12, 0x34, 0x56, 0x78)

    magic_number_params_validity = [
        # Valid
        pytest.param("1234abcd", (0x12, 0x34, 0xAB, 0xCD), id="All hex"),
        pytest.param("12??ab", (0x12, None, 0xAB), id="Has wildcard"),
        pytest.param("12??ab??", (0x12, None, 0xAB, None), id="Multiple wildcards"),
        # Invalid
        pytest.param("12gh", None, id="Non-hex"),
        pytest.param(1234, None, id="Non-string"),
        pytest.param("123", None, id="Odd length"),
        pytest.param("12?4", None, id="Partial wildcard v1"),
        pytest.param("1?34", None, id="Partial wildcard v2"),
        pytest.param("????", None, id="Wildcard only"),
        pytest.param(None, None, id="None input"),
        pytest.param("", None, id="Empty input"),
    ]

    @pytest.mark.parametrize(
        ("pattern", "expected"),
        magic_number_params_validity,
    )
    def test_magic_number_validity(self, pattern, expected):
        """Test various valid and invalid magic numbers, via typical usage."""
        sig = FileSignature(default_filename="test.file", magic_number=pattern)
        if expected:
            assert sig._valid is True
            assert sig._magic_number == expected
        else:
            assert sig._valid is False
            assert sig._magic_number is None

    @pytest.mark.parametrize(
        ("pattern", "expected"),
        magic_number_params_validity,
    )
    def test_magic_number_parser(self, pattern, expected):
        """Test various valid and invalid magic numbers, via internal _parse_magic_number."""
        result = FileSignature._parse_magic_number(pattern)
        assert result == expected

    @pytest.mark.parametrize(
        ("magic", "hex_data", "expected"),
        [
            pytest.param("12345678", "12345678", True, id="Typical"),
            pytest.param("12345678", "DEADBEEF", False, id="Wrong magic"),
            pytest.param("123456", "12345678", True, id="Shorter magic"),
            pytest.param("12345678", "123456", False, id="Longer magic"),
            pytest.param("1234??56", "1234FF56", True, id="Wildcard magic"),
        ],
    )
    def test_magic_number_matching(self, magic, hex_data, expected):
        """Test magic number match logic, via typical usage."""
        sig = FileSignature(default_filename="test.file", magic_number=magic)
        source = io.BytesIO(bytes.fromhex(hex_data))
        assert sig.matches(source) is expected

    @pytest.mark.parametrize(
        ("magic_bytes", "expected"),
        [
            pytest.param(None, False, id="None magic"),
            pytest.param((0x12, 0x34), True, id="Right magic"),
            pytest.param((0x21, 0x43), False, id="Wrong magic"),
            pytest.param((0x12, None, 0x45), False, id="Wildcard magic"),
        ],
    )
    def test_magic_number_matches_bytes(self, magic_bytes, expected):
        """Test magic number match logic, via internal _matches_magic_number."""
        sig = FileSignature(default_filename="test.file", magic_number="1234")
        hex_data = "12345678"
        source = io.BytesIO(bytes.fromhex(hex_data))
        if magic_bytes is None:
            assert sig._matches_magic_number(source, magic_bytes) is None
        else:
            assert sig._matches_magic_number(source, magic_bytes) == expected


class TestXMLTagSignatures:
    """Test XML tag signature related functionality."""

    def test_xml_tags_valid_signature(self):
        """Test that a signature with XML tags is valid."""
        sig = FileSignature(default_filename="test.file", xml_tags=["root", "data"])
        assert sig._valid is True

    @pytest.mark.parametrize(
        ("tags", "expected"),
        [
            # Valid
            pytest.param(["root"], True, id="Populated list"),
            # Invalid -- minimal Falsy lists as "_is_empty" logic tested elsewhere
            pytest.param(None, False, id="None"),
            pytest.param([], False, id="Empty list"),
            pytest.param([""], False, id="Empty string list"),
        ],
    )
    def test_xml_tags_validity(self, tags, expected):
        """Test various valid and invalid XML tags."""
        sig = FileSignature(default_filename="test.file", xml_tags=tags)
        assert sig._valid is expected

    @pytest.mark.parametrize(
        ("data", "expected"),
        [
            pytest.param(
                b'<?xml version="1.0"?><root><data>content</data></root>', True, id="Header"
            ),
            pytest.param(b"<root><data>content</data></root>", True, id="No header"),
            pytest.param(b"<root><not-data>content</not-data></root>", False, id="Missing tag"),
            pytest.param(b"<data><root>content</root></data>", False, id="Wrong order tags"),
            pytest.param(b"<not-root><data>content</data></not-root>", False, id="Last tag only"),
            pytest.param(b" root data content data root ", False, id="No tags"),
        ],
    )
    def test_xml_tags_matching(self, data, expected):
        """Test XML tags match logic."""
        tags = ["root", "data"]
        sig = FileSignature(default_filename="test.file", xml_tags=tags)
        source = io.BytesIO(data)
        assert sig.matches(source) is expected
        # Directly check the internal function as well
        assert sig._matches_xml_tags(source, tags) == expected

    def test_xml_tags_matches_none(self):
        """Test XML tags match logic with None, via internal _matches_xml_tags."""
        sig = FileSignature(default_filename="test.file")
        source = io.BytesIO(b"data")
        assert sig._matches_xml_tags(source, None) is None


class TestSubtringSignatures:
    """Test substring signature related functionality."""

    def test_substrings_valid_signature(self):
        """Test that a signature with substrings is valid."""
        sig = FileSignature(default_filename="test.file", substrings=["hello", "world"])
        assert sig._valid is True

    @pytest.mark.parametrize(
        ("substrings", "expected"),
        [
            # Valid
            pytest.param(["string"], True, id="Populated list"),
            # Invalid -- minimal Falsy lists as "_is_empty" logic tested elsewhere
            pytest.param(None, False, id="None"),
            pytest.param([], False, id="Empty list"),
            pytest.param([""], False, id="Empty string list"),
        ],
    )
    def test_substrings_validity(self, substrings, expected):
        """Test various valid and invalid substrings."""
        sig = FileSignature(default_filename="test.file", substrings=substrings)
        assert sig._valid is expected

    @pytest.mark.parametrize(
        ("data", "expected"),
        [
            pytest.param(b"string\nbytes\n", True, id="Multiple line"),
            pytest.param(b"string bytes", True, id="Single line"),
            pytest.param(b"string bytestring", True, id="Substring match"),
            pytest.param(b"string\nstring\n", False, id="Missing"),
            pytest.param(b"bytes\nstring\n", False, id="Wrong order multiple line"),
            pytest.param(b"bytes string", False, id="Wrong order single line"),
        ],
    )
    def test_substrings_matching(self, data, expected):
        """Test substrings match logic."""
        substrings = ["string", b"bytes"]  # str | bytes
        sig = FileSignature(default_filename="test.file", substrings=substrings)
        source = io.BytesIO(data)
        assert sig.matches(source) is expected
        # Directly check the internal function as well
        assert sig._matches_substrings(source, substrings) == expected

    def test_substrings_matches_none(self):
        """Test substrings match logic with None, via internal _matches_substrings."""
        sig = FileSignature(default_filename="test.file")
        source = io.BytesIO(b"data")
        assert sig._matches_substrings(source, None) is None


class TestCustomCheckSignatures:
    """Test custom check signature related functionality."""

    def test_custom_check_valid_signature_with_named(self):
        """Test that a signature with a named function is valid."""

        def custom_check(_source):
            return True

        sig = FileSignature(default_filename="test.file", custom_check=custom_check)
        assert sig._valid is True

    def test_custom_check_valid_signature_with_lambda(self):
        """Test that a signature with a lambda function is valid."""
        sig = FileSignature(
            default_filename="test.file",
            custom_check=lambda _source: True,
        )
        assert sig._valid is True

    # NOTE: Validity checks either covered by matching checks or fall under (API) user's purview

    @pytest.mark.parametrize(
        ("check", "expected"),
        [
            pytest.param(lambda _source: True, True, id="Always return True"),
            pytest.param(
                lambda source: (
                    isinstance(source, (BinaryIO, io.BufferedIOBase))  # sanity check for read
                    and source.read().strip() == b"test content"
                ),
                True,
                id="Minimal logic",
            ),
            pytest.param(lambda _source: False, False, id="Always return False"),
            pytest.param(lambda _source: None, False, id="Always return None"),
            pytest.param(None, False, id="None function"),
        ],
    )
    def test_custom_check_matching(self, check, expected):
        """Test custom check matching logic."""
        sig = FileSignature(default_filename="test.file", custom_check=check)
        source = io.BytesIO(b"test content")
        assert sig.matches(source) == expected
        # Directly check the internal function as well
        if check is None:
            assert sig._matches_custom_check(source, check) is None
        else:
            assert sig._matches_custom_check(source, check) == expected

    def test_custom_check_passes_source(self):
        """Test custom check passes source data through."""

        def custom_check(data):
            nonlocal received_source
            received_source = data
            return True

        received_source = None
        sig = FileSignature(default_filename="test.file", custom_check=custom_check)
        source = io.BytesIO(b"test content")
        assert sig.matches(source) is True
        assert received_source == source
        assert isinstance(received_source, (BinaryIO, io.BufferedIOBase))


class TestMultipleSignatureTypes:
    """Test signatures that combine multiple signature types."""

    @pytest.mark.parametrize(
        ("magic", "expected"),
        [
            pytest.param("3C3F786D6C", True, id="All pass"),
            pytest.param("3C3F786D6D", False, id="One fails; magic"),
        ],
    )
    def test_multiple_checks_match_all_pass(self, magic, expected):
        """Test that all checks must pass for a match."""
        sig = FileSignature(
            default_filename="test.file",
            magic_number=magic,
            xml_tags=["root"],
            substrings=["<root>"],  # re-check xml tag as string to ensure position reset
        )
        source = io.BytesIO(b'<?xml version="1.0"?><root>content</root>')
        assert sig.matches(source) is expected


class TestGeneralObjectFeatures:
    """Test general object features and capabilities."""

    def test_invalid_signature_no_check_no_match(self):
        """Test that a signature with no checks is invalid and doesn't match."""
        sig = FileSignature(default_filename="test.file")
        assert sig._valid is False
        source = io.BytesIO(b"\x12\x34\x56\x78")
        assert sig.matches(source) is False

    def test_nonexistent_file_no_match(self):
        """Test that nonexistent file returns False."""
        sig = FileSignature(default_filename="test.file", magic_number="12345678")
        assert sig.matches(Path("/nonexistent/path/test.file")) is False

    @pytest.mark.parametrize(
        ("make_source"),
        [
            pytest.param(lambda _source, _data: str(_source), id="str"),
            pytest.param(lambda _source, _data: Path(_source), id="os.PathLike"),
            pytest.param(lambda _source, _data: bytes(_data), id="bytes"),
            pytest.param(lambda _source, _data: bytearray(_data), id="bytearray"),
            pytest.param(lambda _source, _data: memoryview(_data), id="memoryview"),
            pytest.param(lambda _source, _data: io.BytesIO(_data), id="BinaryIO"),
            pytest.param(lambda _source, _data: None, id="None"),
            pytest.param(lambda _source, _data: 1234, id="Non-sensical source"),
        ],
    )
    def test_source_type_support(self, tmp_path, make_source):
        """Test handled source types."""
        path = tmp_path / "test.file"
        data = b"hello world"
        path.write_bytes(data)
        source = make_source(path, data)

        sig = FileSignature(
            default_filename="test.file",
            substrings=["hello", "world"],
        )

        if not source or source == 1234:
            assert sig.matches(source) is False
        else:
            assert sig.matches(source) is True


class TestIsEmptyMethod:
    """Test the internal _is_empty method."""

    @pytest.mark.parametrize(
        ("data", "expected"),
        [
            pytest.param(None, True, id="None"),
            # list[str]
            pytest.param([], True, id="list-nothing"),
            pytest.param([None], True, id="list-None"),
            pytest.param([""], True, id="list-one empty"),
            pytest.param([None, ""], True, id="list-None and empty"),
            pytest.param(["1"], False, id="list-one str"),
            pytest.param(["1", "2"], False, id="list-multiple str"),
            pytest.param(["1", None], False, id="list-one str, None last"),
            pytest.param([None, "1"], False, id="list-one str, None first"),
            pytest.param(["1", ""], False, id="list-one str, empty last"),
            pytest.param(["", "1"], False, id="list-one str, empty first"),
            # tuple[int | None, ...]
            pytest.param((), True, id="tuple-nothing"),
            # ((None), True), # Is equivalent to prior `(None, True)`
            pytest.param((None, None), True, id="tuple-multiple None"),
            pytest.param((0), True, id="tuple-one null"),
            pytest.param((0, 0, 0), True, id="tuple-multiple null"),
            pytest.param((0, None, 0), True, id="tuple-null and None"),
            pytest.param((0, 1, 0), False, id="tuple-null and non-null"),
            pytest.param((1, 2, 3), False, id="tuple-multiple non-null"),
        ],
    )
    def test_is_empty(self, data, expected):
        """Test if a list or tuple is considered empty."""
        assert FileSignature._is_empty(data) is expected


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_matches_with_oserror(self, tmp_path):
        """Test that OSError during file reading is handled gracefully."""
        sig = FileSignature(default_filename="test.file", magic_number="1234")

        # Create a file with no read permissions
        test_file = tmp_path / "test.file"
        test_file.write_bytes(b"\x12\x34\x56\x78")
        test_file.chmod(0o000)

        try:
            assert sig.matches(test_file) is False
        finally:
            test_file.chmod(0o644)

    def test_matches_with_unexpected_exception(self, tmp_path, mocker):
        """Test that unexpected exceptions are handled gracefully."""
        sig = FileSignature(default_filename="test.file", magic_number="1234")

        # Mock the file open to raise an exception
        mocker.patch("builtins.open", side_effect=RuntimeError("Test error"))

        assert sig.matches(tmp_path / "test.file") is False
