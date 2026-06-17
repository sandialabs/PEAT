import zipfile
from unittest.mock import MagicMock

import pytest

from peat import results_crypto


def test_mock_peat_results_exists(mock_peat_results):
    assert mock_peat_results.is_dir()


def test_zip_encrypt_missing_dir(tmp_path):
    missing_dir = tmp_path / "does_not_exist"

    result = results_crypto.zip_encrypt_results(missing_dir)
    assert result is False


def test_zip_encrypt_wrong_target(tmp_path):
    wrong_file = tmp_path / "wrong.txt"
    wrong_file.write_text("hello there")

    result = results_crypto.zip_encrypt_results(wrong_file)
    assert result is False


def test_zip_encrypt_success(monkeypatch, mock_peat_results, tmp_path):
    mock_zip_class = MagicMock()
    # need to return the mock zip in context manager to check for password
    mock_zip = mock_zip_class.return_value.__enter__.return_value

    # patch the pyzipper AESZipFile function and return a mock zip class
    monkeypatch.setattr(results_crypto.pyzipper, "AESZipFile", mock_zip_class)

    # patch the os walk to return our mock files
    monkeypatch.setattr(
        results_crypto.os,
        "walk",
        lambda _path: [(mock_peat_results, [], ["file1.txt", "file2.txt"])],
    )

    result = results_crypto.zip_encrypt_results(mock_peat_results, tmp_path, "secret")
    assert result is True
    mock_zip.setpassword.assert_called_once_with(b"secret")
    assert mock_zip.write.call_count == 2


def test_zip_encrypt_pwd_prompt(monkeypatch, mock_peat_results, tmp_path):
    mock_zip_class = MagicMock()
    # need to return the mock zip in context manager to check for password
    mock_zip = mock_zip_class.return_value.__enter__.return_value

    # patch the pyzipper AESZipFile function and return a mock zip class
    monkeypatch.setattr(results_crypto.pyzipper, "AESZipFile", mock_zip_class)

    # patch the os walk to return our mock files
    monkeypatch.setattr(results_crypto.os, "walk", lambda _path: [])
    # patch getpass to simulate a prompt
    monkeypatch.setattr(results_crypto.getpass, "getpass", lambda _prompt: "typed_pw")

    result = results_crypto.zip_encrypt_results(mock_peat_results, tmp_path, None)
    assert result is True
    mock_zip.setpassword.assert_called_once_with(b"typed_pw")


def test_unzip_decrypt_success(monkeypatch, tmp_path):
    encrypted_file = tmp_path / "encrypted_peat_results.zip"
    encrypted_file.write_text("fake zip content")

    mock_zip_class = MagicMock()
    # need to return the mock zip in context manager to check for password
    mock_zip = mock_zip_class.return_value.__enter__.return_value

    # patch check for zipfile
    monkeypatch.setattr(results_crypto.pyzipper, "is_zipfile", lambda _is_dir: True)
    # patch the pyzipper AESZipFile function and return a mock zip class
    monkeypatch.setattr(results_crypto.pyzipper, "AESZipFile", mock_zip_class)

    result = results_crypto.unzip_decrypt_results(
        encrypted_dir_path=encrypted_file,
        write_path=tmp_path,
        user_password="secret",
    )

    assert result is True
    mock_zip.setpassword.assert_called_once_with(b"secret")
    mock_zip.extractall.assert_called_once()


def test_unzip_decrypt_requires_pwd(monkeypatch, tmp_path):
    encrypted_file = tmp_path / "encrypted_peat_results.zip"
    encrypted_file.write_text("fake zip content")

    mock_zip_class = MagicMock()
    # need to return the mock zip in context manager to check for password
    mock_zip = mock_zip_class.return_value.__enter__.return_value

    monkeypatch.setattr(results_crypto.pyzipper, "is_zipfile", lambda _is_dir: True)
    # patch the pyzipper AESZipFile function and return a mock zip class
    monkeypatch.setattr(results_crypto.pyzipper, "AESZipFile", mock_zip_class)

    # patch getpass to simulate a prompt
    monkeypatch.setattr(results_crypto.getpass, "getpass", lambda _prompt: "typed_pw")

    result = results_crypto.unzip_decrypt_results(encrypted_file, tmp_path, None)
    assert result is True
    mock_zip.setpassword.assert_called_once_with(b"typed_pw")


def test_encrypted_zip_cannot_be_opened_wrong_pwd(mock_encrypted_peat_results, tmp_path):
    result = results_crypto.unzip_decrypt_results(
        encrypted_dir_path=mock_encrypted_peat_results,
        write_path=tmp_path,
        user_password="wrongpass",
    )

    assert result is False


def test_encrypted_zip_cannot_be_opened_with_zip(mock_encrypted_peat_results):
    with zipfile.ZipFile(mock_encrypted_peat_results, "r") as zf:
        # archive is readable, but file contents are encrypted
        assert set(zf.namelist()) == {"file1.txt", "file2.txt"}

        with pytest.raises(RuntimeError, match="encrypted, password required for extraction"):
            zf.read("file1.txt")
