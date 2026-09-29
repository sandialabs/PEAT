import shutil
from pathlib import Path

from peat import config_crypto


def test_wrong_password(tmp_path, examples_dir):
    """
    Test to make sure giving decrypt an incorrect password will result in None returned
    """
    filepath = examples_dir / "encryption/example_config.yaml"
    tmp_filepath = tmp_path / "test"
    tmp_filepath.mkdir()
    shutil.copy(src=filepath.as_posix(), dst=f"{tmp_filepath.as_posix()}/example_config.yaml")
    config_crypto.encrypt_config(
        file_path=tmp_filepath / "example_config.yaml", user_password="passw"
    )
    assert (
        config_crypto.decrypt_config(
            filepath=tmp_filepath / "encrypted_example_config.yaml",
            user_password="wrongpassw",
        )
        is None
    )


def test_gen_header(examples_dir):
    file = Path(examples_dir / "encryption" / "encrypted_config.yaml")
    file_data = file.read_text(encoding="utf-8")
    assert config_crypto.check_header(file_data)


def test_round_trip(tmp_path, examples_dir):
    """
    Test that a config encrypted with the current format decrypts back to its original contents
    """
    original = (examples_dir / "encryption/example_config.yaml").read_text(encoding="utf-8")
    shutil.copy(
        src=(examples_dir / "encryption/example_config.yaml").as_posix(),
        dst=(tmp_path / "example_config.yaml").as_posix(),
    )
    config_crypto.encrypt_config(file_path=tmp_path / "example_config.yaml", user_password="passw")
    assert (
        config_crypto.decrypt_config(
            filepath=tmp_path / "encrypted_example_config.yaml", user_password="passw"
        )
        == original
    )


def test_salt_differs_per_file(tmp_path, examples_dir):
    """
    Test that encrypting the same config twice with the same password produces different salts
    """
    source = examples_dir / "encryption/example_config.yaml"
    ciphertexts = []
    for name in ("first", "second"):
        run_dir = tmp_path / name
        run_dir.mkdir()
        shutil.copy(src=source.as_posix(), dst=(run_dir / "example_config.yaml").as_posix())
        config_crypto.encrypt_config(
            file_path=run_dir / "example_config.yaml", user_password="passw"
        )
        ciphertexts.append((run_dir / "encrypted_example_config.yaml").read_text(encoding="utf-8"))

    header = len(config_crypto._salted_header)
    salts = [text[header : header + config_crypto._salt_size * 2] for text in ciphertexts]
    assert salts[0] != salts[1]


def test_legacy_config_decrypts(tmp_path):
    """
    Test that a config written before per-file salts were added still decrypts
    """
    legacy_key = config_crypto.generate_key(b"passw", config_crypto._legacy_salt)
    legacy_file = tmp_path / "encrypted_legacy.yaml"
    legacy_file.write_bytes(
        config_crypto._encrypted_header.encode() + legacy_key.encrypt(b"device: example\n")
    )

    assert (
        config_crypto.decrypt_config(filepath=legacy_file, user_password="passw")
        == "device: example\n"
    )
