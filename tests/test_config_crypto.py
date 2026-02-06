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
