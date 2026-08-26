from pathlib import Path

import yaml

from peat import config_crypto, log, results_crypto


def encrypt_config_api(config_path: str, user_password: str | None = None) -> bool:
    """
    PEAT CLI functionality to encrypt a file

    Args:
        config_path: The absolute file path to the config file to be encrypted
        user_password: (Optional) password for encryption specified by CLI, defaults to None.
            If none is given by CLI command, user will be asked to input one
    """
    if config_path is None:
        log.error("No config specified")
        return False

    fp = Path(config_path)
    result = config_crypto.encrypt_config(fp, user_password)
    if result:
        return True
    else:
        log.error(f"Failed to save config to {config_path}")
        return False


def decrypt_config_api(
    config_path: str,
    output_path: str | None = None,
    new_filename: str | None = "decrypted_config.yaml",
    user_password: str | None = None,
) -> bool:
    """
    PEAT CLI functionality to decrypt a file

    Args:
        config_path: The absolute file path to the config file to be decrypted
        output_path: (Optional) The absolute file path the decrypted config file should be
            saved to. If not specified, the new encrypted config will be saved to the current
            working directory
        new_filename: (Optional) Give the output file a specified name other than the default
        user_password: (Optional) password for encryption specified by CLI, defaults to None.
            If none is given by CLI command, user will be asked to input one
    """
    if config_path is None:
        log.error("No config specified")
        return False

    fp = Path(config_path)
    decrypted_str = config_crypto.decrypt_config(fp, user_password=user_password)
    if not decrypted_str:
        log.error(f"PEAT was unable to decrypt the given config file: {fp}")
        return False
    # save the decrypted data to a file
    if output_path:
        if not Path(output_path).exists():
            log.error("The output filepath given does not exist, unable to save file")
            return False
        new_file_location = Path(output_path) / Path(new_filename)
        with open(new_file_location, "w") as file:
            yaml_data = yaml.safe_load(decrypted_str)
            yaml.dump(yaml_data, file, default_flow_style=False, sort_keys=False)
            log.info(f"Encrypted config saved to {new_file_location}")
            return True
    else:
        with open(new_filename, "w") as file:
            yaml_data = yaml.safe_load(decrypted_str)
            yaml.dump(yaml_data, file, default_flow_style=False, sort_keys=False)
            log.info(f"Encrypted config saved to current directory as {new_filename}")
            return True


def encrypt_results_api(
    results_dir_path: str, write_path: str | None = None, user_password: str | None = None
) -> bool:
    """
    API for CLI -> Encrypt results function

    Args:
        results_dir_path:  PEAT results directory
        write_path:        Path to write encrypted archive
        user_password:     password to encrypt archive with
    Returns:
        bool
    """
    if results_dir_path is None:
        log.error("No directory specified")
        return False

    results_dir_path = Path(results_dir_path)

    if write_path is None:
        write_path = Path("./")
    else:
        write_path = Path(write_path)

    return results_crypto.zip_encrypt_results(results_dir_path, write_path, user_password)


def decrypt_results_api(
    encrypted_dir_path: str, write_path: str | None = None, user_password: str | None = None
) -> bool:
    """
    API for CLI -> Decrypt archive function

    Args:
        encrypted_dir_path:  Encrypted zip archive path
        write_path:          Path to write extracted PEAT results
        user_password:       password to decrypt archive with
    Returns:
        bool
    """
    if encrypted_dir_path is None:
        log.error("No archive specified")
        return False

    encrypted_dir_path = Path(encrypted_dir_path)

    if write_path is None:
        write_path = Path("./")
    else:
        write_path = Path(write_path)

    return results_crypto.unzip_decrypt_results(encrypted_dir_path, write_path, user_password)
