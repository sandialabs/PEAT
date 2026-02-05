from pathlib import Path

import yaml

from peat import config_crypto, log


def encrypt(config_path: str, user_password: str | None = None) -> bool:
    """
    PEAT CLI functionality to encrypt a file

    Args:
        config_path: The absolute file path to the config file to be encrypted
        user_password: (Optional) password for encryption specified by CLI, defaults to None.
            If none is given by CLI command, user will be asked to input one
    """
    fp = Path(config_path)
    result = config_crypto.encrypt_config(fp, user_password)
    if result:
        return True
    else:
        log.error(f"Failed to save config to {config_path}")
        return False


def decrypt(
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
