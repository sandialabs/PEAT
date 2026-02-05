"""
Functionality for encrypting/decrypting config files
"""

import base64
import getpass
import os
from pathlib import Path

import yaml
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from peat import log, utils

# create header for encrypted PEAT config (this is a hex value of 504541545f4352595054)
_encrypted_header = b"PEAT_CRYPT".hex()
# salt used for file crypto
salt = b"9001"


def encrypt_config(file_path: Path, user_password: str) -> bool:
    """
    Encrypt a config file at a given location

    Args:
        file_path: the path to the config file
        user_password: Password specified by CLI, if None user will
        be prompted to input a password

    Returns:
        true if successful encrypted a config and wrote to disk
    """
    if not user_password:
        user_password = getpass.getpass(prompt="Enter a password: ")

    user_password = user_password.encode()
    fernet_key = generate_key(user_password)
    encrypted_cfg = ""

    if not file_path.is_file():
        log.info(f"Error attempting to read file at {file_path}")
        return False

    cfg_data = file_path.read_text(encoding="utf-8")
    encrypted_cfg = _encrypted_header.encode() + fernet_key.encrypt(cfg_data.encode())

    return write_encrypted_file(encrypted_cfg, file_path)


def write_encrypted_file(data: str, filepath: Path) -> bool:
    """
    Write an encrypted file to disk
    By default the file will be written to /peat/examples/
    An "encrypted" tag will be added to the filename

    Args:
        data: encrypted string to be written to file
        filepath: The path to the originally encrypted file

    Returns:
        Return true if file was written successfully
    """
    if os.sep in str(filepath.resolve()):
        filename = (
            "encrypted_" + filepath.name
        )  # give the encrypted config a new new name
        new_filepath = filepath.with_name(filename)
        new_filepath = new_filepath.resolve()
        log.info(f"Saving encrypted config to {new_filepath}")
        # TODO allow for custmo output path
        return utils.write_file(data, new_filepath)
    else:
        log.error("The argument given to peat encrypt is not a valid path")
        return False


def decrypt_config(filepath: Path, user_password: str) -> str:
    """
    Decrypt a given config file and return as string in memory.
    This does not write the unencrypted file to disk

    Args:
        filepath: the path to the encrypted file
        user_password: Password specified by CLI, if None user will
        be prompted to input a password
    Return:
        String of encrypted data
    """
    if not user_password:
        user_password = getpass.getpass(prompt="Enter a password: ")

    user_password = user_password.encode()

    fernet_key = generate_key(user_password)
    encrypted_cfg = filepath.read_text(encoding="utf-8")
    if not encrypt_config:
        log.error(
            f"PEAT decrypt encountered an error attempting to read the file: {filepath}"
        )
        return None

    if not check_header(encrypted_cfg):
        log.error("Invalid header")
        return None
    # To decrypt, need to remove the header
    try:
        decrypted_msg = fernet_key.decrypt(encrypted_cfg[len(_encrypted_header) :])
    except InvalidToken:
        return None

    return decrypted_msg.decode()


def check_header(file_data: str) -> bool:
    """
    Check if the file data is a config that has been previously
    encrypted by PEAT (should contain valid header)

    Args:
        file_data: the encrypted file in memory
    Returns:
        true: encrypted file has valid PEAT header
        false: no header was found
    """
    header = file_data[: len(_encrypted_header)]
    return header.encode("utf-8") == _encrypted_header.encode("utf-8")


def convert_to_dict(decrypted_data: str) -> dict:
    try:
        return yaml.safe_load(decrypted_data)
    except yaml.YAMLError as err:
        log.error(
            f"PEAT encountered an error while parsing config file, exiting...: {err}"
        )


def generate_key(password: str) -> Fernet:
    """
    Function to generate a new fernet key

    Args:
        password: the password used to create the key, provided by user input

    Returns:
        the fernet key used to decrypt/encrypt a file
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(key)
