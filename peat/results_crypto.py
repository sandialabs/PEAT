"""
Functionality for encrypting/decrypting the results directory
"""

import getpass
import os
from pathlib import Path

import pyzipper

from peat import log


def zip_encrypt_results(
    results_dir_path: Path, write_path: Path = Path("./"), user_password: str | None = None
) -> bool:
    """
    zip and encrypted the target 'peat_results' directory

    Args:
        results_dir_path:    target peat results directory
        write_path:          where to write archive
        user_password:       password to encrypt the zip

    Returns:
        bool
    """

    if not results_dir_path.is_dir():
        log.error(f"directory path {results_dir_path} does not exist")
        return False

    results_dir_path = results_dir_path.resolve()
    write_path = write_path.resolve()

    zip_name = write_path / f"encrypted_{results_dir_path.name}.zip"

    try:
        # pyzipper needs a password
        if user_password is None:
            user_password = getpass.getpass(
                "WARNING: PEAT will not save the encrypted archive's password for you,"
                "it is up to you to remember it\n"
                "Please provide a password for the archive: "
            )

        log.info("Zippping and Encrypting Results...")
        with pyzipper.AESZipFile(
            zip_name,
            "w",
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as zf:
            zf.setpassword(user_password.encode("utf-8"))

            for dirpath, _, filenames in os.walk(results_dir_path):
                dirpath = Path(dirpath)
                for filename in filenames:
                    full_path = dirpath / filename
                    arcname = full_path.relative_to(results_dir_path)
                    zf.write(full_path, arcname=str(arcname))
        log.info(f"encrypted results written: {zip_name}")
        return True

    except Exception as e:
        log.error(f"Issue zipping and encrypting results: {e}")
        return False


def unzip_decrypt_results(
    encrypted_dir_path: Path, write_path: Path = Path("./"), user_password: str | None = None
) -> bool:
    """
    Decrypt target archive with provided password and write to target path

    Args:
        encrypted_dir_path:  target encrypted archive
        write_path:          where to write extracted dir
        user_password:       password to decrypt the zip

    Returns:
        bool
    """

    if not pyzipper.is_zipfile(encrypted_dir_path):
        log.error(f"archive path {encrypted_dir_path} does not exist")
        return False

    write_path = write_path.resolve()
    encrypted_dir_path = encrypted_dir_path.resolve()

    extract_dir = write_path / encrypted_dir_path.stem.replace("encrypted_", "", 1)

    try:
        if user_password is None:
            user_password = getpass.getpass("Please provide a password for the archive: ")

        log.info("Unzipping and Decrypting Results...")
        with pyzipper.AESZipFile(encrypted_dir_path, "r") as zf:
            zf.setpassword(user_password.encode("utf-8"))
            zf.extractall(path=extract_dir)

        log.info(f"decrypted results written: {write_path}")
        return True

    except Exception as e:
        log.error(f"Issue unzipping and decrypting results: {e}")
        return False
