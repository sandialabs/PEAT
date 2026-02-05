"""
This module handles SSH connections for PEAT modules.

This module provides connection handling, command writing/reading, and all parsing and logging.
This module should be inherited by all additional modules that use SSH connections.

Authors

- Kevin Cox
"""

from copy import deepcopy
from time import sleep
from typing import Any
from pathlib import Path

import paramiko
import traceback

import peat
from peat import CommError, log


class SSH:
    """
    General SSH functionality.

    This is a wrapper around Python's :mod:`paramiko` module.

    Note:
        The SSH class attributes can be overridden by the deriving class, but isn't
        always necessary.

    Args:
        ip (str): Which IP address to use.
        port (int, optional): Which port number to use - default is 22.
        timeout (float, optional): Seconds to wait for command before timing out.
        kwargs (dict[str, any], optional): Additional kwargs for Paramiko.
        ENCODING (str, optional): Encoding to use for parsing.
        POST_WRITE_SLEEP (float, optional): How long to sleep after writing out.
        LINE_TERMINATOR (str, optional): Which line terminator to use for input commands.
        MAX_BYTES (int, optional): Max number of bytes to use when reading from device.
        READ_DELAY (float, optional): How long to sleep before reading output.

    Attributes:
        ENCODING (str, optional): Encoding to use for parsing.
        POST_WRITE_SLEEP (float, optional): How long to sleep after writing out.
        LINE_TERMINATOR (str, optional): Which line terminator to use for input commands.
        MAX_BYTES (int, optional): Max number of bytes to use when reading from device.
        READ_DELAY (float, optional): How long to sleep before reading output.

    Added features:
    - Logging messages
    - Records all commands and responses and saves to a file
    - Simpler function calls
    """

    ENCODING: str = "utf-8"
    POST_WRITE_SLEEP: float = 5.0
    READ_DELAY: float = 0.0
    LINE_TERMINATOR: str = "\n"
    MAX_BYTES: int = 60000

    def __init__(
        self,
        ip: str,
        port: int = 22,
        timeout: float = 5.0,
        username: str | None = None,
        password: str | None = None,
        kwargs: dict[str, Any] | None = None,  # Additional Paramiko input
    ) -> None:
        self.ip: str = ip
        self.port: int = port
        self.timeout: float = timeout
        self.connected: bool = False
        self.raw_output: list[bytes] = []
        self.info: dict[str, Any] = {}
        self.successful_creds: tuple[str, str] | None = None
        self.log = log.bind(
            classname=self.__class__.__name__,
            target=f"{self.ip}:{self.port}",
        )
        self.all_output: list[str] = []
        self.username: str | None = username
        self.password: str | None = password

        if kwargs is None:
            kwargs = {}

        self.kwargs = kwargs  # type: dict[str, Any]

        self._comm: paramiko.SSHClient = paramiko.SSHClient()
        self._channel: paramiko.Channel | None = None
        self.sftp_conn: paramiko.SFTPClient | None = None
        self.log.trace2(f"Initialized {repr(self)}")

    def __enter__(self) -> "SSH":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()
        if exc_type:
            self.log.debug(
                f"Unhandled exception while exiting - "
                f"{exc_type.__name__}: {exc_val}"
            )
            self.log.trace(
                f"Exception traceback\n"
                f"{''.join(traceback.format_tb(exc_tb))}"
                f"{exc_type.__name__}: {exc_val}",
                self.log,
            )

    @property
    def channel(self) -> paramiko.Channel:
        """
        SSH channel (paramiko.Channel).
        """
        if not self._channel:
            self._channel = self.comm.invoke_shell()

        return self._channel

    @channel.setter
    def channel(self, obj: paramiko.Channel) -> None:
        self._channel = obj

    @property
    def comm(self) -> paramiko.SSHClient:
        """
        Initialize SSH communication.

        Python SSH instance used for interacting with the device.

        Returns:
            paramiko.SSHClient: SSH client used for maintaining connection state.
        """
        if not self.connected:
            try:
                # TODO: this is specific to the Sage,
                # move sage-specific logic into SageSSH.
                kwargs = deepcopy(self.kwargs)
                pkey = kwargs.pop("key_filename", None)
                if not pkey:
                    pkey = kwargs.pop("pkey", None)
                if pkey is not None:
                    pkey = paramiko.RSAKey.from_private_key_file(
                        filename=pkey,
                        password=self.password,
                    )
                # Commenting out overriding paramiko ciphers.
                # Leaving as comment in case unintended results occur
                # paramiko.Transport._preferred_ciphers = ("aes256-cbc", 'ssh-rsa', 'aes256-ctr')

                # TODO: this is dangerous for MITM Attacks. Is there a way around this?
                self._comm.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                self.log.debug(f"Attempting SSH login with user '{self.username}'")
                self._comm.connect(
                    hostname=self.ip,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    pkey=pkey,
                    timeout=self.timeout,
                    **kwargs,
                )

                self.connected = True
                self.log.info(f"SSH connected to {self.ip}:{self.port}")
            except paramiko.AuthenticationException as ex:
                self._close()
                raise paramiko.AuthenticationException(
                    f"Failed to authenticate to {self.ip}:{self.port} "
                    f"with user '{self.username}': {ex}"
                ) from None
            except Exception as ex:
                self._close()
                raise CommError(
                    f"Failed to SSH connect to {self.ip}:{self.port}: {ex}"
                ) from ex

        return self._comm

    @comm.setter
    def comm(self, obj: paramiko.SSHClient) -> None:
        self._comm = obj

    def open_sftp(self) -> None:
        if self.connected:
            self.sftp_conn = self._comm.open_sftp()

    def sftp_recursive_file_walk(
        self, directory: str, _paths_done: set | None = None
    ) -> dict:
        if not self.sftp_conn:
            self.log.warning(
                "No sftp connection established in order to walk file structure"
            )
            return {}

        file_info = {directory: []}
        self.log.debug(f"Identifying files in following directory: {directory}")
        metadata = self.sftp_conn.listdir_attr(directory)

        if _paths_done is None:
            _paths_done = set()

        for meta_fl in metadata:
            fl_path = f"{directory}/{meta_fl.filename}"
            fl_permissions = meta_fl.longname.split()[0]

            if "d" in fl_permissions:
                if fl_path in _paths_done:
                    continue
                _paths_done.add(fl_path)
                sub_results = self.sftp_recursive_file_walk(fl_path, _paths_done)
                file_info.update(sub_results)
            else:
                file_info[directory].append(meta_fl)

        return file_info

    def sftp_download_files(self, local_dir: Path, files: list[dict]):
        if not self.sftp_conn:
            self.log.warning(
                "No sftp connection established in order to download files."
            )
            return False

        self.log.info(f"Downloading {len(files)} files to '{local_dir}'")

        if not local_dir.exists():
            local_dir.mkdir(parents=True, exist_ok=True)

        good = 0
        failed = 0

        for entry in files:
            save_path = Path(local_dir, entry["path"].lstrip("/"))
            Path(save_path.parent).mkdir(parents=True, exist_ok=True)

            if save_path.exists():
                self.log.debug(f"{save_path} already exists, new file: {entry}")

            try:
                self.log.debug(f"Downloading {entry['path']}")
                self.sftp_conn.get(entry["path"], save_path)
                good += 1
            except Exception as ex:
                self.log.warning(f"Failed to download '{entry['path']}': {ex}")
                failed += 1

        self.log.info(
            f"Finished downloading {len(files)} files to '{local_dir}'. "
            f"{good} downloads were successful, {failed} downloads failed."
        )

        if failed >= 1:
            return False

        return True

    def _close(self) -> None:
        self._comm.close()
        self.connected = False
        self._channel = None

    def test_connection(self) -> bool:
        """
        Test connection to the device.

        Determine if the SSH connection has been established. This is done by simply checking
        the comm variable is initialized.

        Returns:
            Whether the connection has been established or not
        """
        try:
            return self.comm and self.channel.active
        except CommError as ex:
            self.log.error(f"SSH connection test failed: {ex}")
            return False

    def disconnect(self) -> None:
        """
        Disconnect from the device.

        Cleanly disconnect from the device. This function will close the paramiko connection and
        save all read commands.
        """
        if self.connected and self._comm:
            self._close()
            self.log.info(f"SSH disconnected from {self.ip}")

            if self.all_output:
                # Save the raw output to disk as an artifact
                try:
                    dev = peat.data.datastore.get(self.ip)
                    dev.write_file(
                        self.all_output, "ssh-output.json", merge_existing=True
                    )
                except Exception as ex:
                    self.log.warning(f"Failed to write raw SSH output to file: {ex}")

    def write_read(self, command: bytes | str | int) -> str:
        """
        Send a command, then perform a read and return the response.

        Basically, ``self.write(command)`` followed by ``self.read()``.
        """
        self.write(command)
        return self.read()

    def write(
        self,
        command: bytes | str | int,
        flush: bool = False,  # noqa: ARG002
    ) -> None:
        """
        Send the given command to the SSH device.

        Send a SSH command to the device. The input command will be encoded based off of the
        ENCODING attribute.

        Args:
            command: Command to send (this will be automatically encoded)
            flush: If the responses to the command should be dropped
        """
        self.log.debug(f"Writing SSH command: {command}")

        # If it's an int, first convert to a string, which will then be encoded
        if isinstance(command, int):
            command = str(command)

        # If it's a string, encode to bytes with the device's encoding
        if isinstance(command, str):
            command = command.encode(self.ENCODING)

        # Append the line terminator (encode here to ensure proper encoding)
        command += self.LINE_TERMINATOR.encode(self.ENCODING)

        self.channel.sendall(command)
        sleep(self.POST_WRITE_SLEEP)

    def read(
        self,
        delay: float | None = None,
        strip_whitespace: bool = True,
        wait_until_ready: bool = True,
        sleep_between_recvs: bool = True,
    ) -> str:
        """
        Read all data currently in the SSH response buffer.

        This is a stateful operation, so calling this method again will
        not result in the same information. The results are saved in the
        ``all_output`` class attribute for future access.

        Args:
            delay: Seconds to sleep before querying for data
            strip_whitespace: Call ``str.strip()`` on the results
            wait_until_read: Wait until there's data before attempting read
            sleep_between_recvs: Add a sleep between multiple calls to recv

        Returns:
            Decoded data read from the SSH receive stream
        """
        if delay is None:
            delay = self.READ_DELAY

        sleep(delay)

        # Wait until there's data available
        if wait_until_ready:
            while not self.channel.recv_ready():
                sleep(0.1)

        # Pull data while there's still data to get
        output = b""
        while self.channel.recv_ready():
            output += self.channel.recv(self.MAX_BYTES)
            if sleep_between_recvs:
                sleep(0.1)

        return self._add_data(output, strip_whitespace)

    def read_until(
        self,
        until: bytes | str,
        delay: float = 0.15,
        timeout: float | None = None,
        strip_whitespace: bool = True,
    ) -> str:
        """
        Read the SSH response buffer until the specified string is reached.

        This is a stateful operation, so calling this method again will
        not result in the same information. The results are saved in the
        all_output class attribute for future access.

        Note:
            This function is largely a wrapper for read since Paramiko doesn't include
            a read_until method.

        Args:
            until: String to read all data up to.
            delay: Seconds to sleep before querying for data.
            timeout: Seconds to wait for the string before timing out
                (if None, this defaults to the class's timeout configuration).
            strip_whitespace: If ``strip()`` should be called on the results.

        Returns:
            str: Decoded data read from the SSH receive stream
        """
        if isinstance(until, str):
            until = until.encode(self.ENCODING)

        # how long to wait for the expected string to appear
        if timeout is None:
            timeout = self.timeout
        self.channel.settimeout(timeout)

        sleep(delay)

        output = bytearray()
        while True:
            try:
                part = self.channel.recv(self.MAX_BYTES)
                output += part
                if until in output:
                    break
            except TimeoutError:
                break

        return self._add_data(output, strip_whitespace)

    def _add_data(self, raw_data: bytes, strip_whitespace: bool = True) -> str:
        """
        Add the given data to the stored data.

        Decodes and saves responses from device. The input raw_data is decoded based off of the
        ENCODING attribute.

        Args:
            raw_data: Bytes to add to raw data. This is encoded and saved as well.
            strip_whitespace: Whether to strip whitespace or not.
        """
        self.raw_output.append(raw_data)
        data = raw_data.decode(self.ENCODING)

        self.all_output.append(data)
        if strip_whitespace:
            data = data.strip()

        return data

    def login(self, user: str, passwd: str) -> dict | None:
        """
        Login to the device via ssh.

        Login to the ssh device. This function is deferred to the deriving class.

        Args:
            user: Username to login to device
            passwd: Password to login to device

        Returns:
            Connection dict containing successful user and passwd
        """
        pass

    def __str__(self) -> str:
        return self.ip

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.ip}, {self.port}, {self.timeout})"


__all__ = ["SSH"]
