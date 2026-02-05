import ftplib
import re
import traceback
from io import BufferedReader, BytesIO, TextIOWrapper
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Optional

import peat  # Avoid circular imports
from peat import CommError, config, utils, log


class FTP:
    """
    Generic wrapper for File Transfer Protocol (FTP) functionality.
    """

    def __init__(self, ip: str, port: int = 21, timeout: float = 5.0) -> None:
        self.ip: str = ip
        self.port: int = port
        self.timeout: float = timeout

        self.log = log.bind(
            classname=self.__class__.__name__,
            target=f"{self.ip}:{self.port}",
        )
        self.all_output: list[tuple | str] = []
        self._ftp: ftplib.FTP | None = None

        self.log.trace2(f"Initialized {repr(self)}")

    @property
    def ftp(self) -> ftplib.FTP:
        """
        :class:`ftplib.FTP` instance used for interacting with the server.
        """
        if not self._ftp:
            try:
                # Since "connect" shouldn't be reused on instances,
                # we create a new instance for every new connection.
                self.log.debug(
                    f"Attempting connection to {self.ip}:"
                    f"{self.port} (timeout: {self.timeout})"
                )
                self._ftp = ftplib.FTP()
                self._ftp.connect(self.ip, self.port, self.timeout)
            except Exception as ex:
                self._ftp = None
                raise CommError(f"({self.ip}:{self.port}) {ex}") from ex

            # TODO: figure out a way to log FTP protocol debugging messages
            #  to a file (like we're doing for peat.protocols.Telnet)
            if config.DEBUG == 2:
                # Moderate amount of output, generally a single line per request
                # NOTE: this output goes directly to stdout!
                self._ftp.set_debuglevel(1)
            elif config.DEBUG >= 3:
                # Maximum output, each line sent/received on the control connection
                self._ftp.set_debuglevel(2)

            self.log.info(f"Connected to {self.ip}:{self.port}")

        return self._ftp

    def __enter__(self) -> "FTP":
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
                f"{exc_type.__name__}: {exc_val}"
            )

    def __str__(self) -> str:
        return self.ip

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.ip}, {self.port}, {self.timeout})"

    @ftp.setter
    def ftp(self, obj: ftplib.FTP) -> None:
        self._ftp = obj

    @property
    def address(self) -> str:
        """
        Alias for ``ip`` to make code cleaner for some PEAT modules.
        """
        return self.ip

    def disconnect(self) -> None:
        """
        Attempt to cleanly disconnect from the device.
        """
        if self._ftp is not None:
            try:
                # Try to do it cleanly
                self._ftp.quit()
            except Exception as exquit:
                self.log.trace2(f"Unclean quit(): {exquit}")
                try:
                    # If that can't be done, close it normally
                    self._ftp.close()
                except Exception as exclose:
                    self.log.trace2(f"Unclean close(): {exclose}")

            self._ftp = None
            self.log.debug(f"Disconnected from {self.ip}:{self.port}")

            if self.all_output:
                # Save the raw output to disk as an artifact
                try:
                    dev = peat.data.datastore.get(self.ip)
                    dev.write_file(
                        self.all_output, "raw-ftp-output.json", merge_existing=True
                    )
                except Exception as ex:
                    self.log.warning(f"Failed to write raw output to file: {ex}")

    def login(self, user: str = "", passwd: str = "") -> bool:
        """
        Login to the FTP server.

        .. note::
           This function should be called only once for each instance,
           per the documentation for :mod:`ftplib`.

        Args:
            user: Username to login with (default: ``anonymous``)
            passwd: Password to login with (default: ``anonymous@``)

        Returns:
            If the login was successful
        """
        self.log.debug(f"Attempting login as user '{user}'")

        try:
            self.ftp.login(user, passwd)
        except ftplib.all_errors as ex:
            err_str = str(ex)
            if "530" in err_str:
                err_str = "access was denied or server does not allow anonymous login"
            self.log.debug(f"Login failed as user '{user}': {err_str}")
            return False

        self.log.info(f"Successfully logged in as user '{user}'")
        return True

    def download_binary(
        self, filename: str, save_path: Path | None = None, save_to_file: bool = True
    ) -> bytes:
        """
        Download a binary file from the FTP server.

        Args:
            filename: Name or path of the file to download.
                This path must be valid on the server.
                Relative paths generally work best.
            save_path: Path on the local system to save the file to.
                If not specified then it's saved to the device's standard
                output directory and filename.
            save_to_file: If the data should be automatically written to a file
                as defined by ``save_path``

        Returns:
            The binary file data as :class:`bytes`
        """
        file_obj = BytesIO()
        cmd = f"RETR {filename}"
        self.log.trace2(f"download_binary command string: '{cmd}'")

        # TODO: workaround for odd behavior seen in some SEL relays
        # from _ssl import _SSLSocket
        # def retrbinary(obj: ftplib.FTP, command, callback, blocksize=8192, rest=None):
        #     obj.voidcmd('TYPE I')
        #     resp = obj.voidresp()
        #     with obj.transfercmd(command, rest) as conn:
        #         while 1:
        #             data = conn.recv(blocksize)
        #             if not data:
        #                 break
        #             callback(data)
        #         # shutdown ssl layer
        #         if _SSLSocket is not None and isinstance(conn, _SSLSocket):
        #             conn.unwrap()
        #     return resp
        # _old_retr = self.ftp.retrbinary
        # self.ftp.retrbinary = retrbinary
        # self.ftp.retrbinary(self.ftp, cmd, file_obj.write)
        # self.ftp.retrbinary = _old_retr

        self.ftp.retrbinary(cmd, file_obj.write)

        data = file_obj.getvalue()

        if not data:
            self.log.warning(
                f"No data for binary file '{filename}' on "
                f"{self.ip} (command: {cmd})"
            )
        elif not isinstance(data, bytes):
            self.log.error(
                f"download_binary: data has type "
                f"'{data.__class__.__name__}', not 'bytes'"
            )
        # Save the raw file to disk as an artifact
        elif data and save_to_file:
            if save_path:
                utils.write_file(data, save_path)
            else:
                dev = peat.data.datastore.get(self.ip)

                if filename.startswith("/"):
                    filename = filename[1:]  # Prevent files being saved in "/"

                dev.write_file(
                    data=data, filename=filename, out_dir=dev.get_sub_dir("ftp_files")
                )
                dev.related.files.add(filename)

        return data

    def download_text(
        self, filename: str, save_path: Path | None = None, save_to_file: bool = True
    ) -> str:
        """
        Download a text file from the FTP server.

        Args:
            filename: Name or path of the file to download.
                This path must be valid on the server.
                Relative paths generally work best.
            save_path: Path on the local system to save the file to.
                If not specified then it's saved to the device's standard
                output directory and filename.
            save_to_file: If the data should be automatically written to a file
                as defined by ``save_path``

        Returns:
            Text file data as a :class:`str`
        """
        text = ""
        lines = []
        cmd = f"RETR {filename}"
        self.log.trace2(f"download_text command string: '{cmd}'")

        self.ftp.retrlines(cmd, lines.append)

        if lines:
            text = "\n".join(lines)
            if save_to_file:
                # Save the raw file to disk as an artifact
                if save_path:
                    utils.write_file(text, save_path)
                else:
                    dev = peat.data.datastore.get(self.ip)

                    if filename.startswith("/"):
                        filename = filename[1:]  # Prevent files being saved in "/"

                    dev.write_file(
                        data=text,
                        filename=filename,
                        out_dir=dev.get_sub_dir("ftp_files"),
                    )
                    dev.related.files.add(filename)
        else:
            self.log.warning(
                f"No data for text file '{filename}' on {self.ip} (command: {cmd})"
            )

        return text

    def find_file(
        self, check_for: str, ext: str, directory: str | None = None
    ) -> str | None:
        for filename in self.nlst_files(directory):
            if check_for in filename and filename.endswith(ext):
                return filename
        self.log.debug(
            f"Could not find file {check_for} ending with {ext} "
            f"in the output of the 'NLST' command"
        )
        return None

    def upload_text(
        self, filename: str, content: str | bytes | TextIOWrapper | BinaryIO
    ) -> None:
        # We make a new variable to avoid over-writing the argument reference
        if isinstance(content, str):
            file_obj = BytesIO(content.encode("utf-8"))  # str to bytes
        elif isinstance(content, bytes):
            file_obj = BytesIO(content)
        else:
            file_obj = content

        self.ftp.storlines(f"STOR {filename}", file_obj)

    def upload_binary(
        self, filename: str, content: bytes | BufferedReader
    ) -> None:
        # We make a new variable to avoid over-writing the argument reference
        if isinstance(content, bytes):
            file_obj = BytesIO(content)
        else:
            file_obj = content

        self.ftp.storbinary(f"STOR {filename}", file_obj)

    def cmd(self, command: str) -> str | None:
        """Execute a raw FTP command."""
        if isinstance(command, bytes):
            command = command.decode("utf-8")

        try:
            resp = self.ftp.sendcmd(command)
            self.all_output.append((command, resp))
            return resp
        except ftplib.all_errors as ex:
            self.log.debug(f"Command '{command}' failed: {ex}")
            return None

    def cd(self, directory: str) -> bool:
        """Change directory on the server (``cwd``)."""
        self.log.debug(f"Changing directory to '{directory}'")
        return True if self._do("cwd", directory) is not None else False

    def cwd(self, directory: str) -> bool:
        return self.cd(directory)

    def pwd(self) -> str | None:
        """Get the current working directory on the server."""
        return self._do("pwd")

    def mkdir(self, directory: str) -> bool:
        """Create a directory on the server."""
        return True if self._do("mkd", directory) is not None else False

    def rmdir(self, directory: str) -> bool:
        """Remove a directory on the server."""
        return True if self._do("rmd", directory) is not None else False

    def file_size(self, filename: str) -> int | None:
        """Get the size of a file on the server."""
        return self._do("size", filename)

    def file_delete(self, filename: str) -> int | None:
        """Remove a file from the server."""
        return self._do("delete", filename)

    def file_rename(self, filename: str, new_name: str) -> int | None:
        """Rename a file on the server."""
        return self._do("rename", filename, new_name)

    def dir(
        self, directory: str | None = None
    ) -> tuple[list[str], list[dict]] | None:
        """
        List files on the FTP server, including file metadata (``dir`` command).

        This returns two objects:

        - List of filenames
        - List of dicts with detailed information about each file,
            including type of file, modification time, and size.

        Returns:
            :class:`tuple` with list of filenames and list of dicts with
            file metadata, or :obj:`None` if the command failed.
        """
        file_names = []
        file_metadata = []

        # Approximate header structure:
        #   TYPE PERMS ? USER GROUP SIZE DATE-MODIFIED FILENAME
        #
        # Examples:
        # '-rwxrwxrwx   1 0      0          437824 JAN 21  2011 FILE.SYS'
        # '----------   0 0      0               0 JAN 01  1970 null'
        # 'drwxrwxrwx   5 0      0            8192 JAN 01  1970 OS'

        def _append_func(line: str) -> None:
            """
            Python's ftplib takes a function when calling LIST,
            and will call the function with the result of
            each line of data returned from LIST.
            """
            self.all_output.append(line)

            parts = [x.strip() for x in line.strip().split(" ") if x.strip()]
            name = " ".join(parts[8:])

            # skip "." and ".." since they're not files
            if name in [".", ".."]:
                return

            file_names.append(name)

            if directory:
                path = str(PurePosixPath(directory, name))
                parent = directory
                if not parent.endswith("/"):
                    parent += "/"
            else:  # Relative to current directory (directory arg is None)
                path = str(PurePosixPath(name))
                # NOTE: it's impossible to know parent without running
                # "pwd" if directory is None (a relative dir command).
                parent = ""

            metadata = {
                "type": "dir" if parts[0][0] == "d" else "file",
                "permissions": parts[0][1:],
                "size": int(parts[4]),
                "modified": utils.parse_date(" ".join(parts[5:8])),
                "name": name,
                "path": path,
                "parent": parent,
            }
            file_metadata.append(metadata)

        try:
            if directory is None:
                self.ftp.dir(_append_func)
            else:
                self.ftp.dir(directory, _append_func)
        except ftplib.all_errors as ex:
            self.log.warning(f"'dir' failed for {directory}: {ex}")
            return None

        return file_names, file_metadata

    def rdir(
        self,
        directory: str | None = None,
        _paths_done: set | None = None,
    ) -> tuple[list[str], list[dict]] | None:
        """
        Recursively lists files on the server and parses metadata
        about those files (the ``dir`` command).

        This calls recursively calls :func:`~peat.protocols.FTP.dir`
        on any directories, and returns the consolidated output of
        the calls. Refer to that method's docstring for further
        details about the returned data.

        Returns:
            Tuple with list of filenames and list of dicts with file metadata,
            or :obj:`None` if the command failed.
        """
        dir_result = self.dir(directory)
        if not dir_result:
            return None

        # this is all filenames and directories, without path
        filenames = dir_result[0]
        metadata = dir_result[1]

        if _paths_done is None:
            _paths_done = set()

        for file_dict in metadata:
            if file_dict["type"] == "dir":
                # Don't do the same directory twice
                if file_dict["path"] in _paths_done:
                    continue
                _paths_done.add(file_dict["path"])

                sub_result = self.rdir(file_dict["path"], _paths_done)

                if not sub_result:
                    continue

                # Sanity checks for duplicates
                for filename in sub_result[0]:
                    if filename not in filenames:
                        filenames.append(filename)

                # The _paths_done checks should prevent this from ever happening,
                # but better to be safe than sorry like in the past...
                for meta in sub_result[1]:
                    if meta not in metadata:
                        metadata.append(meta)
                    else:
                        self.log.warning(f"Duplicate metadata: {meta}")

        return filenames, metadata

    def download_files(self, local_dir: Path, files: list[dict]):
        """
        Download files from a device to a directory on the local system.

        The file structure of the local files will match that on the device, if possible.

        .. warning::
           On Windows, there are restrictions on characters allowed in paths,
           so the paths may vary on that platform.

        Args:
            local_dir: Path to local directory to save downloaded files to.
            files: Listing of files to download, as returned from
                :func:`~peat.protocols.FTP.dir` or :func:`~peat.protocols.FTP.rdir`.
        """
        to_download = [f for f in files if f["type"] == "file"]

        self.log.info(f"Downloading {len(to_download)} files to '{local_dir}'")

        if not local_dir.exists():
            local_dir.mkdir(parents=True, exist_ok=True)

        good = 0
        failed = 0

        for entry in to_download:
            save_path = Path(local_dir, entry["path"].lstrip("/"))
            if save_path.exists():
                self.log.warning(f"{save_path} already exists, new file: {entry}")
            try:
                self.log.debug(f"Downloading {entry['path']}")
                self.download_binary(entry["path"], save_path)
                good += 1
            except Exception as ex:
                self.log.warning(f"Failed to download '{entry['path']}': {ex}")
                failed += 1

        self.log.info(
            f"Finished downloading {len(to_download)} files to '{local_dir}'. "
            f"{good} downloads were successful, {failed} downloads failed."
        )

    def nlst(self, directory: str | None = None) -> list[str] | None:
        """``nlst`` command to list files on the server."""
        if directory is None:
            return self._do("nlst")
        else:
            return self._do("nlst", directory)

    def nlst_files(self, directory: str | None = None) -> list[str]:
        """
        List files in a directory on the device using NLST.

        This is a wrapper around :func:`~peat.protocols.FTP.nlst`.

        Args:
            directory: Case-insensitive name of directory to list the contents of.
                If :obj:`None` or empty string, the current directory is listed.

        Returns:
            List of names of files in the directory.
        """
        files = self.nlst(directory)
        if files is None:
            return []
        return files

    def list_command(self, directory: str) -> list[str]:
        """
        Get list of files with file type, permission, and timestamp information.

        This uses the LIST FTP command directly, instead of ``nlst`` or ``dir``.

        Args:
            directory: Case-insensitive name of directory to list the contents of.

        Returns:
            List of names of files in the directory,
            or empty list if the command failed.
        """
        listings = []
        self._do("retrlines", f"LIST {directory}", listings.append)
        return listings

    def getwelcome(self) -> str | None:
        """Return the welcome message sent by the server."""
        return self._do("getwelcome")

    def process_vxworks_ftp_welcome(
        self, welcome: str, dev: Optional["peat.data.models.DeviceData"] = None
    ) -> str | None:
        """
        Extract the VxWorks version from the FTP welcome message.

        Args:
            welcome: FTP welcome message string to parse
            dev: DeviceData object to annotate with extracted information
                If :obj:`None`, no information will be annotated, the
                version will be returned and nothing else will happen.

        Returns:
            The version number as a string, or :obj:`None`
            if the parse failed.
        """
        if dev:
            dev.extra["ftp_welcome"] = welcome

        lower_welcome = welcome.strip().lower()
        if "vxworks" in lower_welcome:
            result = re.search(r"\(vxworks\s+(?:vxworks|)([\d\.]+)\)", lower_welcome)
        elif "wind river" in lower_welcome:
            result = re.search(r"wind river ftp server ([\d\.]+)\s+", lower_welcome)
        else:
            self.log.warning(f"Unknown format for FTP welcome '{welcome}'")
            return None

        if result:
            version = result.groups()[0]
            if dev:
                if not dev.os.version:
                    dev.os.version = version
                else:
                    dev.extra["vxworks_version_from_ftp"] = version

                if not dev.os.name:
                    dev.os.name = "VxWorks"

                if not dev.os.vendor.name:
                    dev.os.vendor.name = "Wind River Systems"

                if not dev.os.vendor.id:
                    dev.os.vendor.id = "WindRiver"
            return version
        else:
            self.log.warning(f"Failed to parse FTP welcome '{welcome}' from {dev.ip}")
            return None

    def _do(self, func: str, *args) -> list | str | None:
        try:
            resp = getattr(self.ftp, func)(*args)
            self.all_output.append((func, resp))
            return resp
        except ftplib.all_errors as ex:
            self.log.debug(f"Action '{func}' failed: {ex}")
            return None


__all__ = ["FTP"]
