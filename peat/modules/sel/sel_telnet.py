from time import sleep

from peat import datastore
from peat.protocols import Telnet

from .sel_ascii import SELAscii


class SELTelnet(SELAscii):
    """
    Telnet wrapper for SEL relays.

    This is a transport implementation of :class:`~peat.modules.sel.sel_ascii.SELAscii`.
    Refer to :class:`~peat.modules.sel.sel_ascii.SELAscii` for functions/commands to run.

    .. code-block:: python
       :caption: Example usage of SELTelnet with a SEL 451 on the PEAT testing rack

       >>> from peat.modules.sel.sel_telnet import SELTelnet
       >>> tn = SELTelnet('192.0.2.123')  # doctest: +SKIP
       >>> tn.elevate(1)  # doctest: +SKIP
       True
       >>> tn.list_files()  # doctest: +SKIP
       ['CFG.TXT', 'CFG.XML', 'EVENTS', 'REPORTS', 'SETTINGS', 'SWCFG.ZIP', 'SYNCHROPHASORS']
       >>> tn.disconnect()  # doctest: +SKIP

    """

    def __init__(self, ip: str, port: int = 23, timeout: float = 5.0) -> None:
        super().__init__(ip, timeout)  # Initialize SELAscii

        self.ip: str = ip  # hack to allow agnostic use between SELTelnet and FTP
        self.port: int = port
        self.telnet_download_capable: bool | None = None
        self._comm: Telnet | None = None

        self.log.trace(f"Initialized {repr(self)}")

    @property
    def comm(self) -> Telnet:
        if not self._comm:
            self._comm = Telnet(self.address, self.port, self.timeout)
            # TODO: hack to copy attributes since Telnet isn't a superclass
            self._comm.ENCODING = self.ENCODING
            self._comm.PRE_WRITE_SLEEP = self.PRE_WRITE_SLEEP
            self._comm.POST_WRITE_SLEEP = self.POST_WRITE_SLEEP
            self._comm.READ_DELAY = self.READ_DELAY
        return self._comm

    @comm.setter
    def comm(self, obj: Telnet) -> None:
        self._comm = obj

    def test_connection(self) -> bool:
        return self.comm.test_connection()

    def disconnect(self) -> None:
        if self._comm and self._comm.connected:
            try:
                if self.priv_level == 0:
                    # Attempt to capture useful output from "quit"
                    # while at level 0, such as RID, TID, and time.
                    self.write("quit")
                    self.write("exit")
                else:
                    self.write("exit")
            except Exception:
                pass

            # Ensure anything left in Telnet buffer gets saved to all_output
            try:
                self.read()
            # Ignore errors from telnetlib about connection being closed
            except Exception:
                pass

            self.priv_level = 0
            self._comm.disconnect()
            self._comm = None

    def read(self, delay: float | None = None, strip_whitespace: bool = True) -> str:
        data = self.comm.read(delay, strip_whitespace=False)

        self.all_output.append(data)

        if getattr(self.comm, "raw_output", None):
            self.raw_output.append(self.comm.raw_output[-1])

        if strip_whitespace:
            data = data.strip()

        return data

    def read_until(
        self,
        until: bytes | str,
        strip_whitespace: bool = True,
    ) -> str:
        data = self.comm.read_until(until)

        self.all_output.append(data)

        if getattr(self.comm, "raw_output", None):
            self.raw_output.append(self.comm.raw_output[-1])

        if strip_whitespace:
            data = data.strip()

        return data

    def can_download_files(self) -> bool:
        """
        If file downloads are possible via Telnet.
        """
        if self.telnet_download_capable is not None:
            return self.telnet_download_capable

        self.log.info(f"Testing if {self.address} can download files via Telnet")
        self._ensure_priv("can_download_files", level=1)

        self.read()  # Flush any output from previous operations

        self.write("fil show")

        sleep(self.READ_DELAY)
        result = self.read()

        if not result:
            self.log.error(
                f"No response from {self.address} for command 'fil show'. "
                f"Marking as unable to download files."
            )
            self.telnet_download_capable = False
        elif "command requires" not in result.lower():
            self.log.error(
                f"{self.address} does not support the 'file show' command. "
                f"It is likely an older model such as a 451 or 2032 "
                f"using an older version of SEL's ASCII protocol."
            )
            self.telnet_download_capable = False
        else:
            self.telnet_download_capable = True

        return self.telnet_download_capable

    def download_binary(self, filename: str, save_to_file: bool = True) -> str | None:
        """
        Download a file from the device.

        .. warning::
           File downloads require level 1 (``acc``) permissions on all devices
           we've seen. Ensure you have elevated the login level with
           :meth:`~peat.modules.sel.sel_telnet.SELTelnet.elevate`
           before calling this method!

        .. note::
           Older devices, notably the 451 and 2032 on the PEAT rack, don't
           support the ``file show`` command and therefore CANNOT download
           files via Telnet.

        .. note::
           The name ``download_binary`` is used for compatibility with
           code that calls the same method on instances of
           :class:`~peat.protocols.ftp.FTP`. The interfaces
           are functionally identical.

        Args:
            filename: *Case-insensitive* name of the file to download or the
                directory and file pair, separated by a space.
            save_to_file: If the data should be automatically written to a file
                in the output directory for the device matching ``self.address``.

        Returns:
            The contents of the file, or :obj:`None` if there was an error

        Raises:
            DeviceError: Automatic privilege elevation failed
        """
        # TODO: figure out if it's possible to download files via telnet
        #   on devices that don't support "show". I tried using a Ymodem
        #   library with the Telnet socket and object to pull after executing
        #   a 'fil read' command but no dice. I suspect 'fil read' executes
        #   a file transfer over a modem line or some other interface and
        #   not the telnet connection itself.
        if not self.can_download_files():
            return None

        self.log.info(f"Reading file '{filename}' from {self.address}")
        self._ensure_priv("download_binary", level=1)
        self.read()  # Flush any output from previous operations

        # "show" supported: 700G, 351S, 351,
        # "read": 451, 2032 (Requires Ymodem to transfer the file?)
        self.write(f"fil show {filename}")
        sleep(self.READ_DELAY)  # Give tn time to load file

        raw_file = ""

        # ensure command and 0x02 character doesn't appear in chunk
        first_parts = self.read(strip_whitespace=False).splitlines()
        if not first_parts:
            self.log.error(f"No data for file {filename} from {self.address}")
            return None

        index = 0
        while "fil show" in first_parts[index] or (
            "=>" in first_parts[index] and index < len(first_parts)
        ):
            index += 1

        chunk = "\r\n".join(first_parts[index:])
        raw_file += chunk
        while chunk and "\x03" not in chunk:
            chunk = self.read(strip_whitespace=False)
            raw_file += chunk

        # 0x02: START OF TEXT
        # 0x03: END OF TEXT
        match = self.DATA_REGEX.search(raw_file)
        if not match:
            self.log.error(
                f"Failed to match the data section read of file "
                f"'{filename}' from {self.address} via Telnet. It may"
                f"be a text file or something we haven't seen yet. "
                f"Returning the raw data."
            )
            return raw_file

        self.log.info(f"Finished reading file '{filename}' from {self.address}")

        data = match.groups()[0]

        if data and save_to_file:
            datastore.get(self.address).write_file(data, filename)
        if data:
            data = data.replace("\x02", "").replace("\x03", "")

        return data


__all__ = ["SELTelnet"]
