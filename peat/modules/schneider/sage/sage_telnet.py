"""
Telnet functions for Schneider Electric Sage RTUs.

Authors

- Aaron Lombrozo
- Christopher Goes
"""

from pathlib import Path

from peat import DeviceData, utils
from peat.protocols import Telnet

from .sage_commands import SageCommands


class SageTelnet(Telnet, SageCommands):
    ENCODING: str = "ascii"
    PRE_WRITE_SLEEP: float = 0.0
    TYPE: str = "telnet"  # Used for SageCommands

    def __init__(
        self,
        ip: str,
        port: int = 23,
        timeout: float = 5,
        dev: DeviceData | None = None,
    ) -> None:
        super().__init__(ip, port, timeout)
        self.dev: DeviceData | None = dev
        self.resp_dir: Path | None = None

    def login(self, user: str = "Admin", passwd: str = "Telvent1!") -> bool:
        """
        Login to the device's telnet interface.
        """
        self.log.debug(f"Logging into {self.ip}:{self.port} as user '{user}'")
        try:
            self.read_until("login: ")
            self.write(user)
            self.read_until("Password: ")
            self.write(passwd)
            data = self.read()

            if "->" not in data:
                if "login incorrect" in data.lower():
                    reason = f"Incorrect credentials (user: '{user}')"
                else:
                    reason = f"Unknown reason\nData: {repr(data)}"
                self.log.debug(f"Login failed: {reason}")
                self.disconnect()
                return False

            self.log.debug(
                f"Logged in to Sage with user '{user}' at {utils.time_now()}"
            )

            self.successful_creds = (user, passwd)  # Save the creds
            return True
        except (EOFError, OSError) as ex:
            self.log.debug(f"Exception during login: {ex}")
            self.disconnect()
        return False

    def disconnect(self) -> None:
        if self.connected and self._comm:
            self.log.debug(f"Disconnected from Sage at {utils.time_now()}")
            try:
                self.write("exit")
            except Exception:
                pass
        super().disconnect()
