"""
SSH functions for Schneider Electric Sage RTUs.

This module provides an interface for reading and parsing SSH commands from Sage RTUs.

.. note::
    The key_filename kwarg used in the SSH connection should be the absolute path to the
    desired key. This key should be in the OPENSSH key format required by paramiko. The conversion
    from the default format can be done with PuTTYgen, with an example given in the section `SSH
    Key Generation` of the documentation referenced below.


Examples:

    .. code-block:: python

       from peat.modules.schneider.sage.sage_ssh import SageSSH

       # These kwargs are the common kwargs for the Sage 3030M device.
       ssh_kwargs = {
           "passphrase": "Telvent1!",
           "key_filename": "Admin.ppk",
           "look_for_keys": False,
           "disabled_algorithms": {'pubkeys': ['rsa-sha2-512', 'rsa-sha2-256']}
       }

       sage_con = SageSSH(
           ip="127.0.0.1",
           port=22,
           timeout=5.0,
           username="Admin",
           password="Telvent1!",
           kwargs=ssh_kwargs
       )
       sage_con.login()

       sage_con.write("ls")
       s = sage_con.read()
       sage_con.disconnect()


References

- https://www.sage-rtu.com/uploads/1/1/7/3/117318428/config_web_key___certificate_generation_v1.1.pdf


To SSH directly:

    .. code-block:: shell

       ssh -oHostKeyAlgorithms=+ssh-rsa Admin@192.0.2.2


Authors

- Christopher Goes
- James Gallagher
- Kevin Cox
"""

from copy import deepcopy
from typing import Any

from peat import DeviceData, utils
from peat.protocols import SSH

from .sage_commands import SageCommands


class SageSSH(SSH, SageCommands):
    """
    SSH communication for Sage RTUs.

    This class maintains the connection state and parsed information from
    running common commands on the Sage device. See the parent SSH class for more information
    on expected input when instantiating the SageSSH class.

    Args:
        ip (str): Which IP address to use.
        port (int, optional): Which port number to use - default is 22.
        timeout (float, optional): Seconds to wait for the string before timing out.
        dev (DeviceData, optional): Device specific data to use in configuration.
        kwargs (dict[str, any], optional): Additional kwargs for Paramiko ssh client.
    """

    ENCODING: str = "ascii"
    PRE_WRITE_SLEEP: float = 0.0
    POST_WRITE_SLEEP: float = 0.0
    TYPE: str = "ssh"  # Used for SageCommands

    def __init__(
        self,
        ip: str,
        port: int = 22,
        timeout: float = 5.0,
        username: str | None = None,
        password: str | None = None,
        dev: DeviceData | None = None,
        kwargs: dict[str, Any] | None = None,  # Additional Paramiko input
    ) -> None:
        # Default value outside of initializer. This is for security purposes.
        if kwargs is None:
            kwargs = {}

        # Extract device options to merge with kwargs.
        if dev is None:
            dev_options = {}
        else:
            dev_options = deepcopy(dev.options.get("ssh", {}))

        # Merge sage options and kwargs, but prefer kwargs. This allows
        # the options to be overridden programmatically.
        kwargs = {**dev_options, **kwargs}

        # TODO: backward-compatibility with Sage's logic for now
        if not username and kwargs.get("user"):
            username = kwargs.pop("user")
        elif not username and kwargs.get("username"):
            username = kwargs.pop("username")
        if not password and kwargs.get("pass"):
            password = kwargs.pop("pass")
        elif not password and kwargs.get("password"):
            password = kwargs.pop("password")

        # HACK: remove kwargs arguments that should be set on class
        # Avoids passing duplicate arguments into kwargs in paramiko
        for key in [
            "ip",
            "hostname",
            "port",
            "timeout",
            "username",
            "password",
            "user",
            "pass",
        ]:
            if key in kwargs:
                del kwargs[key]

        super().__init__(ip, port, timeout, username, password, kwargs)

        self.dev = dev  # type: Optional[DeviceData]
        self.resp_dir = None  # type: Optional[Path]

    def login(
        self, user: str | None = "Admin", passwd: str | None = "Telvent1!"
    ) -> bool:
        """
        Login to the device's ssh interface.

        Use the given login credentials to log in to the device via ssh. This connection
        is primarily maintained by the paramiko library.

        Args:
            user: Username to login with.
            passwd: Password to use to login with. This password
                is also used for the key passphrase if the ssh key is input.
        """
        self.log.debug(f"Logging into {self.ip}:{self.port} as user '{user}'")
        try:
            self._comm = self.comm
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
