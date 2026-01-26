"""
Communication functionality for PEAT.

This includes TCP/IP networking, protocol implementations,
serial communication, and parsing utilities.
"""

from peat import state

from .addresses import *
from .common import *
from .discovery import *
from .ftp import FTP
from .http import HTTP
from .interfaces import *
from .ip import *
from .serial import *
from .snmp import *
from .ssh import SSH
from .telnet import Telnet

update_local_interface_cache()
state.raw_socket_capable = raw_socket_capable()
