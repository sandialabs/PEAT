"""MySQL/MariaDB connection protocol for PEAT."""

from __future__ import annotations

import socket
from typing import Any

import pymysql
import pymysql.cursors
from loguru import logger as log


class MySQL:
    """
    MySQL/MariaDB connection wrapper.

    A thin wrapper around PyMySQL for connecting to and querying
    MySQL/MariaDB servers.

    Args:
        ip: Server hostname or IP address.
        port: MySQL port (default 3306).
        username: MySQL username.
        password: MySQL password.
        database: Default database to connect to (optional).
        timeout: Connection and query timeout in seconds.
    """

    def __init__(
        self,
        ip: str,
        port: int = 3306,
        username: str = "root",
        password: str = "",
        database: str = "",
        timeout: float = 10.0,
    ) -> None:
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.database = database
        self.timeout = timeout
        self._conn = None
        self.server_info: str = ""
        self.server_version: tuple[int, ...] = ()

    @staticmethod
    def read_greeting(ip: str, port: int = 3306, timeout: float = 5.0) -> str | None:
        """
        Read the MySQL/MariaDB initial handshake packet over a raw TCP connection.

        MySQL sends a greeting immediately after TCP connect, before any
        authentication. This allows fingerprinting the server without credentials.

        The packet layout (Protocol v10, used since MySQL 4.1):

        - bytes 0-2: payload length (little-endian uint24)
        - byte  3:   sequence number (``0x00``)
        - byte  4:   protocol version (``0x0a`` = 10)
        - bytes 5-N: server version string, null-terminated

        Args:
            ip: Server IP address or hostname.
            port: MySQL port (default 3306).
            timeout: Seconds to wait for the greeting.

        Returns:
            The null-terminated version string (e.g. ``"8.0.32"`` or
            ``"10.6.12-MariaDB"``), or ``None`` if the host did not respond
            with a valid MySQL greeting.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, port))
                data = sock.recv(256)
        except Exception as exc:
            log.debug(f"MySQL greeting read failed ({ip}:{port}): {exc}")
            return None

        # Validate protocol version byte at offset 4
        if len(data) < 6 or data[4] != 0x0A:
            return None

        try:
            null_pos = data.index(b"\x00", 5)
            return data[5:null_pos].decode("ascii", errors="replace")
        except ValueError:
            return None

    @property
    def connected(self) -> bool:
        """True if currently connected to a MySQL server."""
        return self._conn is not None

    def on_connected(self) -> None:
        """
        Hook called immediately after a successful authenticated connection.

        Override in subclasses to run device-specific setup  queries or
        populate additional instance attributes before enumeration begins.
        """

    def enumerate(self) -> dict[str, Any]:
        """
        Hook for device-specific enumeration queries.

        Override in subclasses to run additional queries and return the
        results as a dict. The returned dict is merged into the pull result
        under the key ``"extra_enumeration"``.
        """
        return {}

    def connect(self) -> bool:
        """
        Establish an authenticated connection to the MySQL server.

        Returns:
            True if the connection succeeded, False otherwise.
        """
        try:
            self._conn = pymysql.connect(
                host=self.ip,
                port=self.port,
                user=self.username,
                password=self.password,
                database=self.database or None,
                connect_timeout=int(self.timeout),
                read_timeout=int(self.timeout),
                write_timeout=int(self.timeout),
                autocommit=True,
            )
            self.server_info = self._conn.get_server_info()
            # Version string may include suffix like "8.0.32-log" or "10.6.12-MariaDB"
            version_str = self.server_info.split("-")[0]
            try:
                self.server_version = tuple(int(x) for x in version_str.split("."))
            except ValueError:
                self.server_version = ()
            self.on_connected()
            return True
        except Exception as exc:
            log.debug(f"MySQL connect failed ({self.ip}:{self.port}): {exc}")
            self._conn = None
            return False

    def disconnect(self) -> None:
        """Close the MySQL connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def query(self, sql: str, args: tuple | None = None) -> list[dict[str, Any]]:
        """
        Execute a SQL statement and return all rows as a list of dicts.

        Args:
            sql: SQL statement to execute.
            args: Optional tuple of arguments for parameterized queries.

        Returns:
            List of row dicts, or empty list on error.
        """
        if self._conn is None:
            return []
        try:
            with self._conn.cursor(pymysql.cursors.DictCursor) as cursor:
                cursor.execute(sql, args)
                return list(cursor.fetchall())
        except Exception as exc:
            log.debug(f"MySQL query failed: {exc}")
            return []

    def get_databases(self) -> list[str]:
        """Return names of all databases visible to the current user."""
        rows = self.query("SHOW DATABASES")
        return [r["Database"] for r in rows]

    def get_tables(self, database: str) -> list[str]:
        """Return table names for the given database."""
        rows = self.query(f"SHOW TABLES FROM `{database}`")
        key = f"Tables_in_{database}"
        return [r[key] for r in rows if key in r]

    def get_table_row_count(self, database: str, table: str) -> int | None:
        """
        Return the approximate row count for a table from information_schema.

        Returns None if the count is unavailable.
        """
        rows = self.query(
            "SELECT TABLE_ROWS FROM information_schema.TABLES "
            "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s",
            (database, table),
        )
        if rows and rows[0].get("TABLE_ROWS") is not None:
            return int(rows[0]["TABLE_ROWS"])
        return None

    def get_users(self) -> list[dict[str, str]]:
        """Return all MySQL user accounts from mysql.user."""
        rows = self.query("SELECT User, Host FROM mysql.user ORDER BY User, Host")
        return [{"user": r["User"], "host": r["Host"]} for r in rows]

    def get_grants(self, user: str, host: str) -> list[str]:
        """Return SHOW GRANTS output lines for a specific user@host."""
        rows = self.query(f"SHOW GRANTS FOR '{user}'@'{host}'")
        if not rows:
            return []
        key = next(iter(rows[0]))
        return [r[key] for r in rows]

    def get_global_variables(self, like: str = "%") -> dict[str, str]:
        """Return global system variables whose names match a LIKE pattern."""
        rows = self.query("SHOW GLOBAL VARIABLES LIKE %s", (like,))
        return {r["Variable_name"]: r["Value"] for r in rows}

    def get_process_list(self) -> list[dict[str, Any]]:
        """Return active MySQL connections and queries from SHOW FULL PROCESSLIST."""
        return self.query("SHOW FULL PROCESSLIST")
