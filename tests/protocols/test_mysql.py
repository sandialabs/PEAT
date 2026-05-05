from unittest.mock import MagicMock

from peat.protocols.mysql import MySQL

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_greeting(version: bytes) -> bytes:
    """Build a minimal MySQL Initial Handshake Packet for the given version string."""
    payload = b"\x0a" + version + b"\x00" + b"\x00" * 20
    length = len(payload).to_bytes(3, "little")
    return length + b"\x00" + payload


MYSQL_GREETING = _make_greeting(b"8.0.32")
MARIADB_GREETING = _make_greeting(b"10.6.12-MariaDB")
NOT_MYSQL = b"HTTP/1.1 200 OK\r\n\r\n"
TOO_SHORT = b"\x00\x00"


# ---------------------------------------------------------------------------
# MySQL.read_greeting
# ---------------------------------------------------------------------------


class TestReadGreeting:
    def _mock_socket(self, data: bytes):
        sock = MagicMock()
        sock.recv.return_value = data
        sock.__enter__ = lambda s: s
        sock.__exit__ = MagicMock(return_value=False)
        return sock

    def test_mysql_version_returned(self, mocker):
        mocker.patch("socket.socket", return_value=self._mock_socket(MYSQL_GREETING))
        assert MySQL.read_greeting("127.0.0.1") == "8.0.32"

    def test_mariadb_version_returned(self, mocker):
        mocker.patch("socket.socket", return_value=self._mock_socket(MARIADB_GREETING))
        assert MySQL.read_greeting("127.0.0.1") == "10.6.12-MariaDB"

    def test_non_mysql_response_returns_none(self, mocker):
        mocker.patch("socket.socket", return_value=self._mock_socket(NOT_MYSQL))
        assert MySQL.read_greeting("127.0.0.1") is None

    def test_too_short_returns_none(self, mocker):
        mocker.patch("socket.socket", return_value=self._mock_socket(TOO_SHORT))
        assert MySQL.read_greeting("127.0.0.1") is None

    def test_connection_error_returns_none(self, mocker):
        sock = MagicMock()
        sock.connect.side_effect = TimeoutError("timed out")
        sock.__enter__ = lambda s: s
        sock.__exit__ = MagicMock(return_value=False)
        mocker.patch("socket.socket", return_value=sock)
        assert MySQL.read_greeting("127.0.0.1", timeout=0.01) is None

    def test_custom_port_and_timeout_passed(self, mocker):
        mock_sock = self._mock_socket(MYSQL_GREETING)
        mocker.patch("socket.socket", return_value=mock_sock)
        MySQL.read_greeting("10.0.0.1", port=3307, timeout=2.0)
        mock_sock.settimeout.assert_called_once_with(2.0)
        mock_sock.connect.assert_called_once_with(("10.0.0.1", 3307))


# ---------------------------------------------------------------------------
# MySQL.__init__ and properties
# ---------------------------------------------------------------------------


class TestMySQLInit:
    def test_defaults(self):
        m = MySQL("192.168.1.1")
        assert m.ip == "192.168.1.1"
        assert m.port == 3306
        assert m.username == "root"
        assert m.password == ""
        assert m.database == ""
        assert m.timeout == 10.0
        assert not m.connected
        assert m.server_info == ""
        assert m.server_version == ()

    def test_custom_args(self):
        m = MySQL("10.0.0.1", port=3307, username="admin", password="secret", timeout=5.0)
        assert m.port == 3307
        assert m.username == "admin"
        assert m.password == "secret"
        assert m.timeout == 5.0


# ---------------------------------------------------------------------------
# MySQL.connect / disconnect
# ---------------------------------------------------------------------------


class TestMySQLConnect:
    def _mock_pymysql(self, mocker, server_info="8.0.32"):
        mock_conn = MagicMock()
        mock_conn.get_server_info.return_value = server_info
        mocker.patch("pymysql.connect", return_value=mock_conn)
        return mock_conn

    def test_connect_success(self, mocker):
        self._mock_pymysql(mocker)
        m = MySQL("127.0.0.1")
        assert m.connect()
        assert m.connected
        assert m.server_info == "8.0.32"
        assert m.server_version == (8, 0, 32)

    def test_connect_parses_mariadb_version(self, mocker):
        self._mock_pymysql(mocker, server_info="10.6.12-MariaDB")
        m = MySQL("127.0.0.1")
        assert m.connect()
        # Version tuple uses only the numeric prefix before "-"
        assert m.server_version == (10, 6, 12)

    def test_connect_failure_returns_false(self, mocker):
        mocker.patch("pymysql.connect", side_effect=Exception("refused"))
        m = MySQL("127.0.0.1")
        assert not m.connect()
        assert not m.connected

    def test_on_connected_hook_called(self, mocker):
        self._mock_pymysql(mocker)
        m = MySQL("127.0.0.1")
        m.on_connected = MagicMock()
        m.connect()
        m.on_connected.assert_called_once()

    def test_disconnect_clears_connection(self, mocker):
        self._mock_pymysql(mocker)
        m = MySQL("127.0.0.1")
        m.connect()
        assert m.connected
        m.disconnect()
        assert not m.connected

    def test_disconnect_when_not_connected(self):
        m = MySQL("127.0.0.1")
        m.disconnect()  # should not raise
        assert not m.connected


# ---------------------------------------------------------------------------
# MySQL.query and helpers
# ---------------------------------------------------------------------------


class TestMySQLQuery:
    def _connected_mysql(self, mocker, rows=None):
        mock_cursor = MagicMock()
        mock_cursor.__enter__ = lambda s: s
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_cursor.fetchall.return_value = rows or []

        mock_conn = MagicMock()
        mock_conn.get_server_info.return_value = "8.0.32"
        mock_conn.cursor.return_value = mock_cursor
        mocker.patch("pymysql.connect", return_value=mock_conn)
        mocker.patch("pymysql.cursors.DictCursor", MagicMock())

        m = MySQL("127.0.0.1")
        m.connect()
        return m, mock_cursor

    def test_query_returns_rows(self, mocker):
        rows = [{"id": 1}, {"id": 2}]
        m, _ = self._connected_mysql(mocker, rows)
        assert m.query("SELECT 1") == rows

    def test_query_without_connection_returns_empty(self):
        m = MySQL("127.0.0.1")
        assert m.query("SELECT 1") == []

    def test_get_databases(self, mocker):
        rows = [{"Database": "app"}, {"Database": "logs"}]
        m, _ = self._connected_mysql(mocker, rows)
        assert m.get_databases() == ["app", "logs"]

    def test_get_tables(self, mocker):
        rows = [{"Tables_in_app": "users"}, {"Tables_in_app": "events"}]
        m, _ = self._connected_mysql(mocker, rows)
        assert m.get_tables("app") == ["users", "events"]

    def test_get_table_row_count(self, mocker):
        rows = [{"TABLE_ROWS": 42}]
        m, _ = self._connected_mysql(mocker, rows)
        assert m.get_table_row_count("app", "users") == 42

    def test_get_table_row_count_none(self, mocker):
        rows = [{"TABLE_ROWS": None}]
        m, _ = self._connected_mysql(mocker, rows)
        assert m.get_table_row_count("app", "users") is None

    def test_get_users(self, mocker):
        rows = [{"User": "root", "Host": "localhost"}, {"User": "app", "Host": "%"}]
        m, _ = self._connected_mysql(mocker, rows)
        assert m.get_users() == [
            {"user": "root", "host": "localhost"},
            {"user": "app", "host": "%"},
        ]

    def test_get_grants(self, mocker):
        rows = [{"Grants for root@localhost": "GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost'"}]
        m, _ = self._connected_mysql(mocker, rows)
        result = m.get_grants("root", "localhost")
        assert len(result) == 1
        assert "GRANT ALL" in result[0]

    def test_get_grants_empty(self, mocker):
        m, _ = self._connected_mysql(mocker, rows=[])
        assert m.get_grants("nobody", "localhost") == []

    def test_get_global_variables(self, mocker):
        rows = [{"Variable_name": "version", "Value": "8.0.32"}]
        m, _ = self._connected_mysql(mocker, rows)
        assert m.get_global_variables(like="version") == {"version": "8.0.32"}

    def test_get_process_list(self, mocker):
        rows = [{"Id": 1, "User": "root", "Command": "Query"}]
        m, _ = self._connected_mysql(mocker, rows)
        assert m.get_process_list() == rows


# ---------------------------------------------------------------------------
# Hook methods
# ---------------------------------------------------------------------------


class TestMySQLHooks:
    def test_on_connected_default_is_noop(self):
        m = MySQL("127.0.0.1")
        m.on_connected()  # should not raise or return anything meaningful

    def test_enumerate_default_returns_empty_dict(self):
        m = MySQL("127.0.0.1")
        assert m.enumerate() == {}

    def test_subclass_on_connected_called(self, mocker):
        called = []

        class CustomMySQL(MySQL):
            def on_connected(self):
                called.append(True)

        mock_conn = MagicMock()
        mock_conn.get_server_info.return_value = "8.0.32"
        mocker.patch("pymysql.connect", return_value=mock_conn)

        c = CustomMySQL("127.0.0.1")
        c.connect()
        assert called == [True]

    def test_subclass_enumerate_returned(self, mocker):
        class CustomMySQL(MySQL):
            def enumerate(self):
                return {"custom_table": [{"row": 1}]}

        mock_cursor = MagicMock()
        mock_cursor.__enter__ = lambda s: s
        mock_cursor.__exit__ = MagicMock(return_value=False)
        mock_cursor.fetchall.return_value = []
        mock_conn = MagicMock()
        mock_conn.get_server_info.return_value = "8.0.32"
        mock_conn.cursor.return_value = mock_cursor
        mocker.patch("pymysql.connect", return_value=mock_conn)
        mocker.patch("pymysql.cursors.DictCursor", MagicMock())

        c = CustomMySQL("127.0.0.1")
        c.connect()
        assert c.enumerate() == {"custom_table": [{"row": 1}]}
