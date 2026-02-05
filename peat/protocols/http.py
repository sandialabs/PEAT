from __future__ import annotations

import re
import socket
import ssl
import tempfile
import urllib.parse
from pathlib import Path
from typing import Literal

from bs4 import BeautifulSoup
from requests import Response, Session

import peat  # Avoid circular imports
from peat import config, consts, utils, log


class HTTP:
    """
    Basic set of reusable HTTP functionality.
    """

    page_cache: dict[str, Response] = {}  # Global cache of page data, keyed by URL
    DEFAULT_HEADERS: dict = {}

    def __init__(
        self,
        ip: str,
        port: int = 80,
        timeout: float = 5.0,
        dev: peat.data.models.DeviceData | None = None,
        protocol: Literal["http", "https", ""] = "",
    ) -> None:
        """
        Args:
            ip: IP address of HTTP host
            port: TCP port to use
            timeout: Default timeout for requests
            dev: Default :class:`~peat.data.models.DeviceData` instance to
                use for various things like saving files
        """
        self.ip: str = ip
        self.port: int = port
        self.timeout: float = timeout

        self.protocol: Literal["http", "https", ""] = protocol
        if not self.protocol and self.port == 80:
            self.protocol = "http"
        elif not self.protocol and self.port == 443:
            self.protocol = "https"

        # Instance-level logger
        self.log = log.bind(
            classname=self.__class__.__name__,
            target=f"{self.protocol}://{self.ip}:{self.port}",
        )

        self._session: Session | None = None

        # default device object to use
        self.dev: peat.data.models.DeviceData | None = dev

        # WARNING: do NOT uncomment the code below UNLESS Elasticsearch
        # export is disabled, otherwise all Elasticsearch traffic will
        # be emitted to STDOUT (including logging!).
        #
        # if config.DEBUG >= 3:
        #     # Enable request/response debugging output (print statements)
        #     # can we monkeypatch this so it goes to logging instead of just stdout?
        #     from http.client import HTTPConnection
        #     HTTPConnection.debuglevel = 1

        self.log.trace(f"Initialized {repr(self)}")

    @property
    def url(self) -> str:
        return f"{self.protocol}://{self.ip}:{self.port}"

    @property
    def session(self) -> Session:
        if self._session is None:
            self._session = self.gen_session()
            if self.DEFAULT_HEADERS:
                self._session.headers.update(self.DEFAULT_HEADERS)
        return self._session

    @session.setter
    def session(self, sess: Session) -> None:
        if self._session is not None:
            self._session.close()
        self._session = sess

    @property
    def connected(self) -> bool:
        return bool(self._session)

    def disconnect(self) -> None:
        if self._session is not None:
            self._session.close()

    def __enter__(self) -> HTTP:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()
        if exc_type:
            self.log.debug(f"{exc_type.__name__}: {exc_val}")

    def __str__(self) -> str:
        return self.ip

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.ip}, {self.port}, {self.timeout})"

    def _save_response_to_file(
        self,
        response: Response,
        page: str,
        url: str,
        dev: peat.data.models.DeviceData | None,
    ) -> Path | None:
        """
        Save raw text data from response to disk, even if bad status code.
        """
        try:
            if response.text:
                f_name = ""

                cd = response.headers.get("content-disposition", "")
                if cd and "filename" in cd:
                    fn_match = re.findall(r"filename=(.+)", cd)
                    if fn_match:
                        f_name = fn_match[0].strip('"')

                if not f_name:
                    if not page and url:
                        parts = urllib.parse.urlparse(url)
                        page = parts.path.strip("/")
                        # handle paths with args, e.g. ?0x0D00 vs ?0X0000 are different
                        if parts.query:
                            page = f"{page}{parts.query}.html"

                    if not page or page == "/":
                        f_name = "index.html"
                    elif page.endswith(".html") or page.endswith(".htm"):
                        f_name = page
                    else:
                        f_name = f"{page}.html"

                if not dev:
                    dev = peat.data.datastore.get(self.ip)

                # Sanitize characters that are invalid filenames on Windows
                # This avoids a warning in utils.write_file()
                for char in ["?", ":", '"']:
                    if char in f_name:
                        f_name = f_name.replace(char, "_")

                path = dev.write_file(
                    response.text,
                    filename=f_name,
                    out_dir=dev.get_sub_dir("http_files"),
                )

                dev.related.files.add(f_name)

                self.log.trace2(f"Saved response from {url} to {path.as_posix()}")

                return path
        except Exception:
            self.log.exception(f"Failed to write page '{page}' to file")

    def get(
        self,
        page: str = "",
        protocol: Literal["http", "https", ""] = "",
        url: str = "",
        use_cache: bool = True,
        params: dict | None = None,
        auth=None,
        allow_errors: bool = False,
        dev: peat.data.models.DeviceData | None = None,
        timeout: float | None = None,
        **kwargs,
    ) -> Response | None:
        """
        Perform a HTTP ``GET`` request and return the response.

        .. warning::
           Results of queries for an identical URL are cached by default for
           a single run of PEAT. If your tool is querying the status or looking
           for changes within a single run of PEAT, then set ``use_cache``
           to :obj:`False`.

        .. note::
           The response object will have three additional attributes:
           ``request_timestamp``, ``response_timestamp``, ``file_path``.

        Args:
            page: URL path of the page to get
            protocol: Name of the protocol to use
                If empty string (default), the HTTP instance's "protocol" will be used, if set.
                Otherwise, it will default to "http".
            url: URL to use instead of the auto-constructed one
            use_cache: If the internal page cache should be used.
            params: Additional HTTP parameters to include in the request
            auth: Authentication to use for the request (refer to Requests docs)
            dev: DeviceData object to save files to
            timeout: Timeout for the query. If :obj:`None`, the default
                timeout for this class instance is used instead.
            kwargs: Additional keyword arguments that will be passed
                directly to ``Requests.get()``

        Returns:
            The response object, or :obj:`None` if the request failed.
            The response object will have three additional attributes:
            ``request_timestamp``, ``response_timestamp``, ``file_path``.
        """
        if not protocol and self.protocol:
            protocol = self.protocol
        elif not protocol:
            protocol = "http"

        if not url:
            if protocol == "https" and self.port == 80:  # TODO: hack
                self.log.debug(
                    f"Protocol is https and port is 80, hardcoding "
                    f"to port 443 for request for page {page}"
                )
                port = 443
            else:
                port = self.port

            # trim leading slash for ergonomics
            if page.startswith("/"):
                page = page[1:]

            # TODO: use urllib.parse.urljoin()
            url = f"{protocol}://{self.ip}:{port}/{page}"

        # TODO: add a lifetime to the cache
        if use_cache and self.page_cache.get(url):
            self.log.info(f"GET -> {url} (using cached response)")
            return self.page_cache[url]

        self.log.info(f"GET -> {url}")

        if not dev and self.dev:
            dev = self.dev

        if timeout is None:
            timeout = self.timeout

        try:
            req_ts = utils.utc_now()  # rough timestamp of send time

            response: Response = self.session.get(
                url, timeout=timeout, params=params, auth=auth, **kwargs
            )

            file_path = self._save_response_to_file(response, page, url, dev)

            if not allow_errors and response.status_code != 200:
                err = f"status code {response.status_code}"
            else:
                # Record rough timestamps of request and response
                response.request_timestamp = req_ts
                response.response_timestamp = req_ts + response.elapsed
                # Record where the file was saved as a Path object
                response.file_path = file_path
                self.page_cache[url] = response
                return response
        except Exception as ex:
            err = str(ex)

        self.log.warning(f"Failed to GET '{url}': {err}")
        return None

    def post(
        self,
        url: str,
        timeout: float | None = None,
        dev: peat.data.models.DeviceData | None = None,
        use_cache: bool = False,
        **kwargs,
    ) -> Response | None:
        """
        Perform a HTTP ``POST`` request and return the response.

        .. note::
           The response object will have three additional attributes:
           ``request_timestamp``, ``response_timestamp``, ``file_path``.

        Args:
            url: URL to use for the request
            timeout: Timeout for the query. If :obj:`None`, the default
                timeout for this class instance is used instead.
            dev: DeviceData object to save files to
            use_cache: If the internal page cache should be used
            kwargs: Additional keyword arguments that will be passed
                directly to ``Requests.post()``

        Returns:
            The response object, or :obj:`None` if the request failed.
            The response object will have three additional attributes:
            ``request_timestamp``, ``response_timestamp``, ``file_path``.
        """

        # TODO: add a lifetime to the cache
        if use_cache and self.page_cache.get(url):
            self.log.info(f"POST -> {url} (using cached response)")
            return self.page_cache[url]

        self.log.info(f"POST -> {url}")

        if not dev and self.dev:
            dev = self.dev

        if timeout is None:
            timeout = self.timeout

        try:
            req_ts = utils.utc_now()  # rough timestamp of send time

            response: Response = self.session.post(url, timeout=timeout, **kwargs)

            # Save the raw response text body to disk as an artifact
            parts = urllib.parse.urlparse(url)
            page = parts.path.strip("/")
            # handle paths with args, e.g. ?0x0D00 vs ?0X0000 are different
            if parts.query:
                page = f"{page}{parts.query}.html"

            file_path = self._save_response_to_file(response, page, url, dev)

            if response.status_code != 200:
                err = f"status code {response.status_code}"
            else:
                # Record rough timestamps of request and response
                response.request_timestamp = req_ts
                response.response_timestamp = req_ts + response.elapsed
                # Record where the file was saved as a Path object
                response.file_path = file_path
                self.page_cache[url] = response

                return response
        except Exception as ex:
            err = str(ex)

        self.log.warning(f"Failed to POST '{url}': {err}")
        return None

    def get_ssl_certificate(self) -> peat.data.models.X509 | None:
        """
        Retrieve and parse the server's SSL certificate.

        Returns:
            SSL certificate data in Elastic Common Schema (:term:`ECS`)-compliant format
        """
        emsg = "Failed to get SSL certificate"

        try:
            # (01/04/2022) Workaround issues in newer Pythons (3.10+)
            # with ssl.get_server_certificate() when used with older
            # ICS/OT devices (in other words, what PEAT does).
            #
            # References:
            #   https://stackoverflow.com/a/49132495
            #   https://stackoverflow.com/a/71007463
            #
            # These code snippets may be useful in future:
            #   context.options &= ~ssl.OP_NO_SSLv3
            #   context.check_hostname = False
            #   context.verify_mode = ssl.CERT_NONE
            #
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.set_ciphers("DEFAULT")

            with socket.create_connection(
                address=(self.ip, self.port), timeout=self.timeout
            ) as connection:
                with context.wrap_socket(
                    connection, server_hostname=self.ip
                ) as ssl_sock:
                    der_cert = ssl_sock.getpeercert(True)

            if not der_cert:
                self.log.warning(f"{emsg}: No certificate returned from server")
                return None

            raw_cert = ssl.DER_cert_to_PEM_cert(der_cert)  # type: str
        except Exception as ex:
            self.log.exception(f"{emsg}: {ex}")
            return None

        if not raw_cert:
            self.log.warning(
                f"{emsg}: Empty certificate or no certificate was returned"
            )
            return None

        decoded = self.decode_ssl_certificate(raw_cert)

        return self.parse_decoded_ssl_certificate(decoded[0], decoded[1])

    def decode_ssl_certificate(
        self, source: str | bytes | Path
    ) -> tuple[dict[str, str | tuple | int], str]:
        """
        Decode a raw SSL certificate retrieved from a server into
        a raw :class:`dict`.

        Args:
            source: SSL certificate in string or bytes format, or the file path
                to a certificate (as a :class:`~pathlib.Path` object).

        Returns:
            Decoded SSL certificate data as a :class:`dict`
        """
        tmp_name_base = f"{self.ip.replace('.', '_')}_{self.port}"

        if isinstance(source, Path):
            raw = source.read_text(encoding="utf-8")
            path = source.resolve()
        else:
            raw = source
            if isinstance(raw, bytes):
                raw = raw.decode()

            f_name = f"{tmp_name_base}_raw-ssl-certificate.crt"
            if config.TEMP_DIR:
                path = utils.write_temp_file(raw, f_name)
            else:
                # Create a temporary directory to put the cert data to be parsed
                t_dir = tempfile.mkdtemp()
                path = Path(t_dir, f_name)
                path.write_text(raw, encoding="utf-8")

        # Source: https://stackoverflow.com/a/50072461
        decoded = ssl._ssl._test_decode_cert(path)
        utils.write_temp_file(decoded, f"{tmp_name_base}_decoded-ssl-certificate.json")
        self.log.trace2(f"Decoded SSL cert\n{decoded}")

        return decoded, raw

    def parse_decoded_ssl_certificate(
        self, decoded: dict[str, str | tuple | int], raw: str
    ) -> peat.data.models.X509:
        """
        Parse a decoded SSL certificate into Elastic Common Schema (:term:`ECS`)
        format usable with the x509 data model (:class:`~peat.data.models.X509`).

        Args:
            decoded: Decoded SSL certificate, usually obtained from calling
                :meth:`~peat.protocols.http.decode_ssl_certificate`.
            raw: The original SSL certificate text

        Returns:
            SSL certificate data in Elastic Common Schema (:term:`ECS`)-compliant format
        """
        serial_number = str(decoded.get("serialNumber", ""))
        serial_number = serial_number.strip().upper().replace(":", "")

        # NOTE: hashes will get generated by annotate()
        cert = peat.data.models.X509(
            original=raw,
            serial_number=serial_number,
            version_number=str(decoded.get("version", "")),
            not_after=(
                utils.parse_date(decoded["notAfter"])
                if decoded.get("notAfter")
                else None
            ),
        )

        if decoded.get("notAfter"):
            cert.not_after = utils.parse_date(decoded["notAfter"])
        if decoded.get("notBefore"):
            cert.not_before = utils.parse_date(decoded["notBefore"])

        # Extract Issuer and Subject fields
        alternative_names = set()
        for group in ["issuer", "subject"]:
            if group not in decoded:
                continue

            entity = peat.data.models.CertEntity()

            for field in decoded[group]:
                if len(field) > 1 or len(field[0]) > 2:
                    self.log.warning(f"Abnormal length for SSL field {field}")

                f_name = utils.convert_to_snake_case(field[0][0])
                if "common" not in f_name and "distinguished" not in f_name:
                    f_name = f_name.replace("_name", "")

                val = str(field[0][1]).strip()

                if hasattr(entity, f_name):
                    setattr(entity, f_name, val)
                elif f_name == "email_address":
                    alternative_names.add(val)
                else:
                    self.log.warning(
                        f"Skipping value '{f_name}' with value '{val}' for "
                        f"'{group}' since it's not a valid CertEntity field"
                    )

            setattr(cert, group, entity)

        cert.alternative_names.extend(alternative_names)
        cert.annotate(None)
        self.log.trace2(f"Parsed SSL cert\n{cert}")

        return cert

    @staticmethod
    def gen_soup(text: str | bytes) -> BeautifulSoup:
        """
        Generate a BeautifulSoup instance from the text using the efficient
        ``lxml`` library if it's available or ``html.parser`` otherwise.

        Returns:
            A ``bs4.BeautifulSoup`` instance with the parser set to
                the value of :data:`peat.consts.BS4_PARSER`
        """
        return BeautifulSoup(text, features=consts.BS4_PARSER)

    @staticmethod
    def gen_session() -> Session:
        """
        Session with SSL certificate verification disabled and no
        proxies from environment (e.g. ``http_proxy``/``https_proxy``).
        """
        session = Session()
        session.verify = False
        session.trust_env = False
        return session


__all__ = ["HTTP"]
