"""
HTTP(S) functions for Schneider Electric Sage RTUs

Authors

- Aidan Kollar
- Christopher Goes
"""

import socket
import ssl
import warnings
from time import sleep

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

from peat.protocols import HTTP


class CustomSSLAdapter(HTTPAdapter):
    """
    A custom adapter to force TLSv1.2 and AES256-GCM-SHA384.
    This exists because otherwise the requests library does not work nicely
    with the device by default. This sets cipher and TLS versions that the device likes.
    Run `openssl s_client -connect [IP]:[PORT]` to verify protocol and cipher
    """

    def __init__(self, ssl_context: ssl.SSLContext, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=self.ssl_context,
        )


class SageHTTP(HTTP):
    """
    HTTP interface for Sage RTUs
    """

    DEFAULT_HEADERS = {
        "Connection": "close",
    }

    def __init__(self, *args, **kwargs) -> None:
        self.session_id: str = ""
        self.config_file_name: str = ""
        self.cookies: dict = {"SESSIONID": "", "KEY": ""}

        # Disable warnings about unverified HTTPS requests being sent
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        # Disable warnings from the ssl library about "ssl.PROTOCOL_TLS" being deprecated
        warnings.filterwarnings("ignore", category=DeprecationWarning)

        super().__init__(*args, **kwargs)

    def gen_session(self) -> requests.Session:
        session = super().gen_session()

        if self.protocol == "https":
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            ssl_context.set_ciphers("AES256-GCM-SHA384")
            session.mount("https://", CustomSSLAdapter(ssl_context=ssl_context))

        return session

    def create_socket(self) -> socket.socket | None:
        try:
            if self.protocol == "https":
                context = ssl._create_unverified_context()
                context.set_ciphers("DEFAULT")

                with socket.create_connection(
                    address=(self.ip, self.port), timeout=self.timeout
                ) as connection:
                    sock = context.wrap_socket(connection, server_hostname=self.ip)
            else:
                sock = socket.create_connection(address=(self.ip, self.port), timeout=self.timeout)
        except Exception:
            self.log.exception(
                "An error occurred when trying to create or establish a socket connection"
            )
            return None

        return sock

    def get_socket_data(self, sock: socket.socket) -> bytes:
        response_data = b""

        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            except TimeoutError:
                self.log.error("Socket timed out while waiting for additional data")
                break
            except Exception as ex:
                self.log.error(f"An unknown error occurred when getting data from a socket: {ex}")
                break

        return response_data

    def get_session_cookie(
        self,
        uname: str = "Admin",
        pword: str = "Telvent1!",
    ) -> None:
        self.log.info("Logging in and getting session cookie...")
        login_post_data = f"uname={uname}&pword={pword}"
        login_endpoint = "/fs/login.htm"

        try:
            sock = self.create_socket()

            http_request = f"POST {login_endpoint} HTTP/1.1\r\n"
            http_request += f"Host: {self.ip}\r\n"
            http_request += f"Content-Length: {len(login_post_data)}\r\n"
            http_request += "Connection: close\r\n\r\n"
            http_request += login_post_data

            sock.sendall(http_request.encode("cp1252", errors="ignore"))

            response_data = self.get_socket_data(sock)
            response_text = response_data.decode("cp1252", errors="ignore")

            session_id = None
            key_cookie = None
            for line in response_text.split("\r\n"):
                if line.startswith("Set-Cookie:"):
                    if "SESSIONID=" in line:
                        session_id = line.split("SESSIONID=")[1].split(";")[0]
                    if "KEY=" in line:
                        key_cookie = line.split("KEY=")[1].split(";")[0]

            if session_id:
                self.cookies["SESSIONID"] = session_id
            else:
                self.log.error(
                    "SESSIONID cookie not found in the response. "
                    "Please try again, it may take a few attempts or check your credentials."
                )

            if key_cookie:
                self.cookies["KEY"] = key_cookie
            else:
                self.log.error("KEY cookie not found in the HTTP response")
        except TimeoutError:
            self.log.error("Socket timed out when attempting to log in")
        finally:
            if sock:
                sock.close()

    def get_config_filename(self) -> str:
        """
        Updates the configuration file to be what is currently live on the system
        by sending POST requests using the requests library. Doing this also provides
        the download file name which differs based on the firmware version.
        """
        self.log.info("Getting config filename...")
        channel = "5"
        status = None
        url = f"{self.url}/cgi/fx/command.html"
        session = self.gen_session()

        # Wait for device to get the config ready for download
        while status != 5:
            try:
                config_page_post_data = f"type=UP_DOWN&entid=&state=&exectime=&channel={channel}"

                response = session.post(
                    url,
                    data=config_page_post_data,
                    cookies=self.cookies,
                    headers={"Connection": "close"},
                    verify=False,
                )

                # TODO: self.post, with recycled session
                # response = self.post(
                #     url,
                #     data=config_page_post_data,
                #     cookies=self.cookies,
                #     verify=False,
                # )

                if response.status_code != 200:
                    self.log.error(f"Unexpected response status code: {response.status_code}")
                    break

                response_text = response.text

                if '"status":' in response_text:
                    status_start = response_text.find('"status": "') + len('"status": ')
                    status_end = response_text.find("}", status_start)
                    status = int(response_text[status_start:status_end].strip().strip('"')[:1])
                else:
                    self.log.error("'status' not found in response")
                    break

                # Sleep for a bit to save bandwidth and not flood the device
                sleep(2)

                if status == 0:
                    channel = "3"
                elif status == 2:
                    channel = "0"
                elif status == 5:
                    if '"fw_fileName"' in response_text:
                        fw_filename_start = response_text.find('"fw_fileName" : "') + len(
                            '"fw_fileName" : '
                        )
                        fw_filename_end = response_text.find("}", fw_filename_start)

                        fw_filename = (
                            response_text[fw_filename_start:fw_filename_end].strip().strip('"')
                        )

                        self.log.debug(f"config filename is: {fw_filename}")
                        self.config_file_name = fw_filename
                        return fw_filename

                    self.log.error("'fw_fileName' not found in response")
                    break
            except requests.exceptions.RequestException as ex:
                self.log.error(f"An error occurred when updating the web configuration file: {ex}")
                break
            except Exception as ex:
                self.log.error(f"An unexpected error occurred: {ex}")
                break
            finally:
                session.close()

        return ""

    def download_config_file(self) -> bytes:
        """
        Downloads the configuration file using the requests library.
        """
        self.log.info(f"Downloading config file '{self.config_file_name}'")

        try:
            response = self.get(
                f"download/download/{self.config_file_name}",
                use_cache=False,
                cookies=self.cookies,
                stream=True,
                verify=False,
            )

            if not response:
                self.log.error(f"Failed to download config file '{self.config_file_name}'")
                return b""

            return response.content
        except requests.exceptions.RequestException as ex:
            self.log.error(f"An error occurred while downloading the config file: {ex}")

        return b""

    def logout(self) -> bool:
        self.log.info("Logging out...")

        try:
            if self.post(
                f"{self.url}/fs/logout.html",
                cookies=self.cookies,
                verify=False,
            ):
                return True
        except Exception as ex:
            self.log.error(f"An error occurred while attempting to log out: {ex}")

        return False
