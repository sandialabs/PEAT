from __future__ import annotations

import datetime
import functools
import json
import pickle
from base64 import b64encode
from collections import defaultdict
from collections.abc import Callable
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from pathlib import PurePath
from pprint import pformat
from random import randint
from typing import Any, Literal

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ApiError, RequestError, TransportError
from elasticsearch.helpers import parallel_bulk as elasticsearch_parallel_bulk
from elasticsearch.serializer import JsonSerializer as ESJsonSerializer
from opensearchpy import OpenSearch
from opensearchpy.exceptions import OpenSearchException
from opensearchpy.helpers import parallel_bulk as opensearch_parallel_bulk
from opensearchpy.serializer import JSONSerializer as OSJSONSerializer

from peat import (
    __version__,
    config,
    consts,
    es_mappings,
    exit_handler,
    log,
    state,
    utils,
)
from peat.protocols import HTTP

from .es_mappings import PEAT_INDICES


def _serialize_value(data, default_func: Callable):
    """
    Serializes types for Elasticsearch that aren't handled by
    elasticsearch-py's or opensearchpy's JSON serializers.
    """
    if isinstance(data, (bytes, bytearray, memoryview)):
        return b64encode(data).decode()

    if isinstance(data, PurePath):  # This also handles Path objects
        return data.as_posix()

    if isinstance(data, datetime.timedelta):
        return data.total_seconds()  # Merge days, seconds, and microseconds

    if isinstance(data, (IPv4Interface, IPv6Interface)):
        return str(data.ip)

    if isinstance(data, (IPv4Network, IPv6Network, IPv4Address, IPv6Address)):
        return str(data)

    if isinstance(data, set):
        # Strip Nones and empty strings from sets
        for empty_val in ["", None]:
            if empty_val in data:
                data.remove(empty_val)

        # convert list to set and sort for determinism
        return sorted(data)

    return default_func(data)


class PeatElasticSerializer(ESJsonSerializer):
    def default(self, data: Any) -> bool | str | float | int | list | None:
        return _serialize_value(data, functools.partial(ESJsonSerializer.default, self))


class PeatOpenSearchSerializer(OSJSONSerializer):
    def default(self, data: Any) -> bool | str | float | int | list | None:
        return _serialize_value(data, functools.partial(OSJSONSerializer.default, self))


class Elastic:
    """
    Wrapper for interacting with an Elasticsearch or OpenSearch database.
    """

    ECS_VERSION = "8.10.0"
    """
    Version of :term:`ECS` PEAT currently follows.
    """

    def __init__(self, server_url: str = "http://localhost:9200/") -> None:
        self._es: Elasticsearch | OpenSearch | None = None
        self._index_cache: set[str] = set()
        self._doc_id_cache: set[str] = set()

        # Handle differences in elasticsearch vs opensearch
        self.is_opensearch: bool = False
        self.type: Literal["Elasticsearch", "OpenSearch"] = "Elasticsearch"
        self.parallel_bulk: Callable = elasticsearch_parallel_bulk
        self.serializer = PeatElasticSerializer()

        # Save every doc written to Elastic as a local file, except for
        # log entries, events, and memory reads.
        # This can be used to rebuild the index from file artifacts
        self._docs_written: dict[str, set[str]] = defaultdict(set)
        exit_handler.register(self._dump_docs_to_file, "FILE")

        # Initialize the Base and Agent field values
        self.base_info = {
            "ecs": {"version": Elastic.ECS_VERSION},
            "agent": {
                "id": str(consts.RUN_ID),
                "type": "PEAT",
                "version": __version__,
            },
        }

        # Basic observer information to include with all docs
        self.basic_observer_info = {
            "geo": {"timezone": consts.TIMEZONE},
            "hostname": consts.SYSINFO["hostname"],
            "ip": state.local_interface_ips,
            "mac": state.local_interface_macs,
            "user": {
                "name": consts.SYSINFO["username"],
            },
        }

        # Full server url that may contain username and password
        # Example: http://elastic:changeme@localhost:9200/
        if not server_url.endswith("/"):
            server_url += "/"
        self.unsafe_url = server_url

        # Server URL without any sensitive login credentials
        # Example: http://localhost:9200/
        if "@" in server_url:
            self.safe_url = server_url.partition("@")[2]
            if "://" in server_url:
                self.safe_url = "".join(server_url.partition("://")[:2]) + self.safe_url
        else:
            self.safe_url = server_url

        # Just the hostname and port (e.g. "localhost:9200")
        self.host = self.safe_url.split("://")[-1].strip("/")

        # Instance-specific logger
        # NOTE: "es_logger" MUST be set for any Elastic-logged messages
        self.log = log.bind(target=self.host, es_logger=True)

        # Parse timestamp now so we're not doing it with every push
        self.start_time = self.convert_tstamp(consts.START_TIME_UTC)
        self.log.trace(f"Initialized Elastic({self.safe_url})")

    def __str__(self) -> str:
        return self.host

    def __repr__(self) -> str:  # Needed for dumping peat.state
        return f'Elastic("{self.unsafe_url}")'

    def _dump_docs_to_file(self) -> None:
        if not config.ELASTIC_DIR or not self._docs_written:
            return

        # Nest all documents for a run in their own directory
        dirpath = config.ELASTIC_DIR / str(consts.RUN_ID)
        for index, docs in self._docs_written.items():
            path = dirpath / f"{index}.jsonl"
            data = "\n".join(doc for doc in docs)
            utils.write_file(data, path, format_json=False)

    @property
    def es(self) -> Elasticsearch | OpenSearch:
        """
        Elasticsearch or OpenSearch client instance.

        If it doesn't exist yet, this will create a client object and connect
        to the server. Otherwise, will return the existing instance.
        """
        if self._es is None:
            # use gen_session() to ensure proxy isn't set
            # TODO: this probably won't fly with Malcolm's fronting proxy
            with HTTP.gen_session() as sess:
                r = sess.get(self.unsafe_url)
                if not r or r.status_code != 200:
                    raise ConnectionError(
                        "Failed to connect to Elasticsearch or OpenSearch server"
                    )

                # ES: 'You Know, for Search'
                # OS: 'The OpenSearch Project: https://opensearch.org/'
                tagline = r.json().get("tagline", "").lower()
                if not tagline:
                    raise ConnectionError(
                        f"No 'tagline' field in response from Elasticsearch "
                        f"or OpenSearch server {self.safe_url}, it may not "
                        f"be a Elasticsearch or OpenSearch server"
                    )

                if "opensearch" in tagline:
                    self.is_opensearch = True
                    self.type = "OpenSearch"
                    self.parallel_bulk = opensearch_parallel_bulk
                    self.serializer = PeatOpenSearchSerializer()

            try:
                if self.is_opensearch:
                    # TODO: instead of mutating global state...do this on the class
                    es_mappings.FLATTENED["type"] = "flat_object"
                    if "ignore_above" in es_mappings.FLATTENED:
                        del es_mappings.FLATTENED["ignore_above"]
                    es_klass = OpenSearch
                else:
                    es_klass = Elasticsearch

                self._es = es_klass(
                    hosts=[self.unsafe_url],
                    verify_certs=False,
                    ssl_show_warn=False,
                    timeout=config.ELASTIC_TIMEOUT,
                    serializer=self.serializer,  # type: ignore
                )

                if not self._es.ping:
                    raise consts.PeatError(
                        f"Connected to {self.type} cluster, but "
                        f"the connection test failed for {self.safe_url}"
                    )
            except (ApiError, TransportError, OpenSearchException) as err:
                self.log.exception(f"Failed to connect to {self.type}: {err}")
                raise err
            except Exception as err:
                self.log.error(
                    f"Unknown exception occurred while connecting to {self.type}: {err}"
                )
                raise err

            self.log.info(f"Connected to {self.type} cluster '{self._es.info()['cluster_name']}'")
            self.log.trace2(f"** {self.type} server info **\n{pformat(self._es.info())}")

            # Server may have been flushed, reset the index cache
            self._index_cache = set()

        return self._es

    @es.setter
    def es(self, instance: Elasticsearch | OpenSearch) -> None:
        self._es = instance

    def info(self) -> str:
        """
        Information about the Elasticsearch/OpenSearch server/cluster.
        """
        return str(self.es.info())

    def ping(self) -> bool:
        """
        Check if the server is online and the connection is working.
        """
        return self.es.ping()

    def disconnect(self) -> None:
        """
        Disconnect from the Elasticsearch/OpenSearch server.
        """
        if self._es is not None:
            self._es.close()
            self._es = None

    def doc_exists(self, index: str, doc_id: str) -> bool:
        """
        Check if a document exists on an index.

        Note: this won't auto-resolve dated index names.
        """
        if doc_id in self._doc_id_cache:
            return True

        if not self.index_exists(index):
            return False

        if self.es.exists(index=index, id=doc_id):
            self._doc_id_cache.add(doc_id)
            return True

        return False

    def index_exists(self, index: str) -> bool:
        """
        Check if an Elasticsearch/OpenSearch index exists.

        This method caches index existence checks to reduce number of
        requests to the server.

        Args:
            index: Name of the index to check (this can be any valid index pattern)

        Returns:
            If the index exists
        """
        if index in self._index_cache:
            return True
        elif self.es.indices.exists(index=index):
            self.log.trace3(f"'{index}' already exists")
            self._index_cache.add(index)
            return True

        return False

    def create_index(self, index: str, fields_limit: int = 20000) -> bool:
        """
        Create an index in Elasticsearch/OpenSearch if it doesn't already exist.

        Args:
            index: Name of the index to create
            fields_limit: Elastic limits the number of fields in an index
                to 1000 by default, which is problematic for some devices
                that have protocol register mappings (e.g. DNP3, Modbus).
                To avoid this, we raise the limit by default for all
                PEAT indices. This option allows us to tweak that limit
                as needed for specific indices.

        Returns:
            If the index was successfully created
        """
        if self.index_exists(index):
            return True

        self.log.debug(f"Creating index '{index}'")

        try:
            # Handle dated indices, e.g 'peat-configs-2019.08.28' => 'peat-configs'
            index_name = index.rpartition("-")[0] if "." in index else index

            # Minor hack to make configurable indices work
            index_remap = {
                "alerts": "alerts",  # TODO: kept for backward compatibility
                config.ELASTIC_LOG_INDEX: "vedar-logs",
                config.ELASTIC_SCAN_INDEX: "peat-scan-summaries",
                config.ELASTIC_PULL_INDEX: "peat-pull-summaries",
                config.ELASTIC_PARSE_INDEX: "peat-parse-summaries",
                config.ELASTIC_CONFIG_INDEX: "peat-configs",
                config.ELASTIC_STATE_INDEX: "peat-state",
                config.ELASTIC_HOSTS_INDEX: "ot-device-hosts-timeseries",
                config.ELASTIC_FILES_INDEX: "ot-device-files",
                config.ELASTIC_REGISTERS_INDEX: "ot-device-registers",
                config.ELASTIC_TAGS_INDEX: "ot-device-tags",
                config.ELASTIC_IO_INDEX: "ot-device-io",
                config.ELASTIC_EVENTS_INDEX: "ot-device-events",
                config.ELASTIC_MEMORY_INDEX: "ot-device-memory",
                config.ELASTIC_UEFI_FILES_INDEX: "uefi-files",
                config.ELASTIC_UEFI_HASHES_INDEX: "uefi-hashes",
            }
            remapped_name = index_remap.get(index_name, index_name)

            body = {
                "settings": {
                    "index.mapping.total_fields.limit": fields_limit,
                },
            }

            if remapped_name in PEAT_INDICES:
                index_type_mapping = PEAT_INDICES[remapped_name]
                body["mappings"] = index_type_mapping
            else:
                self.log.warning(
                    f"No index mapping defined for '{remapped_name}'."
                    f"This happens if pushing to a non-PEAT index."
                )

            # Save the index mapping and settings to a JSON file
            # This can be used to rebuild the index from file artifacts
            if config.ELASTIC_DIR:
                f_name = f"{index}_{consts.RUN_ID}.json"
                f_pth = config.ELASTIC_DIR / "mappings" / f_name
                # Workaround nasty recursive logging messages because
                # utils.log has the ElasticHandler
                o_log = utils.log
                utils.log = self.log
                utils.write_file({index: body}, f_pth)
                utils.log = o_log

            # BUGFIX: possible race condition here if timings are unlucky when
            # multiple instances of PEAT are running at the same time and
            # attempt to create the same index at nearly the same time.
            # Error: 'resource_already_exists_exception'
            try:
                self.es.indices.create(index=index, body=body)
            except RequestError as req_err:
                if "resource_already_exists_exception" in str(req_err):
                    self.log.warning(
                        f"Index '{index}' already exists in create_index, "
                        f"weird but not a big deal. There is probably another "
                        f"instance of PEAT running in parallel that attempted "
                        f"to create the same index at the same time."
                    )
                else:
                    raise req_err
        except Exception as ex:
            self.log.exception(f"Failed to create index '{index}': {ex}")
            state.error = True
            return False

        self._index_cache.add(index)
        self.log.info(f"Created index '{index}'")
        return True

    def search(
        self,
        index: str,
        query: str | dict | None = None,
        body: dict | None = None,
    ) -> list[dict]:
        """
        Query for values from an index.

        .. note::
           By default, results sorted are in descending order by timestamp

        Args:
            index: Index to search
            query: Search query, as either a string in Lucene Query format,
                or a :class:`dict` in Elasticsearch Query DSL format.
                If ``query`` is :obj:`None`, all values in the index will be returned.
                Resources:

                - `Lucene query syntax basics <https://www.elastic.co/guide/en/kibana/current/lucene-query.html>`__
                - `Full Lucene Query syntax <https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html#query-string-syntax>`__
                - `Elasticsearch Query DSL <https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html>`__
            body: "body" argument, in lieu of query. Use this if you're doing more complicated
                operations, like aggregations. Example: ``body = {"query": {...}, "aggs": {...}}``

        Returns:
            List of results, in descending order by timestamp (unless a custom
            body is provided with a custom "sort" argument). The :class:`list`
            will be empty if there were no results or an error occurred.
        """
        # https://elasticsearch-py.readthedocs.io/en/master/
        # https://elastic.co/guide/en/elasticsearch/reference/current/search-search.html
        search_args = {
            "size": 10000,
            "index": index,
            "scroll": "5m",
        }

        # Lucene query syntax ("simple query")
        if isinstance(query, str):
            search_args["q"] = query
        # Elasticsearch Query DSL syntax
        elif isinstance(query, dict):
            search_args["body"] = {"query": query, "sort": [{"@timestamp": "asc"}]}
        # Custom body
        elif body:
            search_args["body"] = body

        response = self.raw_search(search_args)
        if not response:
            return []

        # If total is 0, then there are no results
        if response["hits"]["total"]["value"] == 0:
            self.log.info(f"No search results from index '{search_args['index']}'")
            self.log.debug(f"'{search_args['index']}' args: {search_args}")
            self.log.trace(f"Raw response with no results: {response}")
            return []

        # The first 'hits' gets the cluster hits, second is the node hits?
        all_hits = response["hits"]["hits"]  # type: list[dict[str, Any]]

        # Use the Scroll API for large results (more than 10000)
        scroll_ids = []
        num_results = response["hits"]["total"]["value"]
        if num_results > 10000:
            self.log.debug(f"Scrolling through {num_results} results")
            while True:
                page = self.es.scroll(scroll_id=response["_scroll_id"], scroll="5m")

                if response["_scroll_id"] not in scroll_ids:
                    scroll_ids.insert(0, response["_scroll_id"])

                if len(page["hits"]["hits"]) == 0:
                    break

                all_hits.extend(page["hits"]["hits"])

        # "_source" is the data from each hit (the "source" of the result)
        # (basically, _source is the raw document contents as-is in Lucene)
        results = [r["_source"] for r in all_hits]
        self.log.debug(
            f"{len(results)} search results from index "
            f"'{search_args['index']}' (args: {search_args})"
        )

        for scroll_id in scroll_ids:
            self.es.clear_scroll(scroll_id=scroll_id)

        return results

    def raw_search(self, search_args: dict) -> dict | None:
        """
        Query for data in Elasticsearch.

        Assumes you know what you're doing and want direct access to the API.

        Args:
            search_args: Arguments :class:`dict` to pass directly to
                ``Elasticsearch.search`` as keyword arguments (aka "kwargs")

        Returns:
            Raw response :class:`dict` or :obj:`None` if an error occurred
        """
        if "index" not in search_args:
            self.log.error(
                "No index in search_args for raw_search(), did you forget to include it?"
            )
            state.error = True
            return None

        try:
            return self.es.search(**search_args)
        except (ApiError, TransportError) as ex:
            self.log.error(
                f"Failed to search index '{search_args['index']}' (args: {search_args}) : {ex}"
            )
        except Exception:
            self.log.exception(
                f"Unknown error occurred while attempting to search index "
                f"'{search_args['index']}' (args: {search_args})"
            )

        state.error = True
        return None

    def gen_body(self, content: dict) -> dict[str, Any]:
        """
        Generate the basic body of doc to be pushed to Elasticsearch,
        auto-populating standard fields such as "observer", "@timestamp", etc.
        """
        # Populate the Base and Agent fields, then the content
        body: dict[str, Any] = {
            **self.base_info,
            **content,  # The data being pushed
        }

        # Add basic set of observer info if it's not already present
        if "observer" not in body:
            body["observer"] = self.basic_observer_info

        # @timestamp is when event occurred, start time is a fallback
        if "@timestamp" not in body:
            body["@timestamp"] = self.start_time

        if "message" not in body:
            body["message"] = ""
        # ensure message isn't just whitespace
        body["message"] = body["message"].strip().strip(",").strip()

        # Flavor with tags
        tags = set(body.get("tags", []))  # Create a set
        if config.ELASTIC_ADDITIONAL_TAGS:
            # Add additional user-specified tags
            tags.update(config.ELASTIC_ADDITIONAL_TAGS)

        # Strip Nones and empty strings from tags
        for empty_val in ["", None]:
            if empty_val in tags:
                tags.remove(empty_val)
        if tags:
            body["tags"] = list(tags)  # Convert set to list

        return body

    def bulk_push(
        self,
        index: str,
        contents: list[tuple[str, dict]],
    ) -> bool:
        """
        Upload multiple docs to an Elasticsearch index.

        .. note::
           Index names will have a date appended, unless ``no_date=True``. For example,
           ``peat-configs`` will become ``peat-configs-2020.01.01``.

        Args:
            index: Name of the Elasticsearch Index to push to
            contents: data to send, as a :class:`list` of :class:`tuple`
                with doc ID and data payload

        Returns:
            True if the bulk push was successful for all docs,
            False if any docs failed or index creation failed.
        """

        # Add a date to the index name
        if not config.ELASTIC_DISABLE_DATED_INDICES:
            index = f"{index}-{utils.utc_now().strftime('%Y.%m.%d')}"

        if not self.create_index(index):
            state.error = True
            return False

        # TODO: hack, auto-generate doc ID if it's just a list of dict?
        actions = []
        for doc_id, content in contents:
            body = self.gen_body(content)
            action = {"_index": index, "_id": doc_id, "_source": body}
            actions.append(action)

        self.log.info(f"Bulk pushing {len(actions)} docs to {self.type}")

        successful = True
        try:
            for es_success, _ in self.parallel_bulk(client=self.es, actions=actions):
                if not es_success:
                    successful = False
        except Exception as err:
            self.log.error(
                f"Bulk push failed for {len(actions)} docs to index '{index}'\n"
                f"Error: {type(err).__name__}\n"
                f"Status code: {getattr(err, 'status_code', '')}\n"
                f"Elastic exception info: {getattr(err, 'info', '')}\n"
                f"Error message: {getattr(err, 'message', str(err.args))}"
            )
            if config.DEBUG:
                self.log.exception(f"traceback for bulk push error '{err}'")
            successful = False

        if not successful:
            self.log.error("Bulk push failed!")
            state.error = True

        return successful

    def push(
        self,
        index: str,
        content: dict,
        doc_id: str | None = None,
        no_date: bool = False,
    ) -> bool:
        """
        Upload data to an Elasticsearch index.

        .. note::
           Index names will have a date appended, unless ``no_date=True``. For example,
           ``peat-configs`` will become ``peat-configs-2020.01.01``.

        Args:
            index: Name of the Elasticsearch Index to push to
            content: Data to be pushed (this is added to the body)
            doc_id: Document ID to create or update. If :obj:`None`, a ID
                will be automatically generated and used instead.
            no_date: Don't add a date to index name

        Returns:
            True if the push was successful, False if there was an error
            or if index creation failed.
        """
        # Add a date to the index name
        if not no_date and not config.ELASTIC_DISABLE_DATED_INDICES:
            index = f"{index}-{utils.utc_now().strftime('%Y.%m.%d')}"

        if not doc_id:
            doc_id = self.gen_id()

        # NOTE: logging is NOT done here explicitly. On large numbers of
        # doc pushes, it gets extremely spammy, and leads to a massive
        # elasticsearch.log and slows down PEAT noticiably.

        if not self.create_index(index):
            state.error = True
            return False

        body = self.gen_body(content)

        # TODO: add argument "bulk_push", if true, add to a queue
        # once queue reaches 1000 docs, trigger a push
        # need a way to trigger this for pushes with fewer than 1000 docs
        try:
            self.es.index(index=index, body=body, id=doc_id)
        except Exception as err:
            self.log.error(
                f"Failed to push document '{doc_id}' on index '{index}'\n"
                f"Error: {type(err).__name__}\n"
                f"Status code: {getattr(err, 'status_code', '')}\n"
                f"Elastic exception info: {getattr(err, 'info', '')}\n"
                f"Error message: {getattr(err, 'message', str(err.args))}"
            )

            if config.LOG_DIR:
                raw_pth = config.LOG_DIR / "raw-elastic-bad-data.txt"
                fmt_pth = config.LOG_DIR / "formatted-elastic-bad-data.txt"

                utils.write_file(str(body), raw_pth, format_json=False)
                utils.write_file(pformat(body, indent=4), fmt_pth)

                self.log.debug(
                    f"Full dump of bad elastic data is in "
                    f"{raw_pth.as_posix()} and {fmt_pth.as_posix()}"
                )

            self.log.trace(f"Keys: {body.keys()}")
            self.log.trace2(f"** Truncated dump of bad data from '{doc_id}' **\n{str(body)[:500]}")

            state.error = True
            return False

        # Save raw contents of documents for later saving to files
        # TODO: disable this functionality by default or remove it entirely?
        # TODO: make excluded indices configurable
        if (
            config.ELASTIC_DIR
            and config.ELASTIC_LOG_INDEX not in index
            and config.ELASTIC_EVENTS_INDEX not in index
            and config.ELASTIC_MEMORY_INDEX not in index
            and config.ELASTIC_FILES_INDEX not in index
        ):
            doc = {
                "_index": index,
                "_id": doc_id,
                "_source": consts.convert(body),
            }
            # Specify separators reduce amount of whitespace (per the Python docs)
            doc_as_string = json.dumps(doc, separators=(",", ":"))
            self._docs_written[index].add(doc_as_string)

        return True

    @staticmethod
    def bencode(blob: bytes) -> str:
        """
        Encodes bytes into an Elastic-friendly Base64 string.
        """
        return b64encode(blob).decode()

    @staticmethod
    def pickle(obj: dict) -> str:
        """
        Pickle a Python object into an Elastic-friendly Base64 string.
        """
        return Elastic.bencode(pickle.dumps(obj, protocol=4))

    @classmethod
    def convert_tstamp(cls, tstamp: str | datetime.datetime) -> str | None:
        """
        Converts a timestamp into a format compatible with Elasticsearch.
        """
        if isinstance(tstamp, datetime.datetime):
            tstamp = tstamp.isoformat()

        if tstamp.endswith(".000Z"):
            converted = tstamp
        elif "." in tstamp:
            start, end = tstamp.split(".")
            converted = f"{start}.{end[:3]}Z"  # NOTE: 'Z' = "Zulu", aka "Zulu time"
        else:
            converted = f"{tstamp}.000Z"

        if converted == "0.000Z":
            log.warning("ES-converted timestamp is zero ('0.000Z'), returning null value instead")
            return None

        # There was an instance where a timezone snuck in to a doc pushed to elastic...
        # not sure if this is where it came from but doesn't hurt to remove them
        # just in case.
        converted = converted.replace("+00:00.", ".")

        return converted

    @classmethod
    def time_now(cls) -> str | None:
        return cls.convert_tstamp(utils.utc_now())

    @staticmethod
    def gen_id() -> str:
        """
        Generate a unique string used in a document's '_id' field.

        Returns:
            String in the format ``peat~<run-id>~<microsecond>~<random>``,
                where ``<microsecond>`` and ``<random>`` are integers.
        """
        return f"peat~{consts.RUN_ID}~{utils.utc_now().strftime('%f')}~{randint(0, 9999)}"


__all__ = ["Elastic"]
