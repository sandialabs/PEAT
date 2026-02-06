"""
HEAT protocol extractor for SEL relay Telnet protocol.

Telnet packets in Elasticsearch will have the 'type' field set to 'telnet'.
TCP packets in Elasticsearch will have the 'type' field set to 'TCP'.

Authors

- Walter Weiffenbach
"""

import re

from peat import Interface, config, datastore, log, state, utils

from .heat_classes import HeatArtifact, HeatProtocol, TelnetHeatArtifact


def _cleanup_oui(mac: str) -> str:
    # Older tshark (3.0.14) makes vendor names like "HewlettP_c0:b9:20"
    # Modern tshark (3.2.3) is like "Hewlett Packard"
    if mac.count("_") == 1 and mac.count(":") == 2:
        return mac.split("_", maxsplit=1)[0]
    return mac


class TelnetExtractor(HeatProtocol):
    """
    HEAT protocol extractor for SEL relay Telnet protocol.

    - Step 1: get packet data for each telnet stream
    - Step 2: reconstruct each TCP data stream for each file
    - Step 3: identify commands to indicate the start of a file transfer
    - Step 4: reconstruct each artifact from those byte streams
    - Step 5: parse the artifact
    """

    # CRC table for YMODEM taken from rbsb.c
    # source: https://stuff.mit.edu/afs/sipb/user/paradis/zmodem/rbsb.c
    # table calculated by Mark G. Mendel, Network Systems Corporation
    crctab = [
        0x0000,
        0x1021,
        0x2042,
        0x3063,
        0x4084,
        0x50A5,
        0x60C6,
        0x70E7,
        0x8108,
        0x9129,
        0xA14A,
        0xB16B,
        0xC18C,
        0xD1AD,
        0xE1CE,
        0xF1EF,
        0x1231,
        0x0210,
        0x3273,
        0x2252,
        0x52B5,
        0x4294,
        0x72F7,
        0x62D6,
        0x9339,
        0x8318,
        0xB37B,
        0xA35A,
        0xD3BD,
        0xC39C,
        0xF3FF,
        0xE3DE,
        0x2462,
        0x3443,
        0x0420,
        0x1401,
        0x64E6,
        0x74C7,
        0x44A4,
        0x5485,
        0xA56A,
        0xB54B,
        0x8528,
        0x9509,
        0xE5EE,
        0xF5CF,
        0xC5AC,
        0xD58D,
        0x3653,
        0x2672,
        0x1611,
        0x0630,
        0x76D7,
        0x66F6,
        0x5695,
        0x46B4,
        0xB75B,
        0xA77A,
        0x9719,
        0x8738,
        0xF7DF,
        0xE7FE,
        0xD79D,
        0xC7BC,
        0x48C4,
        0x58E5,
        0x6886,
        0x78A7,
        0x0840,
        0x1861,
        0x2802,
        0x3823,
        0xC9CC,
        0xD9ED,
        0xE98E,
        0xF9AF,
        0x8948,
        0x9969,
        0xA90A,
        0xB92B,
        0x5AF5,
        0x4AD4,
        0x7AB7,
        0x6A96,
        0x1A71,
        0x0A50,
        0x3A33,
        0x2A12,
        0xDBFD,
        0xCBDC,
        0xFBBF,
        0xEB9E,
        0x9B79,
        0x8B58,
        0xBB3B,
        0xAB1A,
        0x6CA6,
        0x7C87,
        0x4CE4,
        0x5CC5,
        0x2C22,
        0x3C03,
        0x0C60,
        0x1C41,
        0xEDAE,
        0xFD8F,
        0xCDEC,
        0xDDCD,
        0xAD2A,
        0xBD0B,
        0x8D68,
        0x9D49,
        0x7E97,
        0x6EB6,
        0x5ED5,
        0x4EF4,
        0x3E13,
        0x2E32,
        0x1E51,
        0x0E70,
        0xFF9F,
        0xEFBE,
        0xDFDD,
        0xCFFC,
        0xBF1B,
        0xAF3A,
        0x9F59,
        0x8F78,
        0x9188,
        0x81A9,
        0xB1CA,
        0xA1EB,
        0xD10C,
        0xC12D,
        0xF14E,
        0xE16F,
        0x1080,
        0x00A1,
        0x30C2,
        0x20E3,
        0x5004,
        0x4025,
        0x7046,
        0x6067,
        0x83B9,
        0x9398,
        0xA3FB,
        0xB3DA,
        0xC33D,
        0xD31C,
        0xE37F,
        0xF35E,
        0x02B1,
        0x1290,
        0x22F3,
        0x32D2,
        0x4235,
        0x5214,
        0x6277,
        0x7256,
        0xB5EA,
        0xA5CB,
        0x95A8,
        0x8589,
        0xF56E,
        0xE54F,
        0xD52C,
        0xC50D,
        0x34E2,
        0x24C3,
        0x14A0,
        0x0481,
        0x7466,
        0x6447,
        0x5424,
        0x4405,
        0xA7DB,
        0xB7FA,
        0x8799,
        0x97B8,
        0xE75F,
        0xF77E,
        0xC71D,
        0xD73C,
        0x26D3,
        0x36F2,
        0x0691,
        0x16B0,
        0x6657,
        0x7676,
        0x4615,
        0x5634,
        0xD94C,
        0xC96D,
        0xF90E,
        0xE92F,
        0x99C8,
        0x89E9,
        0xB98A,
        0xA9AB,
        0x5844,
        0x4865,
        0x7806,
        0x6827,
        0x18C0,
        0x08E1,
        0x3882,
        0x28A3,
        0xCB7D,
        0xDB5C,
        0xEB3F,
        0xFB1E,
        0x8BF9,
        0x9BD8,
        0xABBB,
        0xBB9A,
        0x4A75,
        0x5A54,
        0x6A37,
        0x7A16,
        0x0AF1,
        0x1AD0,
        0x2AB3,
        0x3A92,
        0xFD2E,
        0xED0F,
        0xDD6C,
        0xCD4D,
        0xBDAA,
        0xAD8B,
        0x9DE8,
        0x8DC9,
        0x7C26,
        0x6C07,
        0x5C64,
        0x4C45,
        0x3CA2,
        0x2C83,
        0x1CE0,
        0x0CC1,
        0xEF1F,
        0xFF3E,
        0xCF5D,
        0xDF7C,
        0xAF9B,
        0xBFBA,
        0x8FD9,
        0x9FF8,
        0x6E17,
        0x7E36,
        0x4E55,
        0x5E74,
        0x2E93,
        0x3EB2,
        0x0ED1,
        0x1EF0,
    ]

    def get_data(self) -> None:
        # get packet data

        # build query to get aggregate data
        sources = {"terms": {"field": "source.ip"}}

        streams = {
            "terms": {"field": "tcp.stream"},
            "aggs": {"sources": sources},
        }

        telnet = {"terms": {"field": "type"}, "aggs": {"streams": streams}}

        pcaps = {"terms": {"field": "pcap"}, "aggs": {"telnet": telnet}}

        aggs = {"pcaps": pcaps}

        body = {"size": 0, "aggs": aggs}

        search_args = {"size": 0, "index": "packets-*"}
        search_args["body"] = body

        # get aggregate data to build requests for each packet stream
        aggregates = self.es_obj.raw_search(search_args)

        pcaps = {}

        num_requests = 0

        # build pcaps structure for ease of use later
        for pcap in aggregates["aggregations"]["pcaps"]["buckets"]:
            for protocol in pcap["telnet"]["buckets"]:
                if protocol["key"] == "telnet":
                    streams = {}
                    for stream in protocol["streams"]["buckets"]:
                        sources = []
                        for source in stream["sources"]["buckets"]:
                            sources.insert(0, source["key"])
                            num_requests += 1
                        streams[stream["key"]] = sources
                    pcaps[pcap["key"]] = streams

        log.info(f"Found {num_requests} TELNET streams in Elasticsearch database")

        # dict of packet data for different telnet streams
        data = {}
        i = 0

        # build requests to get the packet data for each telnet stream
        for pcap in pcaps:
            for stream in pcaps[pcap]:
                for source in pcaps[pcap][stream]:
                    query = {
                        "bool": {
                            "must": [
                                {"term": {"pcap": pcap}},
                                {"term": {"type": "telnet"}},
                                {"term": {"tcp.stream": stream}},
                                {"term": {"source.ip": source}},
                                {"exists": {"field": "telnet.data_raw"}},
                            ]
                        }
                    }
                    body = {
                        "query": query,
                        "sort": [{"tcp.sequence": {"unmapped_type": "long"}}],
                    }
                    log.info(
                        f"Searching for TELNET Stream {i} - PCAP: {pcap}, "
                        f"TCP Stream: {stream}, Source IP: {source}"
                    )
                    # get packet data for telnet stream i
                    data[i] = self._search_es(body)
                    # check if query failed and try again
                    if len(data[i]) == 0:
                        log.warning("Query failed - trying again")
                        del data[i]
                        log.info(
                            f"Searching for TELNET Stream {i} - PCAP: {pcap}, "
                            f"TCP Stream: {stream}, Source IP: {source}"
                        )
                        # get packet data for telnet stream i
                        data[i] = self._search_es(body)
                        if len(data[i]) == 0:
                            log.error(f"Elasticsearch query failed: {body}")
                            del data[i]

                    i += 1
        self.elastic_data = data

    def get_list_text(self, data: list | str) -> bytearray:
        text = bytearray()
        if isinstance(data, list):
            for string in data:
                text += bytearray.fromhex(string)
        else:
            text += bytearray.fromhex(data)
        return text

    def _getStream(self, i: int) -> bytearray:
        stream = bytearray()

        # first tcp sequence number for the stream
        next_packet = int(self.elastic_data[i][0]["tcp"]["seq"])

        # read data for each packet into stream variable
        for p in range(len(self.elastic_data[i])):
            packet = self.elastic_data[i][p]
            if int(packet["tcp"]["seq"]) == next_packet:
                try:
                    # read packet hex data as bytes from data_raw list
                    stream += self.get_list_text(packet["telnet"]["data_raw"])
                except ValueError as e:
                    if "data_raw" in packet["telnet"]:
                        log.error(
                            f"Failed to read packet from pcap {packet['pcap']} - "
                            f"data:\tsrc: {packet['source']['ip']}\t"
                            f"TCP stream/sequence number: "
                            f"{packet['tcp']['stream']}/{packet['tcp']['seq']}"
                        )
                    else:
                        raise e
                except KeyError:
                    if "data_raw" in packet["telnet"] and "data" not in packet["telnet"]:
                        log.error("Telnet data not in hex format")
                    else:
                        pass
                except Exception as e:
                    raise e
                next_packet = int(packet["tcp"]["nxtseq"])
        return stream

    def _genArtifact(
        self,
        file_name: str,
        fileData: bytearray,
        selcommand: str,
        startoffset: int,
        stopoffset: int,
        filedirection: str,
        streamid: int,
    ) -> None:
        artifact = TelnetHeatArtifact(
            packets=self.elastic_data[streamid],
            source_ip=self.elastic_data[streamid][0]["source"]["ip"],
            source_mac=self.elastic_data[streamid][0]["source"].get("mac", ""),
            source_oui=_cleanup_oui(self.elastic_data[streamid][0]["source"].get("vendor", "")),
            dest_ip=self.elastic_data[streamid][0]["destination"]["ip"],
            dest_mac=self.elastic_data[streamid][0]["destination"].get("mac", ""),
            dest_oui=_cleanup_oui(self.elastic_data[streamid][0]["destination"].get("vendor", "")),
            start_time=self.start_times[streamid],
            end_time=self.end_times[streamid],
            duration=(self.start_times[streamid] - self.end_times[streamid]).total_seconds(),
            direction=filedirection,
            bytestream=self.bytestreams[streamid],
            start=startoffset,
            stop=stopoffset,
            command=selcommand,
            reconstructed_artifact=fileData.decode("ascii"),
            artifact_file_name=file_name,
        )

        if filedirection == "UPLOAD":
            artifact.device_ip = artifact.dest_ip
            artifact.device_mac = artifact.dest_mac
            artifact.device_oui = artifact.dest_oui

            artifact.station_ip = artifact.source_ip
            artifact.station_mac = artifact.source_mac
            artifact.station_oui = artifact.source_oui
        else:
            artifact.device_ip = artifact.source_ip
            artifact.device_mac = artifact.source_mac
            artifact.device_oui = artifact.source_oui

            artifact.station_ip = artifact.dest_ip
            artifact.station_mac = artifact.dest_mac
            artifact.station_oui = artifact.dest_oui

        self.artifacts.append(artifact)

    def ymodem_crc(self, data: bytearray) -> int:
        """
        CRC calculation derived from prior work by Stephen Satchell, Satchell
        Evaluations and Chuck Forsberg, Omen Technology
        especially Forsberg's 1988 article XMODEM/YMODEM PROTOCOL REFERENCE: A compendium of
        documents describing the XMODEM and YMODEM File Transfer Protocols
        and Satchell's 1986 article regarding updcrc.

        Effectively calculates the CRC for a data block iteratively using the macro
        ``#define updcrc(cp, crc) ( crctab[((crc >> 8) & 255)] ^ (crc << 8) ^ cp)``
        from "rbsb.c"
        """
        crc = 0
        for cp in data:
            # implements crc = updcrc(cp, crc)
            cc = 0xFF & cp
            tmp = (crc >> 8) ^ cc
            crc = (crc << 8) ^ self.crctab[tmp & 0xFF]
            crc = crc & 0xFFFF
        return crc

    def parseStream(self, stream: bytearray, streamid: int) -> None:
        fileReadRegex = re.compile(r"File? Read [!-~]*\.[a-zA-Z]{3,4}\r\n")
        fileWriteRegex = re.compile(r"File? Write [!-~]*\.[a-zA-Z]{3,4}\r\x01")
        direction = "UNKNOWN"
        mode = "TELNET"
        selcommand = ""
        i = 0

        # operates in two modes: TELNET SEL Ascii and YMODEM file transfers
        while i < len(stream):
            # Telnet mode
            if mode == "TELNET":
                command = ""
                j = 0
                # search for telnet commands
                # This is slightly broken right now because \r\n is not the ending for echoed
                #  commands, which we need to detect uploads
                # fortunately the regex helps address this for UPLOADS in
                #  the if/else block below by resetting the index appropriately
                while command[-2:] != "\r\n":
                    if i + j >= len(stream):
                        break
                    try:
                        command += bytes([stream[i + j]]).decode()
                    except UnicodeDecodeError:
                        command += "\ufffd"
                    j += 1
                i += j

                # if it is a file transfer command
                readMatch = fileReadRegex.search(command)
                writeMatch = fileWriteRegex.search(command)

                # bad xor, but having both match on one command is undefined behavior
                if readMatch or (writeMatch and not (readMatch and writeMatch)):
                    if readMatch and not writeMatch:
                        direction = "DOWNLOAD"
                        selcommand = command[readMatch.span()[0] : readMatch.span()[1]]
                    else:
                        direction = "UPLOAD"
                        selcommand = command[writeMatch.span()[0] : writeMatch.span()[1]]
                        i -= j
                        i += writeMatch.span()[1]
                        # reset index to be at the carriage return so that YMODEM
                        # starts processing from the SOH character
                        i -= 2
                    # change modes to YMODEM
                    mode = "YMODEM"

            # YMODEM MODE
            elif mode == "YMODEM":
                """
                YMODEM Protocol Spec:

                Each block begins with <SOH> (or <STX>, which is SEL custom, I think),
                afterwhich is the block ID and it's 1's complement

                Then there is either 128 bytes or 1024 bytes of data (it can dynamically switch
                 between them, <STX> prefixes 1024 byte blocks and <SOH> does 128)

                Afterwards, there is 1 or 2 error detection bytes. CRC 16 uses 2 bytes.
                 Arithmetic checksum uses 1 byte.

                There is negotiation over whether to use CRC or not (the <C> character), this
                 implementation only supports CRC because that is
                what SEL uses by default, though it is possible the negotiation could fail and
                 this parser would be invalid, though this is
                extremely unlikely on modern systems

                CRC Option:
                Taken directly from Chuck Forsberg's XMODEM/YMODEM PROTOCOL REFERENCE
                http://pauillac.inria.fr/~doligez/zmodem/ymodem.txt

                SENDER                                       RECEIVER
                                        <---                 <C>
                <soh> 01 FE -data- <xxxx> --->
                                        <---                 <ack>
                <soh> 02 FD -data- <xxxx> --->         (data gets line hit)
                                        <---                 <nak>
                <soh> 02 FD -data- <xxxx> --->
                                        <---                 <ack>
                <soh> 03 FC -data- <xxxx> --->
                (ack gets garbaged)       <---                 <ack>
                                                    times out after 10 seconds,
                                        <---                 <nak>
                <soh> 03 FC -data- <xxxx> --->
                                        <---                 <ack>
                <eot>                     --->
                                        <---                 <ack>



                Sender does not support CRC, uses arithmetic checksum:

                SENDER                                        RECEIVER
                                        <---                <C>
                                                times out after 3 seconds,
                                        <---                <C>
                                                times out after 3 seconds,
                                        <---                <C>
                                                times out after 3 seconds,
                                        <---                <C>
                                                times out after 3 seconds,
                                        <---                <nak>
                <soh> 01 FE -data- <xx> --->
                                        <---                <ack>
                <soh> 02 FD -data- <xx> --->        (data gets line hit)
                                        <---                <nak>
                <soh> 02 FD -data- <xx> --->
                                        <---                <ack>
                <soh> 03 FC -data- <xx> --->
                (ack gets garbaged)  <---                <ack>
                                                times out after 10 seconds,
                                        <---                <nak>
                <soh> 03 FC -data- <xx> --->
                                        <---                <ack>
                <eot>                   --->
                                        <---                <ack>
                """
                if direction == "DOWNLOAD":
                    # ignore "#000 Ready to send file"
                    i += 25

                # SEL by default tries to use CRC option YMODEM
                # TODO: support fallback to default YMODEM and arithmetic checksum
                fileData = bytearray()
                dataBlocks = {}
                numReadBlocks = b"\x00"
                startoffset = i

                # read all blocks
                while mode == "YMODEM":
                    # block starts with <SOH>=b'\x01' for 128 bytes
                    # but <STX>=b'\x02' for 1024 bytes
                    # this is hypothesized since it is nonstandard
                    blockLength = bytes([stream[i]])
                    if blockLength not in {b"\x01", b"\x02"}:
                        log.warning(
                            f"Block header does not match spec - "
                            f"skipping file with command {selcommand}"
                        )
                        mode = "TELNET"
                        break

                    # read block
                    blockID = bytes([stream[i + 1]])
                    # 0xff is encoded as 0xffff by SEL's ascii protocol for command specification
                    # so it has no bearing on the YMODEM transfer
                    if blockID == b"\xff":
                        i += 1
                    block1sComp = bytes([stream[i + 2]])
                    # 0xff is encoded as 0xffff by SEL's ascii protocol for command specification
                    # so it has no bearing on the YMODEM transfer
                    if block1sComp == b"\xff":
                        i += 1
                    i += 3
                    if int(block1sComp.hex(), 16) != 255 - int(blockID.hex(), 16):
                        log.warning(
                            f"Block ID does not match 1's Complement - "
                            f"BlockID: 0x{blockID.hex()}"
                            f"\t 1sComplement: 0x{block1sComp.hex()}"
                        )
                    if blockID.hex() != numReadBlocks.hex():
                        log.warning(
                            f"Block ID is out of order - Expected 0x{numReadBlocks.hex()} "
                            f"but got 0x{blockID.hex()} instead"
                        )
                    data = bytearray()
                    # since the start byte varries by length
                    #  (but not in YMODEM spec...) we know how many bytes to read
                    size = 128
                    if blockLength == b"\x02":
                        size = 1024
                    # read data bytes
                    for j in range(size):
                        data.append(stream[i + j])
                    i += j + 1
                    # after reading 128 bytes or 1024 bytes, get the CRC
                    crc = 0
                    crc += stream[i] << 8
                    # 0xff is encoded as 0xffff by SEL's ascii protocol for command specification
                    # so it has no bearing on the YMODEM transfer
                    if bytes([stream[i]]) == b"\xff":
                        i += 1
                    crc += stream[i + 1]
                    # 0xff is encoded as 0xffff by SEL's ascii protocol for command specification
                    # so it has no bearing on the YMODEM transfer
                    if bytes([stream[i + 1]]) == b"\xff":
                        i += 1
                    i += 2

                    # verify CRC is correct
                    calc_crc = self.ymodem_crc(data)
                    if calc_crc != crc:
                        log.warning(
                            f"CRC16 obtained from transmissiom ({crc}) does not "
                            f"match calculated CRC16 ({calc_crc}) on YMODEM "
                            f"chunk {blockID}. Expecting next chunk to resend this chunk..."
                        )
                        continue

                    endByte = bytes([stream[i]])
                    dataBlocks[blockID] = data
                    numReadBlocks = bytes([int(numReadBlocks.hex(), 16) + 1])

                    # if we are at the end of transmission
                    if endByte == b"\x04":
                        fileName = ""
                        mode = "TELNET"

                        # assemble the file
                        for blk_id, b_data in dataBlocks:
                            if blk_id == b"\x00":
                                for c in range(len(b_data)):
                                    if bytes([b_data[c]]) == b"\x00":
                                        break
                                    fileName += bytes([b_data[c]]).decode("ascii")
                            else:
                                fileData.extend(b_data.rstrip(b"\x00").rstrip(b"\x1a"))

                        dataBlocks = {}  # reset dict

                        # generate the artifact
                        self._genArtifact(
                            fileName,
                            fileData,
                            selcommand,
                            startoffset,
                            i,
                            direction,
                            streamid,
                        )

            i += 1

    def extract_blocks(self) -> None:
        """extract bytes into ``self.artifacts``."""
        # extract byte stream from telnet packet data
        self.bytestreams = dict(bytearray())
        self.blocks = {}
        self.command = {}
        self.direction = {}
        self.files = {}
        self.start_times = {}
        self.end_times = {}

        # for each telnet stream
        for i in range(len(self.elastic_data)):
            self.start_times[i] = utils.parse_date(self.elastic_data[i][0]["@timestamp"], False)
            self.end_times[i] = utils.parse_date(self.elastic_data[i][-1]["@timestamp"], False)

            # build byte stream from packet data
            stream = self._getStream(i)

            # save byte data
            self.bytestreams[i] = stream  # .encode()

            before = len(self.artifacts)

            self.parseStream(self.bytestreams[i], i)

            log.info(f"Found {len(self.artifacts) - before} artifacts in stream {i}")

    def assemble_artifacts(self) -> None:
        for artifact in self.artifacts:
            start = artifact.start_time.strftime("%Y-%m-%d_%H-%M-%S")
            artifact.file_name = (
                f"{artifact.source_ip}_{artifact.dest_ip}_"
                f"{artifact.direction}_{artifact.artifact_file_name}_"
                f"{start}+{int(artifact.duration)}_"
                f"[{artifact.start}:{artifact.stop}] \
                    {artifact.artifact_file_name[artifact.artifact_file_name.index('.') :]}"
            )
            artifact.file_name = str.replace(artifact.file_name, ":", "_")

    def export_artifacts(self) -> None:
        log.info(f"Exporting {len(self.artifacts)} artifacts...")
        for artifact in self.artifacts:
            log.info(f"[{artifact.id} Exporting to {artifact.file_name}")
            artifact.file_path = config.HEAT_ARTIFACTS_DIR / artifact.file_name
            utils.write_file(
                artifact.reconstructed_artifact,
                artifact.file_path,
                overwrite_existing=False,
            )

    def parse_artifacts(self) -> None:
        log.info(f"Parsing {len(self.artifacts)} artifacts using PEAT...")
        # Don't lookup IPs in host's DNS, pointless and can leak information
        config.RESOLVE_HOSTNAME = False
        config.RESOLVE_IP = False
        config.RESOLVE_MAC = False
        txtRegex = re.compile(r".*\.(txt|TXT)")

        for artifact in self.artifacts:
            if txtRegex.search(artifact.artifact_file_name):
                self._parse_artifact(artifact)
            else:
                ext = artifact.artifact_file_name[artifact.artifact_file_name.index(".") :]
                log.warning(
                    f"Unable to parse file with unsupported extension "
                    f"{ext}: {artifact.artifact_file_name}"
                )

    def _parse_artifact(self, artifact: HeatArtifact) -> None:
        log.info(f"Parsing artifact {artifact.id}")

        # Device (the relay)
        # NOTE: it's possible to have multiple project files for same IP!
        #   Therefore, we use .add() instead of .get() to avoid annotating
        #   the same DataManager object.
        dev = datastore.create(artifact.device_ip, "ip")
        dev._is_verified = True
        device_iface = Interface(
            type="ethernet",
            mac=artifact.device_mac,
            ip=artifact.device_ip,
        )
        dev.store("interface", device_iface)
        dev.populate_fields()

        # Do this so SELRelay isn't required for basic artifact extraction
        from peat import SELRelay

        try:
            if config.HEAT_ARTIFACTS_DIR and artifact.file_path:
                SELRelay.parse(to_parse=artifact.file_path, dev=dev)
            else:
                SELRelay.parse(to_parse=artifact.reconstructed_artifact, dev=dev)
        except Exception:
            log.exception(
                f"[{artifact.id}] Failed to parse artifact due to an unhandled exception"
            )
            state.error = True
        dev.related.ip.add(artifact.station_ip)
        if dev.logic.author:
            dev.related.user.add(dev.logic.author)
        SELRelay.update_dev(dev)

        # The Station which programs the device
        # Generally a Engineering Workstation or a SCADA system
        # TODO: merge data for station (use datastore.get()),
        #   since it's likely the same device?
        station = datastore.create(artifact.station_ip, "ip")
        station_iface = Interface(
            type="ethernet",
            mac=artifact.station_mac,
            ip=artifact.station_ip,
        )
        station.store("interface", station_iface)
        # TODO: set station vendor ID to the short manuf string
        #   (e.g. "Dell" instead of "Dell, Inc.")
        station.description.vendor.name = artifact.station_oui
        station.description.description = (
            f"Host that programmed the device at {artifact.device_ip}. "
            f"Likely a engineering workstation or SCADA server."
        )
        station.type = "PC"
        station.related.ip.add(artifact.device_ip)
        if dev.logic.author:
            station.related.user.add(dev.logic.author)
        station.populate_fields()
        if config.DEVICE_DIR:
            station.export_to_files()
        # TODO: "heat_results" file with all results, keyed by file?

        # Export parsed data to Elasticsearch
        if state.elastic:
            dev.export_to_elastic()
            station.export_to_elastic()
