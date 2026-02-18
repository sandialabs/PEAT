# PEAT quickstart


* **Who is this for?**: For system owners or analysts who want to capture information about OT devices.
* **What does it do?** PEAT can scan, pull, parse, and ingest OT device data either to local files or into a database like Elasticsearch or Malcolm (Opensearch).
* **Where do I use it?** On OT/ICS networks with OT devices like PLC's, relays, RTU's, industrial switches/routers, etc.
* **Why would I use it?** To get detailed information about OT device logic, firmware, configurations or event logs so that you can answer cybersecurity or forensic questions about devices.
* **How do I use it?** See below!

## The basics

### System Requirements

**Linux**
- Ubuntu 14.04 and newer
- Red Hat Enterprise Linux (RHEL): RHEL 6 and newer
- Kali Linux 2018 and newer
- Other distributions: Debian, Debian-based distributions, and RHEL-based distributions (e.g. Fedora and CentOS) should work with the peat executable, but are not regularly tested. It has been known to work under Debian 9.

**Windows**
- Windows 7 SP2 and newer: While Windows 7 has been tested; it’s not regularly tested and support is not maintained. Your Mileage May Vary.
- Windows 10 version 1809 and newer/Windows Server 2019+ (build 17763): fully supported and regularly tested on Windows desktop and server build 17763 and newer. 1703+ may work, but hasn’t been tested in a while.
- Windows 11: fully supported and regularly tested

**MacOS/OSX**
- OSX is supported on a best-effort basis. There are known issues with some networking components when running on OSX, but the majority of functionality should work.

### Usage
- run the peat executable and see detailed instructions with `./peat --help` on Linux. on Windows, you can use the `powershell` console or the `cmd` console to run `./peat.exe --help`.

- get help on specific commands with `--help` or `--examples` after a specific command: `./peat scan --help` or `./peat scan --examples`

- Data will get saved to a `peat_results` folder in your working directory.

- To save results to Elasticsearch or Malcolm (Opensearch) database, you can pass in the `-e` flag like `-e https://username:password@opensearch:9200`. If your're running peat on the same server as your database, it will probably look like: `-e https://username:password@localhost:9200`. It's important to specify whether the database's API is over HTTP or HTTPS, and the login credentials (if any). This will depend on the specific database setup. Ask your database admin for more details.

- PEAT can save data to multiple indices in the database. Not every operation will create data in every index.

| Index name                        | Description                                                                                                                      | Index name `configuration option `                       |
|-----------------------------------|----------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| `peat-logs`                      | PEAT logging events. Useful for knowing exactly what PEAT did.                                                                                                            | `ELASTIC_LOG_INDEX ` |
| `peat-scan-summaries`            | Scan result summaries. Useful for high level understanding of what a scan found.                                                                                                          | `ELASTIC_SCAN_INDEX ` |
| `peat-pull-summaries`            | Pull result summaries. Useful for high level understanding of what a pull found.                                                                                                         | `ELASTIC_PULL_INDEX ` |
| `peat-parse-summaries`           | Parse result summaries. Useful for high level understanding of what parse found.                                                                                                         | `ELASTIC_PARSE_INDEX ` |
| `peat-configs`                   | PEAT configurations. for every PEAT run. useful if you want to exactly recreate a PEAT run.                                                                                                            | `ELASTIC_CONFIG_INDEX ` |
| `peat-state`                      | Dumps of PEAT's internal state during a run. Useful if you want to exactly recreate a PEAT run.                                                                                    | `ELASTIC_STATE_INDEX ` |
| `ot-device-hosts-timeseries`     | Information collected by PEAT from field devices or parsed files. A new Elasticsearch document is created for every pull of data from a device (the data is 'timeseries', with differences visible between pulls over time). | `ELASTIC_HOSTS_INDEX ` |
| `ot-device-registers`            | Information about individual communication 'registers' (e.g. Modbus registers/coils, DNP3 data points, BACNet objects, etc.) that are configured on devices, as extracted from device configuration information. | `ELASTIC_REGISTERS_INDEX ` |
| `ot-device-tags`                 | Information about tag variables that are configured on devices, as extracted from device configuration information.              | `ELASTIC_TAGS_INDEX ` |
| `ot-device-io`                   | Information about I/O (Input/Output) available and/or configured on a device, as extracted from device configuration information. | `ELASTIC_IO_INDEX ` |
| `ot-device-events`               | Logging and other event history as extracted from devices. Examples include access logs, system logs, or protection history.     | `ELASTIC_EVENTS_INDEX ` |
| `ot-device-memory`               | Memory reads from devices, including address in memory, the value read, and information about where it came from and when the read occurred. | `ELASTIC_MEMORY_INDEX ` |

- Binary blobs or large data fields (e.g. firmware images or raw configuration files) are NOT saved to Elasticsearch by default!.
To enable saving of large data, use the --elastic-save-blobs command line argument or the ELASTIC_SAVE_BLOBS configuration option.
- Indices are “split” by date, so a new index is created for each day.
Format:
  - Timestamps are in the UTC timezone, not the host’s timezone.

## What do I do once I get information from PEAT?

- **System understanding**: PEAT results can give very high fidelity information about devices on your network.
- **Device monitoring**: Running PEAT periodically to get data from a device can let you see changes if two PEAT runs differ.
- **Log analysis**: Event logs may contain useful cybersecurity information.
- **Network traffic enrichment**: OT network traffic can refer to registers by numerical ID's which don't tell you much about what the register value is. PEAT information can provide more information about what OT network traffic means.
- **Forensic analysis**: Artifacts like firmware dumps, memory dumps, logic dumps, config dumps, etc. can be analyzed for cybersecurity information.

## What are specific next steps I can take with PEAT data?

- Try creating filters, visualizations, and dashboards in Kibana or Malcolm to answer any specific questions you have that PEAT data may be able to answer.
- Run analytics like Archimedes (another Sandia tool) to search for specific behaviors or properties of interest in PEAT data.

## How can I get help?

Reach out to your Sandia point of contact or e-mail peat@sandia.gov for assistance.
