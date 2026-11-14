# SCEPTRE field device config test files

All input XML files are unmodified copies of real configs published by Sandia
National Laboratories under the GNU General Public License v3.0, the same
license as PEAT. The `*_expected_*.json` files are PEAT output generated from
them with `pdm run python tests/generate_test_data_files.py SCEPTRE`.

## sceptre-bennu

- Repository: <https://github.com/sandialabs/sceptre-bennu>
- Commit: [`d0774bbca484c80a469c58200b755417b3dcada8`](https://github.com/sandialabs/sceptre-bennu/tree/d0774bbca484c80a469c58200b755417b3dcada8/data/configs) (2026-10-23)
- License: [GPL-3.0](https://github.com/sandialabs/sceptre-bennu/blob/d0774bbca484c80a469c58200b755417b3dcada8/LICENSE)
- Source directory: `data/configs/` (copied to `bp/` and `ep/` with the same names)

| File | Source path |
| ---- | ----------- |
| `bp/dnp3-client.xml` | `data/configs/bp/dnp3-client.xml` |
| `bp/dnp3-server.xml` | `data/configs/bp/dnp3-server.xml` |
| `bp/modbus-client.xml` | `data/configs/bp/modbus-client.xml` |
| `bp/modbus-server.xml` | `data/configs/bp/modbus-server.xml` |
| `ep/bacnet-client.xml` | `data/configs/ep/bacnet-client.xml` |
| `ep/bacnet-server.xml` | `data/configs/ep/bacnet-server.xml` |
| `ep/dnp3-client.xml` | `data/configs/ep/dnp3-client.xml` |
| `ep/dnp3-server.xml` | `data/configs/ep/dnp3-server.xml` |
| `ep/iec60870-5-104-client.xml` | `data/configs/ep/iec60870-5-104-client.xml` |
| `ep/iec60870-5-104-server.xml` | `data/configs/ep/iec60870-5-104-server.xml` |
| `ep/modbus-client.xml` | `data/configs/ep/modbus-client.xml` |
| `ep/modbus-serial-client.xml` | `data/configs/ep/modbus-serial-client.xml` |
| `ep/modbus-serial-server.xml` | `data/configs/ep/modbus-serial-server.xml` |
| `ep/modbus-server.xml` | `data/configs/ep/modbus-server.xml` |
| `ep/sunspec-server.xml` | `data/configs/ep/sunspec-server.xml` |

`bp/` configs use the older ("legacy") bennu config format, `ep/` configs use
the current format.

## sceptre-phenix-topologies

- Repository: <https://github.com/sandialabs/sceptre-phenix-topologies>
- Commit: [`abc578902be7b9036344c465a6d790f25e7c21c8`](https://github.com/sandialabs/sceptre-phenix-topologies/tree/abc578902be7b9036344c465a6d790f25e7c21c8/soap/injects/override) (2026-10-16)
- License: [GPL-3.0](https://github.com/sandialabs/sceptre-phenix-topologies/blob/abc578902be7b9036344c465a6d790f25e7c21c8/LICENSE)
- Source directory: `soap/injects/override/` (SCEPTRE on a Platter HIL topology RTUs, copied to `phenix-soap/`)

| File | Source path |
| ---- | ----------- |
| `phenix-soap/rtu-1_config.xml` | `soap/injects/override/rtu-1_config.xml` |
| `phenix-soap/rtu-2_config.xml` | `soap/injects/override/rtu-2_config.xml` |
| `phenix-soap/rtu-3_config.xml` | `soap/injects/override/rtu-3_config.xml` |
| `phenix-soap/rtu-4_config.xml` | `soap/injects/override/rtu-4_config.xml` |

`soap-legacy/injects/override/` in the same repository has byte-identical
copies of these four files. No other SCEPTRE field device configs were found
in that repository; the remaining topologies generate theirs at deploy time.
