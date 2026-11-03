# Woodward easYgen-3500 ToolKit settings file examples

Two real settings files saved with Woodward ToolKit from a Woodward easYgen 3500 genset
controller (first generation, non-XT; Operating System v1.2102, Bootloader v3.0011, ToolKit
application `5418-6722-NEW`). Each holds the complete configuration of the controller for a
genset in a hardware-in-the-loop microgrid test bed:

- `4_MVA_Diesel_20161116.wset.gz`: a 4 MVA diesel genset.
- `3_5MVA_NGGenset20161116.wset.gz`: a 3.5 MVA natural gas genset. It has the same
  parameters as the diesel file, with different values for the engine type (start/stop
  logic, ignition), the ratings, and the load control setpoints.

The files and `Firmware Version.txt` are from the MIT Lincoln Laboratory Electric Power HIL
Controls Consortium (EPHCC) repository, where they are published under the MIT license
(see `LICENSE.md`, which covers all of the files in this directory):

- Repository: <https://github.com/PowerSystemsHIL/EPHCC>
- `4_MVA_Diesel_20161116.wset.gz`
  - Path: `Components/TyphoonHIL/genset/Controller Files/4_MVA_Diesel_20161116.wset`
  - SHA-256 (decompressed): `6eda7f571a882b655097b0af0b9fae79855f33464112ab28d1f93131df4f0f33`
- `3_5MVA_NGGenset20161116.wset.gz`
  - Path: `Components/TyphoonHIL/NGgenset/Controller Files/3_5MVA_NGGenset20161116.wset`
  - SHA-256 (decompressed): `ebd6a515e9841d906d49e7740af1a15d8a8f54581e22d18e42559f809ddcf9d8`
- `Firmware Version.txt`: from `Components/TyphoonHIL/genset/Controller Files/`. The
  natural gas genset's `NGgenset_Firmware_Version.txt` is identical.

The files are stored gzip compressed to keep the repository small (1.9 MB uncompressed each).
Decompress them, then parse them with PEAT:

```shell
gunzip -k ./examples/devices/woodward/easygen-3500/*.wset.gz
peat parse -d easygen ./examples/devices/woodward/easygen-3500/4_MVA_Diesel_20161116.wset
peat parse -d easygen ./examples/devices/woodward/easygen-3500/3_5MVA_NGGenset20161116.wset
```

The files are also used by the unit tests in `tests/modules/woodward/`.
