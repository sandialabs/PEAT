# Woodward easYgen-3500 examples

Real settings files saved with Woodward ToolKit from a Woodward easYgen-3500 genset controller
(first generation, non-XT; Operating System v1.2102, Bootloader v3.0011, ToolKit application
`5418-6722-NEW`). Each file holds the complete configuration of the controller for a genset in
a hardware-in-the-loop microgrid test bed.

- `4_MVA_Diesel_20161116.wset.gz`: 4 MVA diesel genset
- `3_5MVA_NGGenset20161116.wset.gz`: 3.5 MVA natural gas genset. It has the same parameters as
  the diesel file, with different values for the engine type (start/stop logic, ignition), the
  ratings, and the load control setpoints.
- `Firmware Version.txt`: firmware versions of the controller

The settings files are stored gzip compressed to keep the repository small (1.9 MB
uncompressed each). They're also used by the unit tests in `tests/modules/woodward/`.

## Usage

```shell
gunzip -k ./examples/devices/woodward/easygen-3500/*.wset.gz
peat parse -d easygen ./examples/devices/woodward/easygen-3500/4_MVA_Diesel_20161116.wset
peat parse -d easygen ./examples/devices/woodward/easygen-3500/3_5MVA_NGGenset20161116.wset
```

## Sources

All files are from the MIT Lincoln Laboratory Electric Power HIL Controls Consortium (EPHCC)
repository, <https://github.com/PowerSystemsHIL/EPHCC>:

- `4_MVA_Diesel_20161116.wset.gz`
  - Path: `Components/TyphoonHIL/genset/Controller Files/4_MVA_Diesel_20161116.wset`
  - SHA-256 (decompressed): `6eda7f571a882b655097b0af0b9fae79855f33464112ab28d1f93131df4f0f33`
- `3_5MVA_NGGenset20161116.wset.gz`
  - Path: `Components/TyphoonHIL/NGgenset/Controller Files/3_5MVA_NGGenset20161116.wset`
  - SHA-256 (decompressed): `ebd6a515e9841d906d49e7740af1a15d8a8f54581e22d18e42559f809ddcf9d8`
- `Firmware Version.txt`
  - Path: `Components/TyphoonHIL/genset/Controller Files/Firmware Version.txt`. The natural
    gas genset's `NGgenset_Firmware_Version.txt` is identical.

All files in this directory are licensed MIT, the license of the EPHCC repository (see
`LICENSE.md`).
