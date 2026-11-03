# Woodward test data

- `tunables_synthetic.tc`: a **synthetic** Control Assistant tunable file, hand-written to
  match the layout PEAT's parser expects (three metadata lines, a `Mode` column header, and
  tab-separated rows). It isn't from a real control, and the block and field names are made
  up, since no public example of a real `.tc` file is available.
- `*.wset`, `*.sid`, and `*.wtool` fixtures are built at test time by `nrbf_builder.py`
  (synthetic .NET serialization streams and ToolKit container headers), or taken from
  `examples/devices/woodward/` (real easYgen-3500 settings files, stored gzip compressed).
