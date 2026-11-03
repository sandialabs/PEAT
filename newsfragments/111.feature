Added parsing of Woodward ToolKit and Control Assistant configuration files, so ``peat parse`` works with the files of easYgen genset controllers (easYgen-3000XT, easYgen-3000, and easYgen-2000 series), the 2301E, and other ToolKit-based Woodward controls:

- ToolKit settings files (``*.wset``): every parameter with its value, default, range, units, enumeration, security levels, and ServLink handle, including LogicsManager equations. 2301E settings files are parsed by the 2301E module, all others by the easYgen module.
- ToolKit Service Interface Definitions (``*.sid``): all data items, LogicsManager equations, enumerations, events, and ServLink security settings.
- ToolKit tool files (``*.wtool``): tool properties, device names, and SID references.
- Control Assistant tunable files (``*.tc``): rewritten parser with encoding detection and typed values. Files of easYgen applications are parsed by the easYgen module, all others by the 2301E module.

Files are identified by their contents. Settings files and SIDs are mapped onto the PEAT data model (registers, tags, I/O, interfaces, services, and users), and LogicsManager equations are converted to Structured Text and PLCopen TC6 XML (``logic.st`` and ``logic-tc6.xml``). Two real easYgen-3500 settings files are included in ``examples/devices/woodward/``, and the file formats are documented on the new Woodward documentation page.
