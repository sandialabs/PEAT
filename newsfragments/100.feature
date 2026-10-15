Make the Structured Text logic generated for Schneider M340 devices compile in OpenPLC v3 and OpenPLC v4.
INT I/O variables are now located at 16-bit memory words (``%MW``) instead of double words (``%MD``), which MatIEC rejected, and they keep their INT type instead of being converted to REAL.
BOOL I/O variable bit indexes now roll over to the next byte (``%QX1.0``) instead of going past ``%QX0.7``.
The ``sceptre_plc_compatible_st_logic`` option was renamed to ``openplc_compatible_st_logic``, and the ``sceptre`` argument of :meth:`~peat.parsing.tc6.TC6.generate_xml_string` and :meth:`~peat.parsing.tc6.TC6.generate_st` was renamed to ``openplc``.
