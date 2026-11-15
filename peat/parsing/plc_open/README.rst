Vendored Beremiz code
=====================

This package contains code from `Beremiz <https://github.com/beremiz/beremiz>`_
(GPLv2, see ``COPYING``), which PEAT uses to convert TC6 XML into
IEC 61131-3 Structured Text.

Upstream version
----------------

`beremiz/beremiz@5e3a749da2297251a9368d3ce2de61619cdf5ce2
<https://github.com/beremiz/beremiz/tree/5e3a749da2297251a9368d3ce2de61619cdf5ce2>`_
(2026-09-22)

File mapping
------------

=======================================  =================================================
Upstream                                 PEAT
=======================================  =================================================
``PLCGenerator.py``                      ``PLCGenerator.py``
``plcopen/__init__.py``                  ``core_modules/__init__.py``
``plcopen/plcopen.py``                   ``core_modules/plcopen.py``
``plcopen/structures.py``                ``core_modules/structures.py``
``plcopen/definitions.py``               ``core_modules/definitions.py``
``plcopen/types_enums.py``               ``core_modules/types_enums.py``
``plcopen/*.xml, *.xsd, iec_std.csv``    ``core_modules/``
``xmlclass/__init__.py``                 ``xml_modules/__init__.py``
``xmlclass/xmlclass.py``                 ``xml_modules/xmlclass.py``
``xmlclass/xsdschema.py``                ``xml_modules/xsdschema.py``
=======================================  =================================================

``PLCControler.py`` is **not** the upstream file. Upstream's ``PLCControler.py``
is the controller for the Beremiz IDE and depends on wxPython and the rest of
Beremiz. PEAT's version is a small subset of it: only the methods that
``PLCGenerator`` calls, plus ``load_project()`` for loading TC6 XML from memory.
When updating, compare those methods against upstream's versions.

``core_modules/_compat.py`` is PEAT-specific. It provides stand-ins for
helpers the vendored code imports from Beremiz's ``util`` package, which is not
vendored.

Local modifications
-------------------

Changes to upstream files are kept as small as possible, and every change is
marked with a ``# PEAT:`` comment. Search for ``PEAT:`` to find them all.

- Imports changed from top-level packages (``plcopen``, ``xmlclass``) to
  relative imports matching PEAT's package layout.
- Resource files are located with :func:`peat.utils.get_resource` instead of
  ``util.paths``, so they are found in PyInstaller builds.
- ``NoTranslate`` is imported from ``_compat`` instead of
  ``util.TranslationCatalogs``.
- ``URI_model`` in ``xml_modules/xmlclass.py`` is rewritten to an equivalent
  regular expression without nested quantifiers, which could backtrack
  exponentially (flagged by CodeQL).
- Beremiz installs gettext's ``_`` as a builtin at startup. PEAT doesn't,
  so modules that use ``_`` at runtime import ``NoTranslate as _``.

How to update
-------------

1. Clone Beremiz and check out the commit to update to.
2. Copy the upstream files over the PEAT files using the mapping above, and
   commit them unmodified so the next commit shows only PEAT's changes.
3. Re-apply the local modifications listed above (the previous update's
   ``# PEAT:`` comments show exactly what changed).
4. Compare the methods in ``PLCControler.py`` with upstream's ``PLCControler.py``.
5. If new resource files are needed, add them to ``distribution/peat.spec`` and
   ``distribution/sneakypeat.spec``.
6. Update the upstream version in this file.
7. Run ``pytest tests/parsing``. If the expected output in
   ``tests/parsing/data_files/beremiz_first_steps_expected.st`` changes, check
   that the change comes from an upstream fix before regenerating it.
