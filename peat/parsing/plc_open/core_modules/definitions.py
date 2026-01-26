# This file is part of Beremiz, a Integrated Development Environment for
# programming IEC 61131-3 automates supporting plcopen standard and CanFestival.
#
# Copyright (C) 2007: Edouard TISSERANT and Laurent BESSARD
# Copyright (C) 2017: Andrey Skvortsov
#
# See COPYING file for copyrights details.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from peat.utils import get_resource

_ = lambda z:z  # Patch usages of gettext


# -------------------------------------------------------------------------------
#                        Function Block Types definitions
# -------------------------------------------------------------------------------
StdTC6Libs = [
    (_("Standard function blocks"),
     get_resource(__package__, "Standard_Function_Blocks.xml")),
    (_("Additional function blocks"),
     get_resource(__package__, "Additional_Function_Blocks.xml"))
]
StdFuncsCSV = get_resource(__package__, "iec_std.csv")


def GetBlockInfos(pou):
    infos = pou.getblockInfos()
    infos["inputs"] = [
        (var_name, var_type, "rising")
        if var_name in ["CU", "CD"]
        else (var_name, var_type, var_modifier)
        for var_name, var_type, var_modifier in infos["inputs"]]
    return infos


# -------------------------------------------------------------------------------
#                           Data Types definitions
# -------------------------------------------------------------------------------
#: Ordered list of common data types defined in the IEC 61131-3
#: Each type is associated to his direct parent type. It defines then a hierarchy
#: between type that permits to make a comparison of two types
TypeHierarchy_list = [
    ("ANY", None),
    ("ANY_DERIVED", "ANY"),
    ("ANY_ELEMENTARY", "ANY"),
    ("ANY_MAGNITUDE", "ANY_ELEMENTARY"),
    ("ANY_BIT", "ANY_ELEMENTARY"),
    ("ANY_NBIT", "ANY_BIT"),
    ("ANY_STRING", "ANY_ELEMENTARY"),
    ("ANY_DATE", "ANY_ELEMENTARY"),
    ("ANY_NUM", "ANY_MAGNITUDE"),
    ("ANY_REAL", "ANY_NUM"),
    ("ANY_INT", "ANY_NUM"),
    ("ANY_SINT", "ANY_INT"),
    ("ANY_UINT", "ANY_INT"),
    ("BOOL", "ANY_BIT"),
    ("SINT", "ANY_SINT"),
    ("INT", "ANY_SINT"),
    ("DINT", "ANY_SINT"),
    ("LINT", "ANY_SINT"),
    ("USINT", "ANY_UINT"),
    ("UINT", "ANY_UINT"),
    ("UDINT", "ANY_UINT"),
    ("ULINT", "ANY_UINT"),
    ("REAL", "ANY_REAL"),
    ("LREAL", "ANY_REAL"),
    ("TIME", "ANY_MAGNITUDE"),
    ("DATE", "ANY_DATE"),
    ("TOD", "ANY_DATE"),
    ("DT", "ANY_DATE"),
    ("STRING", "ANY_STRING"),
    ("BYTE", "ANY_NBIT"),
    ("WORD", "ANY_NBIT"),
    ("DWORD", "ANY_NBIT"),
    ("LWORD", "ANY_NBIT")
    # ("WSTRING", "ANY_STRING")
]

ANY_TO_ANY_FILTERS = {
    "ANY_TO_ANY": [
        # simple type conv are let as C cast
        (("ANY_INT", "ANY_BIT"), ("ANY_NUM", "ANY_BIT")),
        (("ANY_REAL",), ("ANY_REAL",)),
        # REAL_TO_INT
        (("ANY_REAL",), ("ANY_SINT",)),
        (("ANY_REAL",), ("ANY_UINT",)),
        (("ANY_REAL",), ("ANY_BIT",)),
        # TO_TIME
        (("ANY_INT", "ANY_BIT"), ("ANY_DATE", "TIME")),
        (("ANY_REAL",),          ("ANY_DATE", "TIME")),
        (("ANY_STRING",),        ("ANY_DATE", "TIME")),
        # FROM_TIME
        (("ANY_DATE", "TIME"), ("ANY_REAL",)),
        (("ANY_DATE", "TIME"), ("ANY_INT", "ANY_NBIT")),
        (("TIME",), ("ANY_STRING",)),
        (("DATE",), ("ANY_STRING",)),
        (("TOD",),  ("ANY_STRING",)),
        (("DT",),   ("ANY_STRING",)),
        # TO_STRING
        (("BOOL",),     ("ANY_STRING",)),
        (("ANY_BIT",),  ("ANY_STRING",)),
        (("ANY_REAL",), ("ANY_STRING",)),
        (("ANY_SINT",), ("ANY_STRING",)),
        (("ANY_UINT",), ("ANY_STRING",)),
        # FROM_STRING
        (("ANY_STRING",), ("BOOL",)),
        (("ANY_STRING",), ("ANY_BIT",)),
        (("ANY_STRING",), ("ANY_SINT",)),
        (("ANY_STRING",), ("ANY_UINT",)),
        (("ANY_STRING",), ("ANY_REAL",))
    ],
    "BCD_TO_ANY": [
        (("BYTE",),  ("USINT",)),
        (("WORD",),  ("UINT",)),
        (("DWORD",), ("UDINT",)),
        (("LWORD",), ("ULINT",))
    ],
    "ANY_TO_BCD": [
        (("USINT",), ("BYTE",)),
        (("UINT",),  ("WORD",)),
        (("UDINT",), ("DWORD",)),
        (("ULINT",), ("LWORD",))
    ]
}
