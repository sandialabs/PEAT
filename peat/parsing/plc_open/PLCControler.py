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

from .PLCGenerator import *
from typing import Optional


class PLCControler:
    """Class which controls the operations made on
    the plcopen model and answers to view requests."""

    def __init__(self):
        self.Project = None
        self.FileName = ""
        self.ProgramChunks = []
        self.ConfNodeTypes = []
        self.TotalTypesDict = StdBlckDct.copy()

    # !! USED BY logic_gen.py !!
    def GenerateProgram(self, filepath: str = None) -> tuple[str, list, list]:
        """
        Generate a ST program from a TC6 XML file.
        OpenXMLFile needs to be called before this.

        Args:
            filepath: Path to the TC6 XML file with the program

        Returns:
            tuple with the generated program string,
            a list of errors that occurred during generation,
            and a list of warnings that occurred during generation.
        """
        errors = []
        warnings = []
        if self.Project is not None:
            try:
                self.ProgramChunks = GenerateCurrentProgram(self, self.Project, errors, warnings)
                program_text = "".join([item[0] for item in self.ProgramChunks])
                if filepath is not None:
                    with open(filepath, 'w') as programfile:
                        programfile.write(program_text.encode('utf-8'))
                return program_text, errors, warnings
            except PLCGenException as e:
                errors.append(str(e))
        else:
            errors.append("No project opened")
        return "", errors, warnings

    # !! USED BY logic_gen.py !!
    def load_project(self, project_xml: bytes) -> str:
        """Load project XML.

        Call this before calling GenerateProgram.

        Args:
            project_xml: TC6 XML string

        Returns:
            Error message"""
        self.Project, error = LoadProjectXML(project_xml)
        if self.Project is None:
            return "Project file syntax error: " + error
        self.ProgramChunks = []
        return error

    @staticmethod
    def ComputeDataTypeName(datatype):
        return "D::%s" % datatype

    @staticmethod
    def ComputePouName(pou):
        return "P::%s" % pou

    @staticmethod
    def ComputePouTransitionName(pou, transition):
        return "T::%s::%s" % (pou, transition)

    @staticmethod
    def ComputePouActionName(pou, action):
        return "A::%s::%s" % (pou, action)

    @staticmethod
    def ComputeConfigurationName(config):
        return "C::%s" % config

    @staticmethod
    def ComputeConfigurationResourceName(config, resource):
        return "R::%s::%s" % (config, resource)

    @staticmethod
    def GetConfigurationExtraVariables():
        return []

    def GetBlockType(self, typename: str, inputs: str = None) -> Optional[dict]:
        """Returns the block definition associated to the block type given"""
        result_blocktype = {}
        for _sectioname, blocktype in self.TotalTypesDict.get(typename, []):
            if inputs is not None and inputs != "undefined":
                block_inputs = tuple(
                    [var_type for _name, var_type, _modifier in blocktype["inputs"]])
                if reduce(lambda x, y: x and y,
                          map(lambda x: x[0] == "ANY" or self.IsOfType(*x),
                              zip(inputs, block_inputs)), True):
                    return blocktype
            else:
                if result_blocktype:
                    if inputs == "undefined":
                        return None
                    else:
                        result_blocktype["inputs"] = [(i[0], "ANY", i[2]) for i in
                                                      result_blocktype["inputs"]]
                        result_blocktype["outputs"] = [(o[0], "ANY", o[2]) for o in
                                                       result_blocktype["outputs"]]
                        return result_blocktype
                result_blocktype = blocktype.copy()
        if result_blocktype:
            return result_blocktype
        blocktype = self.Project.getpou(typename)
        if blocktype is not None:
            blocktype_infos = blocktype.getblockInfos()
            if inputs in [None, "undefined"]:
                return blocktype_infos

            if inputs == tuple([var_type
                                for _name, var_type, _modifier in
                                blocktype_infos["inputs"]]):
                return blocktype_infos
        return None

    def IsOfType(self, typename: str, reference: str) -> bool:
        if reference is None or typename == reference:
            return True

        basetype = TypeHierarchy.get(typename)
        if basetype is not None:
            return self.IsOfType(basetype, reference)

        datatype = self.GetDataType(typename)
        if datatype is not None:
            basetype = self.GetDataTypeBaseType(datatype)
            if basetype is not None:
                return self.IsOfType(basetype, reference)

    def GetDataType(self, typename: str):
        """Return Data Type Object"""
        result = self.Project.getdataType(typename)
        if result is not None:
            return result
        for confnodetype in self.ConfNodeTypes:
            result = confnodetype["types"].getdataType(typename)
            if result is not None:
                return result
        return None

    @staticmethod
    def GetDataTypeBaseType(datatype) -> str:
        """Return Data Type Object Base Type"""
        basetype_content = datatype.baseType.getcontent()
        basetype_content_type = basetype_content.getLocalTag()
        if basetype_content_type in ["array", "subrangeSigned", "subrangeUnsigned"]:
            basetype = basetype_content.baseType.getcontent()
            basetype_type = basetype.getLocalTag()
            return (basetype.getname() if basetype_type == "derived"
                    else basetype_type.upper())
        return (basetype_content.getname() if basetype_content_type == "derived"
                else basetype_content_type.upper())

    def GetBaseType(self, typename: str) -> Optional[str]:
        """Return Base Type of given possible derived type"""
        if typename in TypeHierarchy:
            return typename
        datatype = self.GetDataType(typename)
        if datatype is not None:
            basetype = self.GetDataTypeBaseType(datatype)
            if basetype is not None:
                return self.GetBaseType(basetype)
            return typename
        return None

    def GetDataTypeInfos(self, tagname: str) -> Optional[dict]:
        """Return the data type informations"""
        words = tagname.split("::")
        if words[0] == "D":
            infos = {}
            datatype = self.Project.getdataType(words[1])
            if datatype is None:
                return None
            basetype_content = datatype.baseType.getcontent()
            basetype_content_type = basetype_content.getLocalTag()
            if basetype_content_type in ["subrangeSigned", "subrangeUnsigned"]:
                infos["type"] = "Subrange"
                infos["min"] = basetype_content.range.getlower()
                infos["max"] = basetype_content.range.getupper()
                base_type = basetype_content.baseType.getcontent()
                base_type_type = base_type.getLocalTag()
                infos["base_type"] = (base_type.getname()
                                      if base_type_type == "derived"
                                      else base_type_type)
            elif basetype_content_type == "enum":
                infos["type"] = "Enumerated"
                infos["values"] = []
                for value in basetype_content.xpath("ppx:values/ppx:value",
                                                    namespaces=PLCOpenParser.NSMAP):
                    infos["values"].append(value.getname())
            elif basetype_content_type == "array":
                infos["type"] = "Array"
                infos["dimensions"] = []
                for dimension in basetype_content.getdimension():
                    infos["dimensions"].append((dimension.getlower(), dimension.getupper()))
                base_type = basetype_content.baseType.getcontent()
                base_type_type = base_type.getLocalTag()
                infos["base_type"] = (base_type.getname()
                                      if base_type_type == "derived"
                                      else base_type_type.upper())
            elif basetype_content_type == "struct":
                infos["type"] = "Structure"
                infos["elements"] = []
                for element in basetype_content.getvariable():
                    element_infos = {}
                    element_infos["Name"] = element.getname()
                    element_type = element.type.getcontent()
                    element_type_type = element_type.getLocalTag()
                    if element_type_type == "array":
                        dimensions = []
                        for dimension in element_type.getdimension():
                            dimensions.append((dimension.getlower(), dimension.getupper()))
                        base_type = element_type.baseType.getcontent()
                        base_type_type = base_type.getLocalTag()
                        element_infos["Type"] = ("array",
                                                 base_type.getname()
                                                 if base_type_type == "derived"
                                                 else base_type_type.upper(),
                                                 dimensions)
                    elif element_type_type == "derived":
                        element_infos["Type"] = element_type.getname()
                    else:
                        element_infos["Type"] = element_type_type.upper()
                    if element.initialValue is not None:
                        element_infos["Initial Value"] = element.initialValue.getvalue()
                    else:
                        element_infos["Initial Value"] = ""
                    infos["elements"].append(element_infos)
            else:
                infos["type"] = "Directly"
                infos["base_type"] = (basetype_content.getname()
                                      if basetype_content_type == "derived"
                                      else basetype_content_type.upper())

            if datatype.initialValue is not None:
                infos["initial"] = datatype.initialValue.getvalue()
            else:
                infos["initial"] = ""
            return infos
