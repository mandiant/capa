# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import codecs
from typing import List, Iterator, Optional

import idc
import idaapi
from PyQt5 import QtCore

import capa.ida.helpers
from capa.features.address import Address, FileOffsetAddress, AbsoluteVirtualAddress


def info_to_name(display):
    """extract root value from display name

    e.g. function(my_function) => my_function
    """
    try:
        return display.split("(")[1].rstrip(")")
    except IndexError:
        return ""


def ea_to_hex(ea):
    """convert effective address (ea) to hex for display"""
    return f"{hex(ea)}"


class CapaExplorerDataItem:
    """store data for CapaExplorerDataModel"""

    def __init__(self, parent: Optional["CapaExplorerDataItem"], data: List[str], can_check=True):
        """initialize item"""
        self.pred = parent
        self._data = data
        self._children: List["CapaExplorerDataItem"] = []
        self._checked = False
        self._can_check = can_check

        # default state for item
        self.flags = QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable

        if self._can_check:
            self.flags = self.flags | QtCore.Qt.ItemIsUserCheckable | QtCore.Qt.ItemIsTristate

        if self.pred:
            self.pred.appendChild(self)

    def setIsEditable(self, isEditable=False):
        """modify item editable flags

        @param isEditable: True, can edit, False cannot edit
        """
        if isEditable:
            self.flags |= QtCore.Qt.ItemIsEditable
        else:
            self.flags &= ~QtCore.Qt.ItemIsEditable

    def setChecked(self, checked):
        """set item as checked

        @param checked: True, item checked, False item not checked
        """
        self._checked = checked

    def canCheck(self):
        """ """
        return self._can_check

    def isChecked(self):
        """get item is checked"""
        return self._checked

    def appendChild(self, item: "CapaExplorerDataItem"):
        """add a new child to specified item

        @param item: CapaExplorerDataItem
        """
        self._children.append(item)

    def child(self, row: int) -> "CapaExplorerDataItem":
        """get child row

        @param row: row number
        """
        return self._children[row]

    def childCount(self) -> int:
        """get child count"""
        return len(self._children)

    def columnCount(self) -> int:
        """get column count"""
        return len(self._data)

    def data(self, column: int) -> Optional[str]:
        """get data at column

        @param: column number
        """
        try:
            return self._data[column]
        except IndexError:
            return None

    def parent(self) -> Optional["CapaExplorerDataItem"]:
        """get parent"""
        return self.pred

    def row(self) -> int:
        """get row location"""
        if self.pred:
            return self.pred._children.index(self)
        return 0

    def setData(self, column: int, value: str):
        """set data in column

        @param column: column number
        @value: value to set (assume str)
        """
        self._data[column] = value

    def children(self) -> Iterator["CapaExplorerDataItem"]:
        """yield children"""
        for child in self._children:
            yield child

    def removeChildren(self):
        """remove children"""
        del self._children[:]

    def __str__(self):
        """get string representation of columns

        used for copy-n-paste operations
        """
        return " ".join([data for data in self._data if data])

    @property
    def info(self):
        """return data stored in information column"""
        return self._data[0]

    @property
    def location(self) -> Optional[int]:
        """return data stored in location column"""
        try:
            # address stored as str, convert to int before return
            return int(self._data[1], 16)
        except ValueError:
            return None

    @property
    def details(self):
        """return data stored in details column"""
        return self._data[2]


class CapaExplorerRuleItem(CapaExplorerDataItem):
    """store data for rule result"""

    fmt = "%s (%d matches)"

    def __init__(
        self, parent: CapaExplorerDataItem, name: str, namespace: str, count: int, source: str, can_check=True
    ):
        """initialize item

        @param parent: parent node
        @param name: rule name
        @param namespace: rule namespace
        @param count: number of match for this rule
        @param source: rule source (tooltip)
        """
        display = self.fmt % (name, count) if count > 1 else name
        super().__init__(parent, [display, "", namespace], can_check)
        self._source = source

    @property
    def source(self):
        """return rule source to display (tooltip)"""
        return self._source


class CapaExplorerRuleMatchItem(CapaExplorerDataItem):
    """store data for rule match"""

    def __init__(self, parent: CapaExplorerDataItem, display: str, source=""):
        """initialize item

        @param parent: parent node
        @param display: text to display in UI
        @param source: rule match source to display (tooltip)
        """
        super().__init__(parent, [display, "", ""])
        self._source = source

    @property
    def source(self):
        """return rule contents for display"""
        return self._source


class CapaExplorerFunctionItem(CapaExplorerDataItem):
    """store data for function match"""

    fmt = "function(%s)"

    def __init__(self, parent: CapaExplorerDataItem, location: Address, can_check=True):
        """initialize item

        @param parent: parent node
        @param location: virtual address of function as seen by IDA
        """
        assert isinstance(location, AbsoluteVirtualAddress)
        ea = int(location)
        super().__init__(parent, [self.fmt % idaapi.get_name(ea), ea_to_hex(ea), ""], can_check)

    @property
    def info(self):
        """return function name"""
        info = super().info
        display = info_to_name(info)
        return display if display else info

    @info.setter
    def info(self, display):
        """set function name

        called when user changes function name in plugin UI

        @param display: new function name to display
        """
        self._data[0] = self.fmt % display


class CapaExplorerSubscopeItem(CapaExplorerDataItem):
    """store data for subscope match"""

    fmt = "subscope(%s)"

    def __init__(self, parent: CapaExplorerDataItem, scope):
        """initialize item

        @param parent: parent node
        @param scope: subscope name
        """
        super().__init__(parent, [self.fmt % scope, "", ""])


class CapaExplorerBlockItem(CapaExplorerDataItem):
    """store data for basic block match"""

    fmt = "basic block(loc_%08X)"

    def __init__(self, parent: CapaExplorerDataItem, location: Address):
        """initialize item

        @param parent: parent node
        @param location: virtual address of basic block as seen by IDA
        """
        assert isinstance(location, AbsoluteVirtualAddress)
        ea = int(location)
        super().__init__(parent, [self.fmt % ea, ea_to_hex(ea), ""])


class CapaExplorerInstructionItem(CapaExplorerBlockItem):
    """store data for instruction match"""

    fmt = "instruction(loc_%08X)"


class CapaExplorerDefaultItem(CapaExplorerDataItem):
    """store data for default match e.g. statement (and, or)"""

    def __init__(
        self, parent: CapaExplorerDataItem, display: str, details: str = "", location: Optional[Address] = None
    ):
        """initialize item

        @param parent: parent node
        @param display: text to display in UI
        @param details: text to display in details section of UI
        @param location: virtual address as seen by IDA
        """
        ea = None
        if location:
            assert isinstance(location, AbsoluteVirtualAddress)
            ea = int(location)

        super().__init__(parent, [display, ea_to_hex(ea) if ea is not None else "", details])


class CapaExplorerFeatureItem(CapaExplorerDataItem):
    """store data for feature match"""

    def __init__(
        self, parent: CapaExplorerDataItem, display: str, location: Optional[Address] = None, details: str = ""
    ):
        """initialize item

        @param parent: parent node
        @param display: text to display in UI
        @param details: text to display in details section of UI
        @param location: virtual address as seen by IDA
        """
        if location:
            assert isinstance(location, (AbsoluteVirtualAddress, FileOffsetAddress))
            ea = int(location)
            super().__init__(parent, [display, ea_to_hex(ea), details])
        else:
            super().__init__(parent, [display, "", details])


class CapaExplorerInstructionViewItem(CapaExplorerFeatureItem):
    """store data for instruction match"""

    def __init__(self, parent: CapaExplorerDataItem, display: str, location: Address):
        """initialize item

        details section shows disassembly view for match

        @param parent: parent node
        @param display: text to display in UI
        @param location: virtual address as seen by IDA
        """
        assert isinstance(location, AbsoluteVirtualAddress)
        ea = int(location)
        details = capa.ida.helpers.get_disasm_line(ea)
        super().__init__(parent, display, location=location, details=details)
        self.ida_highlight = idc.get_color(ea, idc.CIC_ITEM)


class CapaExplorerByteViewItem(CapaExplorerFeatureItem):
    """store data for byte match"""

    def __init__(self, parent: CapaExplorerDataItem, display: str, location: Address):
        """initialize item

        details section shows byte preview for match

        @param parent: parent node
        @param display: text to display in UI
        @param location: virtual address as seen by IDA
        """
        assert isinstance(location, (AbsoluteVirtualAddress, FileOffsetAddress))
        ea = int(location)

        byte_snap = idaapi.get_bytes(ea, 32)

        details = ""
        if byte_snap:
            byte_snap = codecs.encode(byte_snap, "hex").upper()
            details = " ".join([byte_snap[i : i + 2].decode() for i in range(0, len(byte_snap), 2)])

        super().__init__(parent, display, location=location, details=details)
        self.ida_highlight = idc.get_color(ea, idc.CIC_ITEM)


class CapaExplorerStringViewItem(CapaExplorerFeatureItem):
    """store data for string match"""

    def __init__(self, parent: CapaExplorerDataItem, display: str, location: Address, value: str):
        """initialize item

        @param parent: parent node
        @param display: text to display in UI
        @param location: virtual address as seen by IDA
        """
        assert isinstance(location, (AbsoluteVirtualAddress, FileOffsetAddress))
        ea = int(location)

        super().__init__(parent, display, location=location, details=value)
        self.ida_highlight = idc.get_color(ea, idc.CIC_ITEM)
