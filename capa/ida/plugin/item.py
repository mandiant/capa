# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import codecs

import idc
import idaapi
from PyQt5 import QtCore

import capa.ida.helpers


def info_to_name(display):
    """extract root value from display name

    e.g. function(my_function) => my_function
    """
    try:
        return display.split("(")[1].rstrip(")")
    except IndexError:
        return ""


def location_to_hex(location):
    """convert location to hex for display"""
    return "%08X" % location


class CapaExplorerDataItem:
    """store data for CapaExplorerDataModel"""

    def __init__(self, parent, data, can_check=True):
        """initialize item"""
        self.pred = parent
        self._data = data
        self.children = []
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

    def appendChild(self, item):
        """add a new child to specified item

        @param item: CapaExplorerDataItem
        """
        self.children.append(item)

    def child(self, row):
        """get child row

        @param row: row number
        """
        return self.children[row]

    def childCount(self):
        """get child count"""
        return len(self.children)

    def columnCount(self):
        """get column count"""
        return len(self._data)

    def data(self, column):
        """get data at column

        @param: column number
        """
        try:
            return self._data[column]
        except IndexError:
            return None

    def parent(self):
        """get parent"""
        return self.pred

    def row(self):
        """get row location"""
        if self.pred:
            return self.pred.children.index(self)
        return 0

    def setData(self, column, value):
        """set data in column

        @param column: column number
        @value: value to set (assume str)
        """
        self._data[column] = value

    def children(self):
        """yield children"""
        for child in self.children:
            yield child

    def removeChildren(self):
        """remove children"""
        del self.children[:]

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
    def location(self):
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

    def __init__(self, parent, name, namespace, count, source, can_check=True):
        """initialize item

        @param parent: parent node
        @param name: rule name
        @param namespace: rule namespace
        @param count: number of match for this rule
        @param source: rule source (tooltip)
        """
        display = self.fmt % (name, count) if count > 1 else name
        super(CapaExplorerRuleItem, self).__init__(parent, [display, "", namespace], can_check)
        self._source = source

    @property
    def source(self):
        """return rule source to display (tooltip)"""
        return self._source


class CapaExplorerRuleMatchItem(CapaExplorerDataItem):
    """store data for rule match"""

    def __init__(self, parent, display, source=""):
        """initialize item

        @param parent: parent node
        @param display: text to display in UI
        @param source: rule match source to display (tooltip)
        """
        super(CapaExplorerRuleMatchItem, self).__init__(parent, [display, "", ""])
        self._source = source

    @property
    def source(self):
        """return rule contents for display"""
        return self._source


class CapaExplorerFunctionItem(CapaExplorerDataItem):
    """store data for function match"""

    fmt = "function(%s)"

    def __init__(self, parent, location, can_check=True):
        """initialize item

        @param parent: parent node
        @param location: virtual address of function as seen by IDA
        """
        super(CapaExplorerFunctionItem, self).__init__(
            parent, [self.fmt % idaapi.get_name(location), location_to_hex(location), ""], can_check
        )

    @property
    def info(self):
        """return function name"""
        info = super(CapaExplorerFunctionItem, self).info
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

    def __init__(self, parent, scope):
        """initialize item

        @param parent: parent node
        @param scope: subscope name
        """
        super(CapaExplorerSubscopeItem, self).__init__(parent, [self.fmt % scope, "", ""])


class CapaExplorerBlockItem(CapaExplorerDataItem):
    """store data for basic block match"""

    fmt = "basic block(loc_%08X)"

    def __init__(self, parent, location):
        """initialize item

        @param parent: parent node
        @param location: virtual address of basic block as seen by IDA
        """
        super(CapaExplorerBlockItem, self).__init__(parent, [self.fmt % location, location_to_hex(location), ""])


class CapaExplorerDefaultItem(CapaExplorerDataItem):
    """store data for default match e.g. statement (and, or)"""

    def __init__(self, parent, display, details="", location=None):
        """initialize item

        @param parent: parent node
        @param display: text to display in UI
        @param details: text to display in details section of UI
        @param location: virtual address as seen by IDA
        """
        location = location_to_hex(location) if location else ""
        super(CapaExplorerDefaultItem, self).__init__(parent, [display, location, details])


class CapaExplorerFeatureItem(CapaExplorerDataItem):
    """store data for feature match"""

    def __init__(self, parent, display, location="", details=""):
        """initialize item

        @param parent: parent node
        @param display: text to display in UI
        @param details: text to display in details section of UI
        @param location: virtual address as seen by IDA
        """
        location = location_to_hex(location) if location else ""
        super(CapaExplorerFeatureItem, self).__init__(parent, [display, location, details])


class CapaExplorerInstructionViewItem(CapaExplorerFeatureItem):
    """store data for instruction match"""

    def __init__(self, parent, display, location):
        """initialize item

        details section shows disassembly view for match

        @param parent: parent node
        @param display: text to display in UI
        @param location: virtual address as seen by IDA
        """
        details = capa.ida.helpers.get_disasm_line(location)
        super(CapaExplorerInstructionViewItem, self).__init__(parent, display, location=location, details=details)
        self.ida_highlight = idc.get_color(location, idc.CIC_ITEM)


class CapaExplorerByteViewItem(CapaExplorerFeatureItem):
    """store data for byte match"""

    def __init__(self, parent, display, location):
        """initialize item

        details section shows byte preview for match

        @param parent: parent node
        @param display: text to display in UI
        @param location: virtual address as seen by IDA
        """
        byte_snap = idaapi.get_bytes(location, 32)

        details = ""
        if byte_snap:
            byte_snap = codecs.encode(byte_snap, "hex").upper()
            details = " ".join([byte_snap[i : i + 2].decode() for i in range(0, len(byte_snap), 2)])

        super(CapaExplorerByteViewItem, self).__init__(parent, display, location=location, details=details)
        self.ida_highlight = idc.get_color(location, idc.CIC_ITEM)


class CapaExplorerStringViewItem(CapaExplorerFeatureItem):
    """store data for string match"""

    def __init__(self, parent, display, location, value):
        """initialize item

        @param parent: parent node
        @param display: text to display in UI
        @param location: virtual address as seen by IDA
        """
        super(CapaExplorerStringViewItem, self).__init__(parent, display, location=location, details=value)
        self.ida_highlight = idc.get_color(location, idc.CIC_ITEM)
