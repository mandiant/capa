# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import sys
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
    """ convert location to hex for display """
    return "%08X" % location


class CapaExplorerDataItem(object):
    """ store data for CapaExplorerDataModel """

    def __init__(self, parent, data):
        """ """
        self.pred = parent
        self._data = data
        self.children = []
        self._checked = False

        self.flags = (
            QtCore.Qt.ItemIsEnabled
            | QtCore.Qt.ItemIsSelectable
            | QtCore.Qt.ItemIsTristate
            | QtCore.Qt.ItemIsUserCheckable
        )

        if self.pred:
            self.pred.appendChild(self)

    def setIsEditable(self, isEditable=False):
        """ modify item flags to be editable or not """
        if isEditable:
            self.flags |= QtCore.Qt.ItemIsEditable
        else:
            self.flags &= ~QtCore.Qt.ItemIsEditable

    def setChecked(self, checked):
        """ set item as checked """
        self._checked = checked

    def isChecked(self):
        """ get item is checked """
        return self._checked

    def appendChild(self, item):
        """add child item

        @param item: CapaExplorerDataItem*
        """
        self.children.append(item)

    def child(self, row):
        """get child row

        @param row: TODO
        """
        return self.children[row]

    def childCount(self):
        """ get child count """
        return len(self.children)

    def columnCount(self):
        """ get column count """
        return len(self._data)

    def data(self, column):
        """ get data at column """
        try:
            return self._data[column]
        except IndexError:
            return None

    def parent(self):
        """ get parent """
        return self.pred

    def row(self):
        """ get row location """
        if self.pred:
            return self.pred.children.index(self)
        return 0

    def setData(self, column, value):
        """ set data in column """
        self._data[column] = value

    def children(self):
        """ yield children """
        for child in self.children:
            yield child

    def removeChildren(self):
        """ remove children from node """
        del self.children[:]

    def __str__(self):
        """ get string representation of columns """
        return " ".join([data for data in self._data if data])

    @property
    def info(self):
        """ return data stored in information column """
        return self._data[0]

    @property
    def location(self):
        """ return data stored in location column """
        try:
            return int(self._data[1], 16)
        except ValueError:
            return None

    @property
    def details(self):
        """ return data stored in details column """
        return self._data[2]


class CapaExplorerRuleItem(CapaExplorerDataItem):
    """ store data relevant to capa function result """

    fmt = "%s (%d matches)"

    def __init__(self, parent, display, count, source):
        """ """
        display = self.fmt % (display, count) if count > 1 else display
        super(CapaExplorerRuleItem, self).__init__(parent, [display, "", ""])
        self._source = source

    @property
    def source(self):
        """ return rule contents for display """
        return self._source


class CapaExplorerRuleMatchItem(CapaExplorerDataItem):
    """ store data relevant to capa function match result """

    def __init__(self, parent, display, source=""):
        """ """
        super(CapaExplorerRuleMatchItem, self).__init__(parent, [display, "", ""])
        self._source = source

    @property
    def source(self):
        """ return rule contents for display """
        return self._source


class CapaExplorerFunctionItem(CapaExplorerDataItem):
    """ store data relevant to capa function result """

    fmt = "function(%s)"

    def __init__(self, parent, location):
        """ """
        super(CapaExplorerFunctionItem, self).__init__(
            parent, [self.fmt % idaapi.get_name(location), location_to_hex(location), ""]
        )

    @property
    def info(self):
        """ """
        info = super(CapaExplorerFunctionItem, self).info
        display = info_to_name(info)
        return display if display else info

    @info.setter
    def info(self, display):
        """ """
        self._data[0] = self.fmt % display


class CapaExplorerSubscopeItem(CapaExplorerDataItem):
    """ store data relevant to subscope """

    fmt = "subscope(%s)"

    def __init__(self, parent, scope):
        """ """
        super(CapaExplorerSubscopeItem, self).__init__(parent, [self.fmt % scope, "", ""])


class CapaExplorerBlockItem(CapaExplorerDataItem):
    """ store data relevant to capa basic block result """

    fmt = "basic block(loc_%08X)"

    def __init__(self, parent, location):
        """ """
        super(CapaExplorerBlockItem, self).__init__(parent, [self.fmt % location, location_to_hex(location), ""])


class CapaExplorerDefaultItem(CapaExplorerDataItem):
    """ store data relevant to capa default result """

    def __init__(self, parent, display, details="", location=None):
        """ """
        location = location_to_hex(location) if location else ""
        super(CapaExplorerDefaultItem, self).__init__(parent, [display, location, details])


class CapaExplorerFeatureItem(CapaExplorerDataItem):
    """ store data relevant to capa feature result """

    def __init__(self, parent, display, location="", details=""):
        """ """
        location = location_to_hex(location) if location else ""
        super(CapaExplorerFeatureItem, self).__init__(parent, [display, location, details])


class CapaExplorerInstructionViewItem(CapaExplorerFeatureItem):
    """ store data relevant to an instruction preview """

    def __init__(self, parent, display, location):
        """ """
        details = capa.ida.helpers.get_disasm_line(location)
        super(CapaExplorerInstructionViewItem, self).__init__(parent, display, location=location, details=details)
        self.ida_highlight = idc.get_color(location, idc.CIC_ITEM)


class CapaExplorerByteViewItem(CapaExplorerFeatureItem):
    """ store data relevant to byte preview """

    def __init__(self, parent, display, location):
        """ """
        byte_snap = idaapi.get_bytes(location, 32)

        if byte_snap:
            byte_snap = codecs.encode(byte_snap, "hex").upper()
            if sys.version_info >= (3, 0):
                details = " ".join([byte_snap[i : i + 2].decode() for i in range(0, len(byte_snap), 2)])
            else:
                details = " ".join([byte_snap[i : i + 2] for i in range(0, len(byte_snap), 2)])
        else:
            details = ""

        super(CapaExplorerByteViewItem, self).__init__(parent, display, location=location, details=details)
        self.ida_highlight = idc.get_color(location, idc.CIC_ITEM)


class CapaExplorerStringViewItem(CapaExplorerFeatureItem):
    """ store data relevant to string preview """

    def __init__(self, parent, display, location):
        """ """
        super(CapaExplorerStringViewItem, self).__init__(parent, display, location=location)
        self.ida_highlight = idc.get_color(location, idc.CIC_ITEM)
