# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import codecs
from typing import Iterator, Optional

try:
    from PySide6 import QtCore

    _QT6 = True
except Exception:
    from PyQt5 import QtCore  # type: ignore

    _QT6 = False

import idc
import idaapi

import capa.ida.helpers
from capa.features.address import Address, FileOffsetAddress, AbsoluteVirtualAddress


def info_to_name(display):
    try:
        return display.split("(")[1].rstrip(")")
    except IndexError:
        return ""


def ea_to_hex(ea):
    return f"{hex(ea)}"


_HAS_ITEMFLAG = hasattr(QtCore.Qt, "ItemFlag")


def _qt_flag(name: str):
    """Return a single flag enum across Qt5/Qt6."""
    if _HAS_ITEMFLAG:
        return getattr(QtCore.Qt.ItemFlag, name)
    return getattr(QtCore.Qt, name)


def _qt_flags_or(*flags):
    """Build ItemFlags value across Qt5/Qt6."""
    if _HAS_ITEMFLAG:
        f = QtCore.Qt.ItemFlags()
        for fl in flags:
            f |= fl
        return f
    val = 0
    for fl in flags:
        val |= int(fl)
    return QtCore.Qt.ItemFlags(val)


class CapaExplorerDataItem:
    """store data for CapaExplorerDataModel"""

    def __init__(self, parent: Optional["CapaExplorerDataItem"], data: list[str], can_check=True):
        self.pred = parent
        self._data = data
        self._children: list["CapaExplorerDataItem"] = []
        self._checked = False
        self._can_check = can_check

        # default state for item
        self.flags = _qt_flags_or(_qt_flag("ItemIsEnabled"), _qt_flag("ItemIsSelectable"))

        if self._can_check:
            # Evita ItemIsTristate (indisponível no PySide6 do IDA)
            self.flags |= _qt_flag("ItemIsUserCheckable")

        if self.pred:
            self.pred.appendChild(self)

    def setIsEditable(self, isEditable=False):
        if isEditable:
            self.flags |= _qt_flag("ItemIsEditable")
        else:
            # remove bit
            self.flags &= ~_qt_flag("ItemIsEditable")

    def setChecked(self, checked: bool):
        self._checked = checked

    def canCheck(self):
        return self._can_check

    def isChecked(self):
        return self._checked

    def appendChild(self, item: "CapaExplorerDataItem"):
        self._children.append(item)

    def child(self, row: int) -> "CapaExplorerDataItem":
        return self._children[row]

    def childCount(self) -> int:
        return len(self._children)

    def columnCount(self) -> int:
        return len(self._data)

    def data(self, column: int) -> Optional[str]:
        try:
            return self._data[column]
        except IndexError:
            return None

    def parent(self) -> Optional["CapaExplorerDataItem"]:
        return self.pred

    def row(self) -> int:
        if self.pred:
            return self.pred._children.index(self)
        return 0

    def setData(self, column: int, value: str):
        self._data[column] = value

    def children(self) -> Iterator["CapaExplorerDataItem"]:
        yield from self._children

    def removeChildren(self):
        del self._children[:]

    def __str__(self):
        return " ".join([data for data in self._data if data])

    @property
    def info(self):
        return self._data[0]

    @property
    def location(self) -> Optional[int]:
        try:
            return int(self._data[1], 16)
        except ValueError:
            return None

    @property
    def details(self):
        return self._data[2]


class CapaExplorerRuleItem(CapaExplorerDataItem):
    fmt = "%s (%d matches)"

    def __init__(
        self,
        parent: CapaExplorerDataItem,
        name: str,
        namespace: str,
        count: int,
        source: str,
        can_check=True,
    ):
        display = self.fmt % (name, count) if count > 1 else name
        super().__init__(parent, [display, "", namespace], can_check)
        self._source = source

    @property
    def source(self):
        return self._source


class CapaExplorerRuleMatchItem(CapaExplorerDataItem):
    def __init__(self, parent: CapaExplorerDataItem, display: str, source=""):
        super().__init__(parent, [display, "", ""])
        self._source = source

    @property
    def source(self):
        return self._source


class CapaExplorerFunctionItem(CapaExplorerDataItem):
    fmt = "function(%s)"

    def __init__(self, parent: CapaExplorerDataItem, location: Address, can_check=True):
        assert isinstance(location, AbsoluteVirtualAddress)
        ea = int(location)
        super().__init__(parent, [self.fmt % idaapi.get_name(ea), ea_to_hex(ea), ""], can_check)

    @property
    def info(self):
        info = super().info
        display = info_to_name(info)
        return display if display else info

    @info.setter
    def info(self, display):
        self._data[0] = self.fmt % display


class CapaExplorerSubscopeItem(CapaExplorerDataItem):
    fmt = "subscope(%s)"

    def __init__(self, parent: CapaExplorerDataItem, scope):
        super().__init__(parent, [self.fmt % scope, "", ""])


class CapaExplorerBlockItem(CapaExplorerDataItem):
    fmt = "basic block(loc_%08X)"

    def __init__(self, parent: CapaExplorerDataItem, location: Address):
        assert isinstance(location, AbsoluteVirtualAddress)
        ea = int(location)
        super().__init__(parent, [self.fmt % ea, ea_to_hex(ea), ""])


class CapaExplorerInstructionItem(CapaExplorerBlockItem):
    fmt = "instruction(loc_%08X)"


class CapaExplorerDefaultItem(CapaExplorerDataItem):
    def __init__(
        self,
        parent: CapaExplorerDataItem,
        display: str,
        details: str = "",
        location: Optional[Address] = None,
    ):
        ea = None
        if location:
            assert isinstance(location, AbsoluteVirtualAddress)
            ea = int(location)
        super().__init__(parent, [display, ea_to_hex(ea) if ea is not None else "", details])


class CapaExplorerFeatureItem(CapaExplorerDataItem):
    def __init__(
        self,
        parent: CapaExplorerDataItem,
        display: str,
        location: Optional[Address] = None,
        details: str = "",
    ):
        if location:
            assert isinstance(location, (AbsoluteVirtualAddress, FileOffsetAddress))
            ea = int(location)
            super().__init__(parent, [display, ea_to_hex(ea), details])
        else:
            super().__init__(parent, [display, "", details])


class CapaExplorerInstructionViewItem(CapaExplorerFeatureItem):
    def __init__(self, parent: CapaExplorerDataItem, display: str, location: Address):
        assert isinstance(location, AbsoluteVirtualAddress)
        ea = int(location)
        details = capa.ida.helpers.get_disasm_line(ea)
        super().__init__(parent, display, location=location, details=details)
        self.ida_highlight = idc.get_color(ea, idc.CIC_ITEM)


class CapaExplorerByteViewItem(CapaExplorerFeatureItem):
    def __init__(self, parent: CapaExplorerDataItem, display: str, location: Address):
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
    def __init__(self, parent: CapaExplorerDataItem, display: str, location: Address, value: str):
        assert isinstance(location, (AbsoluteVirtualAddress, FileOffsetAddress))
        ea = int(location)

        super().__init__(parent, display, location=location, details=value)
        self.ida_highlight = idc.get_color(ea, idc.CIC_ITEM)
