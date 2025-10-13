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


from typing import Optional
from collections import deque

try:
    from PySide6 import QtGui, QtCore

    _QT6 = True
except Exception:
    from PyQt5 import QtGui, QtCore  # type: ignore

    _QT6 = False

import idc
import idaapi

import capa.rules
import capa.ida.helpers
import capa.render.utils as rutils
import capa.features.common
import capa.features.freeze as frz
import capa.render.result_document as rd
import capa.features.freeze.features as frzf
from capa.ida.plugin.item import (
    CapaExplorerDataItem,
    CapaExplorerRuleItem,
    CapaExplorerBlockItem,
    CapaExplorerDefaultItem,
    CapaExplorerFeatureItem,
    CapaExplorerByteViewItem,
    CapaExplorerFunctionItem,
    CapaExplorerSubscopeItem,
    CapaExplorerRuleMatchItem,
    CapaExplorerStringViewItem,
    CapaExplorerInstructionItem,
    CapaExplorerInstructionViewItem,
)
from capa.features.address import Address, AbsoluteVirtualAddress

DEFAULT_HIGHLIGHT = 0xE6C700


_HAS_ITEMFLAG = hasattr(QtCore.Qt, "ItemFlag")
_HAS_MATCHFLAG = hasattr(QtCore.Qt, "MatchFlag")


def _qt_noitemflags():
    if _HAS_ITEMFLAG:
        return QtCore.Qt.ItemFlags()  # empty
    return QtCore.Qt.NoItemFlags


def _qt_matchflag(name: str):
    if _HAS_MATCHFLAG:
        return getattr(QtCore.Qt.MatchFlag, name)
    return getattr(QtCore.Qt, name)


class CapaExplorerDataModel(QtCore.QAbstractItemModel):
    COLUMN_INDEX_RULE_INFORMATION = 0
    COLUMN_INDEX_VIRTUAL_ADDRESS = 1
    COLUMN_INDEX_DETAILS = 2
    COLUMN_COUNT = 3

    def __init__(self, parent=None):
        super().__init__(parent)
        self.root_node = CapaExplorerDataItem(None, ["Rule Information", "Address", "Details"])

    def reset(self):
        for idx in range(self.root_node.childCount()):
            root_index = self.index(idx, 0, QtCore.QModelIndex())
            for model_index in self.iterateChildrenIndexFromRootIndex(root_index, ignore_root=False):
                model_index.internalPointer().setChecked(False)
                self.reset_ida_highlighting(model_index.internalPointer(), False)
                self.dataChanged.emit(model_index, model_index)

    def clear(self):
        self.beginResetModel()
        self.root_node.removeChildren()
        self.endResetModel()

    def columnCount(self, model_index):
        if model_index.isValid():
            return model_index.internalPointer().columnCount()
        else:
            return self.root_node.columnCount()

    def data(self, model_index, role):
        if not model_index.isValid():
            return None

        item = model_index.internalPointer()
        column = model_index.column()

        if role == QtCore.Qt.DisplayRole:
            return item.data(column)

        if (
            role == QtCore.Qt.ToolTipRole
            and isinstance(item, (CapaExplorerRuleItem, CapaExplorerRuleMatchItem))
            and CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION == column
        ):
            return item.source

        if role == QtCore.Qt.CheckStateRole and column == CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION:
            if not item.canCheck():
                return None
            return QtCore.Qt.Checked if item.isChecked() else QtCore.Qt.Unchecked

        if role == QtCore.Qt.FontRole and column in (
            CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS,
            CapaExplorerDataModel.COLUMN_INDEX_DETAILS,
        ):
            font = QtGui.QFont("Courier", weight=QtGui.QFont.Weight.Medium)
            if column == CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS:
                font.setBold(True)
            return font

        if (
            role == QtCore.Qt.FontRole
            and isinstance(
                item,
                (
                    CapaExplorerRuleItem,
                    CapaExplorerRuleMatchItem,
                    CapaExplorerBlockItem,
                    CapaExplorerFunctionItem,
                    CapaExplorerFeatureItem,
                    CapaExplorerSubscopeItem,
                    CapaExplorerInstructionItem,
                ),
            )
            and column == CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION
        ):
            font = QtGui.QFont()
            font.setBold(True)
            return font

        if role == QtCore.Qt.ForegroundRole and column == CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS:
            return QtGui.QColor(37, 147, 215)

        if (
            role == QtCore.Qt.ForegroundRole
            and isinstance(item, CapaExplorerFeatureItem)
            and column == CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION
        ):
            return QtGui.QColor(79, 121, 66)

        return None

    def flags(self, model_index):
        if not model_index.isValid():
            return _qt_noitemflags()
        return model_index.internalPointer().flags

    def headerData(self, section, orientation, role):
        if orientation == QtCore.Qt.Orientation.Horizontal and role == QtCore.Qt.DisplayRole:
            return self.root_node.data(section)
        return None

    def index(self, row, column, parent):
        if not self.hasIndex(row, column, parent):
            return QtCore.QModelIndex()

        if not parent.isValid():
            parent_item = self.root_node
        else:
            parent_item = parent.internalPointer()

        child_item = parent_item.child(row)

        if child_item:
            return self.createIndex(row, column, child_item)
        else:
            return QtCore.QModelIndex()

    def parent(self, model_index):
        if not model_index.isValid():
            return QtCore.QModelIndex()

        child = model_index.internalPointer()
        parent = child.parent()

        if parent == self.root_node:
            return QtCore.QModelIndex()

        return self.createIndex(parent.row(), 0, parent)

    def iterateChildrenIndexFromRootIndex(self, model_index, ignore_root=True):
        visited = set()
        stack = deque((model_index,))

        while True:
            try:
                child_index = stack.pop()
            except IndexError:
                break

            if child_index not in visited:
                if not ignore_root or child_index is not model_index:
                    yield child_index

                visited.add(child_index)

                for idx in range(self.rowCount(child_index)):
                    stack.append(child_index.child(idx, 0))

    def reset_ida_highlighting(self, item, checked):
        if not isinstance(
            item,
            (
                CapaExplorerStringViewItem,
                CapaExplorerInstructionViewItem,
                CapaExplorerByteViewItem,
            ),
        ):
            return

        curr_highlight = idc.get_color(item.location, idc.CIC_ITEM)

        if checked:
            item.ida_highlight = curr_highlight
            idc.set_color(item.location, idc.CIC_ITEM, DEFAULT_HIGHLIGHT)
        else:
            if curr_highlight != DEFAULT_HIGHLIGHT:
                item.ida_highlight = curr_highlight
            else:
                idc.set_color(item.location, idc.CIC_ITEM, item.ida_highlight)

    def setData(self, model_index, value, role):
        if not model_index.isValid():
            return False

        if (
            role == QtCore.Qt.CheckStateRole
            and model_index.column() == CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION
        ):
            is_checked = value == QtCore.Qt.CheckState.Checked
            for child_index in self.iterateChildrenIndexFromRootIndex(model_index, ignore_root=False):
                child_index.internalPointer().setChecked(is_checked)
                self.reset_ida_highlighting(child_index.internalPointer(), is_checked)
                self.dataChanged.emit(child_index, child_index)
            return True

        if (
            role == QtCore.Qt.EditRole
            and value
            and model_index.column() == CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION
            and isinstance(model_index.internalPointer(), CapaExplorerFunctionItem)
        ):
            old_name = model_index.internalPointer().info
            new_name = str(value)

            if idaapi.set_name(model_index.internalPointer().location, new_name):
                self.update_function_name(old_name, new_name)
                return True

        return False

    def rowCount(self, model_index):
        if model_index.column() > 0:
            return 0

        if not model_index.isValid():
            item = self.root_node
        else:
            item = model_index.internalPointer()

        return item.childCount()

    def render_capa_doc_statement_node(
        self,
        parent: CapaExplorerDataItem,
        match: rd.Match,
        statement: rd.Statement,
        locations: list[Address],
        doc: rd.ResultDocument,
    ):
        if isinstance(statement, rd.CompoundStatement):
            if statement.type != rd.CompoundStatementType.NOT:
                display = statement.type
                if statement.description:
                    display += f" ({statement.description})"
                return CapaExplorerDefaultItem(parent, display)
        elif isinstance(statement, rd.CompoundStatement) and statement.type == rd.CompoundStatementType.NOT:
            pass
        elif isinstance(statement, rd.SomeStatement):
            display = f"{statement.count} or more"
            if statement.description:
                display += f" ({statement.description})"
            return CapaExplorerDefaultItem(parent, display)
        elif isinstance(statement, rd.RangeStatement):
            display = f"count({self.capa_doc_feature_to_display(statement.child)}): "

            if statement.max == statement.min:
                display += f"{statement.min}"
            elif statement.min == 0:
                display += f"{statement.max} or fewer"
            elif statement.max == (1 << 64 - 1):
                display += f"{statement.min} or more"
            else:
                display += f"between {statement.min} and {statement.max}"

            if statement.description:
                display += f" ({statement.description})"

            parent2 = CapaExplorerFeatureItem(parent, display=display)

            for location in locations:
                self.render_capa_doc_feature(parent2, match, statement.child, location, doc)

            return parent2
        elif isinstance(statement, rd.SubscopeStatement):
            display = str(statement.scope)
            if statement.description:
                display += f" ({statement.description})"
            return CapaExplorerSubscopeItem(parent, display)
        else:
            raise RuntimeError("unexpected match statement type: " + str(statement))

    def render_capa_doc_match(self, parent: CapaExplorerDataItem, match: rd.Match, doc: rd.ResultDocument):
        if not match.success:
            return

        if isinstance(match.node, rd.StatementNode) and match.node.statement.type == rd.CompoundStatementType.OPTIONAL:
            if not any(m.success for m in match.children):
                return

        if isinstance(match.node, rd.StatementNode):
            parent2 = self.render_capa_doc_statement_node(
                parent,
                match,
                match.node.statement,
                [addr.to_capa() for addr in match.locations],
                doc,
            )
        elif isinstance(match.node, rd.FeatureNode):
            parent2 = self.render_capa_doc_feature_node(
                parent,
                match,
                match.node.feature,
                [addr.to_capa() for addr in match.locations],
                doc,
            )
        else:
            raise RuntimeError("unexpected node type: " + str(match.node.type))

        for child in match.children:
            self.render_capa_doc_match(parent2, child, doc)

    def render_capa_doc_by_function(self, doc: rd.ResultDocument):
        matches_by_function: dict[AbsoluteVirtualAddress, tuple[CapaExplorerFunctionItem, set[str]]] = {}
        for rule in rutils.capability_rules(doc):
            match_eas: list[int] = []

            for addr_, _ in rule.matches:
                addr: Address = addr_.to_capa()
                if isinstance(addr, AbsoluteVirtualAddress):
                    match_eas.append(int(addr))

            for ea in match_eas:
                func_ea: Optional[int] = capa.ida.helpers.get_func_start_ea(ea)
                if func_ea is None:
                    continue

                func_address: AbsoluteVirtualAddress = AbsoluteVirtualAddress(func_ea)
                if not matches_by_function.get(func_address, ()):
                    matches_by_function[func_address] = (
                        CapaExplorerFunctionItem(self.root_node, func_address, can_check=False),
                        set(),
                    )

                func_root, func_match_cache = matches_by_function[func_address]
                if rule.meta.name in func_match_cache:
                    continue

                func_match_cache.add(rule.meta.name)
                CapaExplorerRuleItem(
                    func_root,
                    rule.meta.name,
                    rule.meta.namespace or "",
                    len([ea for ea in match_eas if capa.ida.helpers.get_func_start_ea(ea) == func_ea]),
                    rule.source,
                    can_check=False,
                )

    def render_capa_doc_by_program(self, doc: rd.ResultDocument):
        for rule in rutils.capability_rules(doc):
            rule_name = rule.meta.name
            rule_namespace = rule.meta.namespace or ""
            parent = CapaExplorerRuleItem(
                self.root_node,
                rule_name,
                rule_namespace,
                len(rule.matches),
                rule.source,
            )

            for location_, match in rule.matches:
                location = location_.to_capa()

                parent2: CapaExplorerDataItem
                if capa.rules.Scope.FILE in rule.meta.scopes:
                    parent2 = parent
                elif capa.rules.Scope.FUNCTION in rule.meta.scopes:
                    parent2 = CapaExplorerFunctionItem(parent, location)
                elif capa.rules.Scope.BASIC_BLOCK in rule.meta.scopes:
                    parent2 = CapaExplorerBlockItem(parent, location)
                elif capa.rules.Scope.INSTRUCTION in rule.meta.scopes:
                    parent2 = CapaExplorerInstructionItem(parent, location)
                else:
                    raise RuntimeError("unexpected rule scope: " + str(rule.meta.scopes.static))

                self.render_capa_doc_match(parent2, match, doc)

    def render_capa_doc(self, doc: rd.ResultDocument, by_function: bool):
        self.beginResetModel()
        if by_function:
            self.render_capa_doc_by_function(doc)
        else:
            self.render_capa_doc_by_program(doc)
        self.endResetModel()

    def capa_doc_feature_to_display(self, feature: frzf.Feature) -> str:
        key = str(feature.type)
        value = feature.dict(by_alias=True).get(feature.type)

        if value:
            if isinstance(feature, frzf.StringFeature):
                value = f'"{capa.features.common.escape_string(value)}"'

            if isinstance(feature, frzf.PropertyFeature) and feature.access is not None:
                key = f"property/{feature.access}"
            elif isinstance(feature, frzf.OperandNumberFeature):
                key = f"operand[{feature.index}].number"
            elif isinstance(feature, frzf.OperandOffsetFeature):
                key = f"operand[{feature.index}].offset"

            if feature.description:
                return f"{key}({value} = {feature.description})"
            else:
                return f"{key}({value})"
        else:
            return f"{key}"

    def render_capa_doc_feature_node(
        self,
        parent: CapaExplorerDataItem,
        match: rd.Match,
        feature: frzf.Feature,
        locations: list[Address],
        doc: rd.ResultDocument,
    ):
        display = self.capa_doc_feature_to_display(feature)

        if len(locations) == 1:
            parent2 = self.render_capa_doc_feature(
                parent,
                match,
                feature,
                next(iter(locations)),
                doc,
                display=display,
            )
        else:
            parent2 = CapaExplorerFeatureItem(parent, display)

            for location in sorted(locations):
                self.render_capa_doc_feature(parent2, match, feature, location, doc)

        return parent2

    def render_capa_doc_feature(
        self,
        parent: CapaExplorerDataItem,
        match: rd.Match,
        feature: frzf.Feature,
        location: Address,
        doc: rd.ResultDocument,
        display="-",
    ):
        if isinstance(feature, frzf.CharacteristicFeature):
            characteristic = feature.characteristic
            if characteristic in ("embedded pe",):
                return CapaExplorerByteViewItem(parent, display, location)

            if characteristic in ("loop", "recursive call", "tight loop"):
                return CapaExplorerFeatureItem(parent, display=display)

            return CapaExplorerInstructionViewItem(parent, display, location)

        elif isinstance(feature, frzf.MatchFeature):
            matched_rule_source = ""
            matched_rule = doc.rules.get(feature.match)
            if matched_rule is not None:
                matched_rule_source = matched_rule.source
            return CapaExplorerRuleMatchItem(parent, display, source=matched_rule_source)

        elif isinstance(feature, (frzf.RegexFeature, frzf.SubstringFeature)):
            for capture, addrs in sorted(match.captures.items()):
                for addr in addrs:
                    assert isinstance(addr, frz.Address)
                    if location == addr.value:
                        return CapaExplorerStringViewItem(
                            parent,
                            display,
                            location,
                            '"' + capa.features.common.escape_string(capture) + '"',
                        )
            raise ValueError("regex match at location not found")

        elif isinstance(feature, frzf.BasicBlockFeature):
            return CapaExplorerBlockItem(parent, location)

        elif isinstance(
            feature,
            (
                frzf.BytesFeature,
                frzf.APIFeature,
                frzf.MnemonicFeature,
                frzf.NumberFeature,
                frzf.OffsetFeature,
                frzf.OperandNumberFeature,
                frzf.OperandOffsetFeature,
            ),
        ):
            return CapaExplorerInstructionViewItem(parent, display, location)

        elif isinstance(feature, frzf.SectionFeature):
            return CapaExplorerByteViewItem(parent, display, location)

        elif isinstance(feature, frzf.StringFeature):
            return CapaExplorerStringViewItem(
                parent,
                display,
                location,
                f'"{capa.features.common.escape_string(feature.string)}"',
            )

        elif isinstance(
            feature,
            (
                frzf.ImportFeature,
                frzf.ExportFeature,
                frzf.FunctionNameFeature,
            ),
        ):
            return CapaExplorerFeatureItem(parent, location=location, display=display)

        elif isinstance(
            feature,
            (
                frzf.ArchFeature,
                frzf.OSFeature,
                frzf.FormatFeature,
            ),
        ):
            return CapaExplorerFeatureItem(parent, display=display)

        raise RuntimeError("unexpected feature type: " + str(feature.type))

    def update_function_name(self, old_name, new_name):
        root_index = self.index(0, 0, QtCore.QModelIndex())
        old_name = CapaExplorerFunctionItem.fmt % old_name
        match_recursive = _qt_matchflag("MatchRecursive")
        for model_index in self.match(
            root_index,
            QtCore.Qt.ItemDataRole.DisplayRole,
            old_name,
            hits=-1,
            flags=QtCore.Qt.MatchFlags(match_recursive),
        ):
            if not isinstance(model_index.internalPointer(), CapaExplorerFunctionItem):
                continue
            model_index.internalPointer().info = new_name
            self.dataChanged.emit(model_index, model_index)
