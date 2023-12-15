# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Set, Dict, List, Tuple, Optional
from collections import deque

import idc
import idaapi
from PyQt5 import QtGui, QtCore

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

# default highlight color used in IDA window
DEFAULT_HIGHLIGHT = 0xE6C700


class CapaExplorerDataModel(QtCore.QAbstractItemModel):
    """model for displaying hierarchical results return by capa"""

    COLUMN_INDEX_RULE_INFORMATION = 0
    COLUMN_INDEX_VIRTUAL_ADDRESS = 1
    COLUMN_INDEX_DETAILS = 2

    COLUMN_COUNT = 3

    def __init__(self, parent=None):
        """initialize model"""
        super().__init__(parent)
        # root node does not have parent, contains header columns
        self.root_node = CapaExplorerDataItem(None, ["Rule Information", "Address", "Details"])

    def reset(self):
        """reset UI elements (e.g. checkboxes, IDA color highlights)

        called when view wants to reset UI display
        """
        for idx in range(self.root_node.childCount()):
            root_index = self.index(idx, 0, QtCore.QModelIndex())
            for model_index in self.iterateChildrenIndexFromRootIndex(root_index, ignore_root=False):
                model_index.internalPointer().setChecked(False)
                self.reset_ida_highlighting(model_index.internalPointer(), False)
                self.dataChanged.emit(model_index, model_index)

    def clear(self):
        """clear model data

        called when view wants to clear UI display
        """
        self.beginResetModel()
        self.root_node.removeChildren()
        self.endResetModel()

    def columnCount(self, model_index):
        """return number of columns for the children of the given parent

        @param model_index: QModelIndex

        @retval column count
        """
        if model_index.isValid():
            return model_index.internalPointer().columnCount()
        else:
            return self.root_node.columnCount()

    def data(self, model_index, role):
        """return data stored at given index by display role

        this function is used to control UI elements (e.g. text font, color, etc.) based on column, item type, etc.

        @param model_index: QModelIndex
        @param role: QtCore.Qt.*

        @retval data to be displayed
        """
        if not model_index.isValid():
            return None

        item = model_index.internalPointer()
        column = model_index.column()

        if role == QtCore.Qt.DisplayRole:
            # display data in corresponding column
            return item.data(column)

        if (
            role == QtCore.Qt.ToolTipRole
            and isinstance(item, (CapaExplorerRuleItem, CapaExplorerRuleMatchItem))
            and CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION == column
        ):
            # show tooltip containing rule source
            return item.source

        if role == QtCore.Qt.CheckStateRole and column == CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION:
            # inform view how to display content of checkbox - un/checked
            if not item.canCheck():
                return None
            return QtCore.Qt.Checked if item.isChecked() else QtCore.Qt.Unchecked

        if role == QtCore.Qt.FontRole and column in (
            CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS,
            CapaExplorerDataModel.COLUMN_INDEX_DETAILS,
        ):
            # set font for virtual address and details columns
            font = QtGui.QFont("Courier", weight=QtGui.QFont.Medium)
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
            # set bold font for important items
            font = QtGui.QFont()
            font.setBold(True)
            return font

        if role == QtCore.Qt.ForegroundRole and column == CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS:
            # set color for virtual address column
            return QtGui.QColor(37, 147, 215)

        if (
            role == QtCore.Qt.ForegroundRole
            and isinstance(item, CapaExplorerFeatureItem)
            and column == CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION
        ):
            # set color for feature items
            return QtGui.QColor(79, 121, 66)

        return None

    def flags(self, model_index):
        """return item flags for given index

        @param model_index: QModelIndex

        @retval QtCore.Qt.ItemFlags
        """
        if not model_index.isValid():
            return QtCore.Qt.NoItemFlags

        return model_index.internalPointer().flags

    def headerData(self, section, orientation, role):
        """return data for the given role and section in the header with the specified orientation

        @param section: int
        @param orientation: QtCore.Qt.Orientation
        @param role: QtCore.Qt.DisplayRole

        @retval header data
        """
        if orientation == QtCore.Qt.Horizontal and role == QtCore.Qt.DisplayRole:
            return self.root_node.data(section)

        return None

    def index(self, row, column, parent):
        """return index of the item by row, column, and parent index

        @param row: item row
        @param column: item column
        @param parent: QModelIndex of parent

        @retval QModelIndex of item
        """
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
        """return parent index by child index

        if the item has no parent, an invalid QModelIndex is returned

        @param model_index: QModelIndex of child

        @retval QModelIndex of parent
        """
        if not model_index.isValid():
            return QtCore.QModelIndex()

        child = model_index.internalPointer()
        parent = child.parent()

        if parent == self.root_node:
            return QtCore.QModelIndex()

        return self.createIndex(parent.row(), 0, parent)

    def iterateChildrenIndexFromRootIndex(self, model_index, ignore_root=True):
        """depth-first traversal of child nodes

        @param model_index: QModelIndex of starting item
        @param ignore_root: True, do not yield root index, False yield root index

        @retval yield QModelIndex
        """
        visited = set()
        stack = deque((model_index,))

        while True:
            try:
                child_index = stack.pop()
            except IndexError:
                break

            if child_index not in visited:
                if not ignore_root or child_index is not model_index:
                    # ignore root
                    yield child_index

                visited.add(child_index)

                for idx in range(self.rowCount(child_index)):
                    stack.append(child_index.child(idx, 0))

    def reset_ida_highlighting(self, item, checked):
        """reset IDA highlight for item

        @param item: CapaExplorerDataItem
        @param checked: True, item checked, False item not checked
        """
        if not isinstance(
            item, (CapaExplorerStringViewItem, CapaExplorerInstructionViewItem, CapaExplorerByteViewItem)
        ):
            # ignore other item types
            return

        curr_highlight = idc.get_color(item.location, idc.CIC_ITEM)

        if checked:
            # item checked - record current highlight and set to new
            item.ida_highlight = curr_highlight
            idc.set_color(item.location, idc.CIC_ITEM, DEFAULT_HIGHLIGHT)
        else:
            # item unchecked - reset highlight
            if curr_highlight != DEFAULT_HIGHLIGHT:
                # user modified highlight - record new highlight and do not modify
                item.ida_highlight = curr_highlight
            else:
                # reset highlight to previous
                idc.set_color(item.location, idc.CIC_ITEM, item.ida_highlight)

    def setData(self, model_index, value, role):
        """set data at index by role

        @param model_index: QModelIndex of item
        @param value: value to set
        @param role: QtCore.Qt.EditRole
        """
        if not model_index.isValid():
            return False

        if (
            role == QtCore.Qt.CheckStateRole
            and model_index.column() == CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION
        ):
            # user un/checked box - un/check parent and children
            for child_index in self.iterateChildrenIndexFromRootIndex(model_index, ignore_root=False):
                child_index.internalPointer().setChecked(value)
                self.reset_ida_highlighting(child_index.internalPointer(), value)
                self.dataChanged.emit(child_index, child_index)
            return True

        if (
            role == QtCore.Qt.EditRole
            and value
            and model_index.column() == CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION
            and isinstance(model_index.internalPointer(), CapaExplorerFunctionItem)
        ):
            # user renamed function - update IDA database and data model
            old_name = model_index.internalPointer().info
            new_name = str(value)

            if idaapi.set_name(model_index.internalPointer().location, new_name):
                # success update IDA database - update data model
                self.update_function_name(old_name, new_name)
                return True

        # no handle
        return False

    def rowCount(self, model_index):
        """return number of rows under item by index

        when the parent is valid it means that is returning the number of children of parent

        @param model_index: QModelIndex

        @retval row count
        """
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
        locations: List[Address],
        doc: rd.ResultDocument,
    ):
        """render capa statement read from doc

        @param parent: parent to which new child is assigned
        @param statement: statement read from doc
        @param locations: locations of children (applies to range only?)
        @param doc: result doc
        """

        if isinstance(statement, rd.CompoundStatement):
            if statement.type != rd.CompoundStatementType.NOT:
                display = statement.type
                if statement.description:
                    display += f" ({statement.description})"
                return CapaExplorerDefaultItem(parent, display)
        elif isinstance(statement, rd.CompoundStatement) and statement.type == rd.CompoundStatementType.NOT:
            # TODO(mike-hunhoff): verify that we can display NOT statements
            # https://github.com/mandiant/capa/issues/1602
            pass
        elif isinstance(statement, rd.SomeStatement):
            display = f"{statement.count} or more"
            if statement.description:
                display += f" ({statement.description})"
            return CapaExplorerDefaultItem(parent, display)
        elif isinstance(statement, rd.RangeStatement):
            # `range` is a weird node, its almost a hybrid of statement + feature.
            # it is a specific feature repeated multiple times.
            # there's no additional logic in the feature part, just the existence of a feature.
            # so, we have to inline some of the feature rendering here.
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
                # for each location render child node for range statement
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
        """render capa match read from doc

        @param parent: parent node to which new child is assigned
        @param match: match read from doc
        @param doc: result doc
        """
        if not match.success:
            # TODO(mike-hunhoff): display failed branches at some point? Help with debugging rules?
            # https://github.com/mandiant/capa/issues/1601
            return

        # optional statement with no successful children is empty
        if isinstance(match.node, rd.StatementNode) and match.node.statement.type == rd.CompoundStatementType.OPTIONAL:
            if not any(m.success for m in match.children):
                return

        if isinstance(match.node, rd.StatementNode):
            parent2 = self.render_capa_doc_statement_node(
                parent, match, match.node.statement, [addr.to_capa() for addr in match.locations], doc
            )
        elif isinstance(match.node, rd.FeatureNode):
            parent2 = self.render_capa_doc_feature_node(
                parent, match, match.node.feature, [addr.to_capa() for addr in match.locations], doc
            )
        else:
            raise RuntimeError("unexpected node type: " + str(match.node.type))

        for child in match.children:
            self.render_capa_doc_match(parent2, child, doc)

    def render_capa_doc_by_function(self, doc: rd.ResultDocument):
        """render rule matches by function meaning each rule match is nested under function where it was found"""
        matches_by_function: Dict[AbsoluteVirtualAddress, Tuple[CapaExplorerFunctionItem, Set[str]]] = {}
        for rule in rutils.capability_rules(doc):
            match_eas: List[int] = []

            # initial pass of rule matches
            for addr_, _ in rule.matches:
                addr: Address = addr_.to_capa()
                if isinstance(addr, AbsoluteVirtualAddress):
                    match_eas.append(int(addr))

            for ea in match_eas:
                func_ea: Optional[int] = capa.ida.helpers.get_func_start_ea(ea)
                if func_ea is None:
                    # rule match address is not located in a defined function
                    continue

                func_address: AbsoluteVirtualAddress = AbsoluteVirtualAddress(func_ea)
                if not matches_by_function.get(func_address, ()):
                    # create a new function root to nest its rule matches; Note: we must use the address of the
                    # function here so everything is displayed properly
                    matches_by_function[func_address] = (
                        CapaExplorerFunctionItem(self.root_node, func_address, can_check=False),
                        set(),
                    )

                func_root, func_match_cache = matches_by_function[func_address]
                if rule.meta.name in func_match_cache:
                    # only nest each rule once, so if found, skip
                    continue

                # add matched rule to its function cache; create a new rule node whose parent is the matched
                # function node
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
        """ """
        for rule in rutils.capability_rules(doc):
            rule_name = rule.meta.name
            rule_namespace = rule.meta.namespace or ""
            parent = CapaExplorerRuleItem(self.root_node, rule_name, rule_namespace, len(rule.matches), rule.source)

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
        """render capa features specified in doc

        @param doc: capa result doc
        """
        # inform model that changes are about to occur
        self.beginResetModel()

        if by_function:
            self.render_capa_doc_by_function(doc)
        else:
            self.render_capa_doc_by_program(doc)

        # inform model changes have ended
        self.endResetModel()

    def capa_doc_feature_to_display(self, feature: frzf.Feature):
        """convert capa doc feature type string to display string for ui

        @param feature: capa feature read from doc
        """
        key = feature.type
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
        locations: List[Address],
        doc: rd.ResultDocument,
    ):
        """process capa doc feature node

        @param parent: parent node to which child is assigned
        @param match: match information
        @param feature: capa doc feature node
        @param locations: locations identified for feature
        @param doc: capa doc
        """
        display = self.capa_doc_feature_to_display(feature)

        if len(locations) == 1:
            # only one location for feature so no need to nest children
            parent2 = self.render_capa_doc_feature(
                parent,
                match,
                feature,
                next(iter(locations)),
                doc,
                display=display,
            )
        else:
            # feature has multiple children, nest  under one parent feature node
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
        """render capa feature read from doc

        @param parent: parent node to which new child is assigned
        @param match: match information
        @param feature: feature read from doc
        @param doc: capa feature doc
        @param location: address of feature
        @param display: text to display in plugin UI
        """

        # special handling for characteristic pending type
        if isinstance(feature, frzf.CharacteristicFeature):
            characteristic = feature.characteristic
            if characteristic in ("embedded pe",):
                return CapaExplorerByteViewItem(parent, display, location)

            if characteristic in ("loop", "recursive call", "tight loop"):
                return CapaExplorerFeatureItem(parent, display=display)

            # default to instruction view for all other characteristics
            return CapaExplorerInstructionViewItem(parent, display, location)

        elif isinstance(feature, frzf.MatchFeature):
            # display content of rule for all rule matches
            matched_rule_source = ""

            # check if match is a matched rule
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
                            parent, display, location, '"' + capa.features.common.escape_string(capture) + '"'
                        )

            # programming error: the given location should always be found in the regex matches
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
            # display instruction preview
            return CapaExplorerInstructionViewItem(parent, display, location)

        elif isinstance(feature, frzf.SectionFeature):
            # display byte preview
            return CapaExplorerByteViewItem(parent, display, location)

        elif isinstance(feature, frzf.StringFeature):
            # display string preview
            return CapaExplorerStringViewItem(
                parent, display, location, f'"{capa.features.common.escape_string(feature.string)}"'
            )

        elif isinstance(
            feature,
            (
                frzf.ImportFeature,
                frzf.ExportFeature,
                frzf.FunctionNameFeature,
            ),
        ):
            # display no preview
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
        """update all instances of old function name with new function name

        called when user updates function name using plugin UI

        @param old_name: old function name
        @param new_name: new function name
        """
        # create empty root index for search
        root_index = self.index(0, 0, QtCore.QModelIndex())

        # convert name to view format for matching e.g. function(my_function)
        old_name = CapaExplorerFunctionItem.fmt % old_name

        # recursive search for all instances of old function name
        for model_index in self.match(
            root_index, QtCore.Qt.DisplayRole, old_name, hits=-1, flags=QtCore.Qt.MatchRecursive
        ):
            if not isinstance(model_index.internalPointer(), CapaExplorerFunctionItem):
                continue

            # replace old function name with new function name and emit change
            model_index.internalPointer().info = new_name
            self.dataChanged.emit(model_index, model_index)
