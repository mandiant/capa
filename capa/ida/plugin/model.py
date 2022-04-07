# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from collections import deque, defaultdict

import idc
import idaapi
from PyQt5 import QtGui, QtCore

import capa.rules
import capa.ida.helpers
import capa.render.utils as rutils
import capa.features.common
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
    CapaExplorerInstructionViewItem,
)

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
        super(CapaExplorerDataModel, self).__init__(parent)
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

    def render_capa_doc_statement_node(self, parent, statement, locations, doc):
        """render capa statement read from doc

        @param parent: parent to which new child is assigned
        @param statement: statement read from doc
        @param locations: locations of children (applies to range only?)
        @param doc: result doc
        """
        if statement["type"] in ("and", "or", "optional"):
            display = statement["type"]
            if statement.get("description"):
                display += " (%s)" % statement["description"]
            return CapaExplorerDefaultItem(parent, display)
        elif statement["type"] == "not":
            # TODO: do we display 'not'
            pass
        elif statement["type"] == "some":
            display = "%d or more" % statement["count"]
            if statement.get("description"):
                display += " (%s)" % statement["description"]
            return CapaExplorerDefaultItem(parent, display)
        elif statement["type"] == "range":
            # `range` is a weird node, its almost a hybrid of statement + feature.
            # it is a specific feature repeated multiple times.
            # there's no additional logic in the feature part, just the existence of a feature.
            # so, we have to inline some of the feature rendering here.
            display = "count(%s): " % self.capa_doc_feature_to_display(statement["child"])

            if statement["max"] == statement["min"]:
                display += "%d" % (statement["min"])
            elif statement["min"] == 0:
                display += "%d or fewer" % (statement["max"])
            elif statement["max"] == (1 << 64 - 1):
                display += "%d or more" % (statement["min"])
            else:
                display += "between %d and %d" % (statement["min"], statement["max"])

            if statement.get("description"):
                display += " (%s)" % statement["description"]

            parent2 = CapaExplorerFeatureItem(parent, display=display)

            for location in locations:
                # for each location render child node for range statement
                self.render_capa_doc_feature(parent2, statement["child"], location, doc)

            return parent2
        elif statement["type"] == "subscope":
            display = statement[statement["type"]]
            if statement.get("description"):
                display += " (%s)" % statement["description"]
            return CapaExplorerSubscopeItem(parent, display)
        else:
            raise RuntimeError("unexpected match statement type: " + str(statement))

    def render_capa_doc_match(self, parent, match, doc):
        """render capa match read from doc

        @param parent: parent node to which new child is assigned
        @param match: match read from doc
        @param doc: result doc
        """
        if not match["success"]:
            # TODO: display failed branches at some point? Help with debugging rules?
            return

        # optional statement with no successful children is empty
        if match["node"].get("statement", {}).get("type") == "optional" and not any(
            map(lambda m: m["success"], match["children"])
        ):
            return

        if match["node"]["type"] == "statement":
            parent2 = self.render_capa_doc_statement_node(
                parent, match["node"]["statement"], match.get("locations", []), doc
            )
        elif match["node"]["type"] == "feature":
            parent2 = self.render_capa_doc_feature_node(
                parent, match["node"]["feature"], match.get("locations", []), doc
            )
        else:
            raise RuntimeError("unexpected node type: " + str(match["node"]["type"]))

        for child in match.get("children", []):
            self.render_capa_doc_match(parent2, child, doc)

    def render_capa_doc_by_function(self, doc):
        """ """
        matches_by_function = {}
        for rule in rutils.capability_rules(doc):
            for ea in rule["matches"].keys():
                ea = capa.ida.helpers.get_func_start_ea(ea)
                if ea is None:
                    # file scope, skip rendering in this mode
                    continue
                if not matches_by_function.get(ea, ()):
                    # new function root
                    matches_by_function[ea] = (CapaExplorerFunctionItem(self.root_node, ea, can_check=False), [])
                function_root, match_cache = matches_by_function[ea]
                if rule["meta"]["name"] in match_cache:
                    # rule match already rendered for this function root, skip it
                    continue
                match_cache.append(rule["meta"]["name"])
                CapaExplorerRuleItem(
                    function_root,
                    rule["meta"]["name"],
                    rule["meta"].get("namespace"),
                    len(rule["matches"]),
                    rule["source"],
                    can_check=False,
                )

    def render_capa_doc_by_program(self, doc):
        """ """
        for rule in rutils.capability_rules(doc):
            rule_name = rule["meta"]["name"]
            rule_namespace = rule["meta"].get("namespace")
            parent = CapaExplorerRuleItem(
                self.root_node, rule_name, rule_namespace, len(rule["matches"]), rule["source"]
            )

            for (location, match) in doc["rules"][rule["meta"]["name"]]["matches"].items():
                if rule["meta"]["scope"] == capa.rules.FILE_SCOPE:
                    parent2 = parent
                elif rule["meta"]["scope"] == capa.rules.FUNCTION_SCOPE:
                    parent2 = CapaExplorerFunctionItem(parent, location)
                elif rule["meta"]["scope"] == capa.rules.BASIC_BLOCK_SCOPE:
                    parent2 = CapaExplorerBlockItem(parent, location)
                else:
                    raise RuntimeError("unexpected rule scope: " + str(rule["meta"]["scope"]))

                self.render_capa_doc_match(parent2, match, doc)

    def render_capa_doc(self, doc, by_function):
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

    def capa_doc_feature_to_display(self, feature):
        """convert capa doc feature type string to display string for ui

        @param feature: capa feature read from doc
        """
        key = feature["type"]
        value = feature[feature["type"]]
        if value:
            if key == "string":
                value = '"%s"' % capa.features.common.escape_string(value)
            if feature.get("description", ""):
                return "%s(%s = %s)" % (key, value, feature["description"])
            else:
                return "%s(%s)" % (key, value)
        else:
            return "%s" % key

    def render_capa_doc_feature_node(self, parent, feature, locations, doc):
        """process capa doc feature node

        @param parent: parent node to which child is assigned
        @param feature: capa doc feature node
        @param locations: locations identified for feature
        @param doc: capa doc
        """
        display = self.capa_doc_feature_to_display(feature)

        if len(locations) == 1:
            # only one location for feature so no need to nest children
            parent2 = self.render_capa_doc_feature(
                parent,
                feature,
                next(iter(locations)),
                doc,
                display=display,
            )
        else:
            # feature has multiple children, nest  under one parent feature node
            parent2 = CapaExplorerFeatureItem(parent, display)

            for location in sorted(locations):
                self.render_capa_doc_feature(parent2, feature, location, doc)

        return parent2

    def render_capa_doc_feature(self, parent, feature, location, doc, display="-"):
        """render capa feature read from doc

        @param parent: parent node to which new child is assigned
        @param feature: feature read from doc
        @param doc: capa feature doc
        @param location: address of feature
        @param display: text to display in plugin UI
        """
        # special handling for characteristic pending type
        if feature["type"] == "characteristic":
            if feature[feature["type"]] in ("embedded pe",):
                return CapaExplorerByteViewItem(parent, display, location)

            if feature[feature["type"]] in ("loop", "recursive call", "tight loop"):
                return CapaExplorerFeatureItem(parent, display=display)

            # default to instruction view for all other characteristics
            return CapaExplorerInstructionViewItem(parent, display, location)

        if feature["type"] == "match":
            # display content of rule for all rule matches
            return CapaExplorerRuleMatchItem(
                parent, display, source=doc["rules"].get(feature[feature["type"]], {}).get("source", "")
            )

        if feature["type"] in ("regex", "substring"):
            for s, locations in feature["matches"].items():
                if location in locations:
                    return CapaExplorerStringViewItem(
                        parent, display, location, '"' + capa.features.common.escape_string(s) + '"'
                    )

            # programming error: the given location should always be found in the regex matches
            raise ValueError("regex match at location not found")

        if feature["type"] == "basicblock":
            return CapaExplorerBlockItem(parent, location)

        if feature["type"] in (
            "bytes",
            "api",
            "mnemonic",
            "number",
            "offset",
        ):
            # display instruction preview
            return CapaExplorerInstructionViewItem(parent, display, location)

        if feature["type"] in ("section",):
            # display byte preview
            return CapaExplorerByteViewItem(parent, display, location)

        if feature["type"] in ("string",):
            # display string preview
            return CapaExplorerStringViewItem(
                parent, display, location, '"%s"' % capa.features.common.escape_string(feature[feature["type"]])
            )

        if feature["type"] in ("import", "export", "function-name"):
            # display no preview
            return CapaExplorerFeatureItem(parent, location=location, display=display)

        if feature["type"] in ("arch", "os", "format"):
            return CapaExplorerFeatureItem(parent, display=display)

        raise RuntimeError("unexpected feature type: " + str(feature["type"]))

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
