# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from collections import Counter, defaultdict
import binascii

import idc
from PyQt5 import QtCore, QtWidgets, QtGui

import capa.ida.helpers
import capa.engine
import capa.rules

from capa.ida.plugin.item import CapaExplorerFunctionItem
from capa.ida.plugin.model import CapaExplorerDataModel

MAX_SECTION_SIZE = 750


def iterate_tree(o):
    """ """
    itr = QtWidgets.QTreeWidgetItemIterator(o)
    while itr.value():
        yield itr.value()
        itr += 1


def calc_item_depth(o):
    """ """
    depth = 0
    while True:
        parent = o.parent()
        if not parent:
            break
        depth += 1
        o = o.parent()
    return depth


def build_custom_action(o, display, data, slot):
    """ """
    action = QtWidgets.QAction(display, o)

    action.setData(data)
    action.triggered.connect(lambda checked: slot(action))

    return action


def build_custom_context_menu(o, actions):
    """ """
    menu = QtWidgets.QMenu()

    for action in actions:
        menu.addAction(build_custom_action(o, *action))

    return menu


class CapaExplorerRulgenPreview(QtWidgets.QTextEdit):
    def __init__(self, parent=None):
        """ """
        super(CapaExplorerRulgenPreview, self).__init__(parent)

        self.setFont(QtGui.QFont("Courier", weight=QtGui.QFont.Medium))

    def reset_view(self):
        """ """
        self.clear()

    def load_preview_meta(self, ea):
        """ """
        metadata_default = [
            "rule:",
            "  meta:",
            "    name: <insert_name>",
            "    namespace: <insert_namespace>",
            "    author: <insert_author>",
            "    scope: function",
            "    references: <insert_references>",
            "    examples:",
            "      - %s:0x%X" % (capa.ida.helpers.get_file_md5().upper(), capa.ida.helpers.get_func_start_ea(ea)),
            "  features:",
        ]
        self.setText("\n".join(metadata_default))


class CapaExplorerRulgenEditor(QtWidgets.QTreeWidget):
    def __init__(self, preview, parent=None):
        """ """
        super(CapaExplorerRulgenEditor, self).__init__(parent)

        self.preview = preview

        self.setHeaderHidden(True)
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.setStyleSheet("QTreeView::item {padding-right: 15 px;padding-bottom: 2 px;}")

        # enable drag and drop
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDragDropMode(QtWidgets.QAbstractItemView.InternalMove)

        # connect slots
        self.itemChanged.connect(self.slot_item_changed)
        self.customContextMenuRequested.connect(self.slot_custom_context_menu_requested)

        self.root = None
        self.reset_view()

    def dragMoveEvent(self, e):
        """ """
        super(CapaExplorerRulgenEditor, self).dragMoveEvent(e)

    def dragEventEnter(self, e):
        """ """
        super(CapaExplorerRulgenEditor, self).dragEventEnter(e)

    def dropEvent(self, e):
        """ """
        if not self.indexAt(e.pos()).isValid():
            return

        super(CapaExplorerRulgenEditor, self).dropEvent(e)

        self.prune_expressions()
        self.update_preview()
        self.expandAll()

    def reset_view(self):
        """ """
        self.root = None
        self.clear()

    def slot_item_changed(self, item, column):
        """ """
        self.update_preview()

    def slot_remove_selected_features(self, action):
        """ """
        for o in self.selectedItems():
            # do not remove root node from tree
            if o == self.root:
                continue
            o.parent().removeChild(o)

    def slot_nest_features(self, action):
        """ """
        new_parent = self.add_child_item(
            self.root,
            [action.data()[0]],
            drop_enabled=True,
            select_enabled=True,
            drag_enabled=True,
        )

        for o in self.selectedItems():
            if o.childCount():
                # do not attempt to nest parents, may lead to bad tree
                continue

            # find item's parent, take child from parent by index
            parent = o.parent()
            idx = parent.indexOfChild(o)
            item = parent.takeChild(idx)

            # add child to its new parent
            new_parent.addChild(item)

        # ensure new parent expanded
        new_parent.setExpanded(True)

    def slot_edit_expression(self, action):
        """ """
        expression, o = action.data()
        o.setText(0, expression)

    def slot_custom_context_menu_requested(self, pos):
        """ """
        if not self.indexAt(pos).isValid():
            return

        if not (self.itemAt(pos).flags() & QtCore.Qt.ItemIsEditable):
            # expression is no editable, so we use this property to choose menu type
            self.load_custom_context_menu_expression(pos)
        else:
            self.load_custom_context_menu_feature(pos)

        self.prune_expressions()
        self.update_preview()

    def update_preview(self):
        """ """
        rule_text = self.preview.toPlainText()
        rule_text = rule_text[: rule_text.find("features:") + len("features:")]
        rule_text += "\n"

        for o in iterate_tree(self):
            rule_text += "%s%s\n" % (" " * ((calc_item_depth(o) * 2) + 4), o.text(0))

        self.preview.setPlainText(rule_text)

    def load_custom_context_menu_feature(self, pos):
        """ """
        actions = (
            ("Remove selection", (), self.slot_remove_selected_features),
        )

        sub_actions = (
            ("and", ("- and:",), self.slot_nest_features),
            ("or", ("- or:",), self.slot_nest_features),
            ("not", ("- not:",), self.slot_nest_features),
            ("optional", ("- optional:",), self.slot_nest_features),
            ("basic block", ("- basic block:",), self.slot_nest_features),
        )

        sub_menu = build_custom_context_menu(self.parent(), sub_actions)
        sub_menu.setTitle("Nest feature%s" % ("" if len(self.selectedItems()) == 1 else "s"))

        menu = build_custom_context_menu(self.parent(), actions)
        menu.addMenu(sub_menu)

        menu.exec_(self.viewport().mapToGlobal(pos))

    def load_custom_context_menu_expression(self, pos):
        """ """
        sub_actions = (
            ("and", ("- and:", self.itemAt(pos)), self.slot_edit_expression),
            ("or", ("- or:", self.itemAt(pos)), self.slot_edit_expression),
            ("not", ("- not:", self.itemAt(pos)), self.slot_edit_expression),
            ("optional", ("- optional:", self.itemAt(pos)), self.slot_edit_expression),
            ("basic block", ("- basic block:", self.itemAt(pos)), self.slot_edit_expression),
        )

        actions = ()

        sub_menu = build_custom_context_menu(self.parent(), sub_actions)
        sub_menu.setTitle("Modify")

        if self.root != self.itemAt(pos):
            # only add remove option if not root
            actions = (("Remove expression", (), self.slot_remove_selected_features),)

        menu = build_custom_context_menu(self.parent(), actions)
        menu.addMenu(sub_menu)

        menu.exec_(self.viewport().mapToGlobal(pos))

    def add_child_item(
        self,
        parent,
        values,
        data=None,
        drop_enabled=False,
        edit_enabled=False,
        select_enabled=False,
        drag_enabled=False,
    ):
        """ """
        child = QtWidgets.QTreeWidgetItem(parent)

        if not select_enabled:
            child.setFlags(child.flags() & ~QtCore.Qt.ItemIsSelectable)
        if edit_enabled:
            child.setFlags(child.flags() | QtCore.Qt.ItemIsTristate | QtCore.Qt.ItemIsEditable)
        if not drop_enabled:
            child.setFlags(child.flags() & ~QtCore.Qt.ItemIsDropEnabled)
        if drag_enabled:
            child.setFlags(child.flags() | QtCore.Qt.ItemIsDragEnabled)

        for (i, v) in enumerate(values):
            child.setText(i, v)
            if data:
                child.setData(0, 0x100, data)

        return child

    def update_features(self, features):
        """ """
        if not self.root:
            self.root = self.add_child_item(self, ["- or:"], drop_enabled=True, select_enabled=True)
            self.root.setExpanded(True)

        counted = list(
            zip(Counter(features).keys(), Counter(features).values())  # equals to list(set(words))
        )  # counts the elements' frequency

        # single features
        for (k, v) in filter(lambda t: t[1] == 1, counted):
            r = "- %s: %s" % (k.name.lower(), k.get_value_str())
            self.add_child_item(self.root, [r], edit_enabled=True, select_enabled=True, drag_enabled=True)

        # counted features
        for (k, v) in filter(lambda t: t[1] > 1, counted):
            r = "- count(%s): %d" % (str(k), v)
            self.add_child_item(self.root, [r], edit_enabled=True, select_enabled=True, drag_enabled=True)

        self.update_preview()

    def prune_expressions(self):
        """ """
        for o in iterate_tree(self):
            if o == self.root:
                # do not prune root
                continue
            if o.flags() & QtCore.Qt.ItemIsEditable:
                # only expressions are not editable, so we use this flag to distinguish items
                continue
            if not o.childCount():
                # if no children, prune
                o.parent().removeChild(o)


class CapaExplorerRulegenFeatures(QtWidgets.QTreeWidget):
    def __init__(self, editor, parent=None):
        """ """
        super(CapaExplorerRulegenFeatures, self).__init__(parent)

        self.parent_items = {}
        self.editor = editor

        self.setHeaderLabels(["Feature", "Virtual Address"])
        self.header().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        self.setStyleSheet("QTreeView::item {padding-right: 15 px;padding-bottom: 2 px;}")

        self.setExpandsOnDoubleClick(False)
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)

        # connect slots
        self.itemDoubleClicked.connect(self.slot_item_double_clicked)
        self.customContextMenuRequested.connect(self.slot_custom_context_menu_requested)

        self.reset_view()

    def reset_view(self):
        """ """
        self.clear()

    def slot_add_selected_features(self, action):
        """ """
        selected = [item.data(0, 0x100) for item in self.selectedItems()]
        if selected:
            self.editor.update_features(selected)

    def slot_custom_context_menu_requested(self, pos):
        """ """
        actions = []
        action_add_features_fmt = ""

        selected_items_count = len(self.selectedItems())
        if selected_items_count == 0:
            return

        if selected_items_count == 1:
            action_add_features_fmt = "Add feature"
        else:
            action_add_features_fmt = "Add %d features" % selected_items_count

        actions.append((action_add_features_fmt, (), self.slot_add_selected_features))

        menu = build_custom_context_menu(self.parent(), actions)
        menu.exec_(self.viewport().mapToGlobal(pos))

    def slot_item_double_clicked(self, o, column):
        """ """
        if column == 1:
            idc.jumpto(int(o.text(column), 0x10))
            return

    def add_child_item(self, parent, values, feature=None, selectable=False):
        """ """
        child = QtWidgets.QTreeWidgetItem(parent)
        child.setFlags(child.flags() | QtCore.Qt.ItemIsTristate)

        if not selectable:
            child.setFlags(child.flags() & ~QtCore.Qt.ItemIsSelectable)

        for (i, v) in enumerate(values):
            child.setText(i, v)
            if feature:
                child.setData(0, 0x100, feature)

        return child

    def load_features(self, features):
        """ """
        self.parent_items = {}

        for (feature, eas) in sorted(features.items(), key=lambda k: sorted(k[1])):
            # level 0
            if type(feature) not in self.parent_items:
                self.parent_items[type(feature)] = self.add_child_item(self, [feature.name.lower()])

            # level 1
            if feature not in self.parent_items:
                selectable = False if len(eas) > 1 else True
                self.parent_items[feature] = self.add_child_item(
                    self.parent_items[type(feature)], [str(feature)], selectable=selectable
                )

            # level n > 1
            if len(eas) > 1:
                for ea in sorted(eas):
                    self.add_child_item(
                        self.parent_items[feature], [str(feature), "0x%X" % ea], feature, selectable=True
                    )
            else:
                ea = eas.pop()
                self.parent_items[feature].setText(0, str(feature))
                self.parent_items[feature].setText(1, "0x%X" % ea)
                self.parent_items[feature].setData(0, 0x100, feature)


class CapaExplorerQtreeView(QtWidgets.QTreeView):
    """tree view used to display hierarchical capa results

    view controls UI action responses and displays data from CapaExplorerDataModel

    view does not modify CapaExplorerDataModel directly - data modifications should be implemented
    in CapaExplorerDataModel
    """

    def __init__(self, model, parent=None):
        """initialize view"""
        super(CapaExplorerQtreeView, self).__init__(parent)

        self.setModel(model)

        self.model = model
        self.parent = parent

        # control when we resize columns
        self.should_resize_columns = True

        # configure custom UI controls
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.setExpandsOnDoubleClick(False)
        self.setSortingEnabled(True)
        self.model.setDynamicSortFilter(False)

        # configure view columns to auto-resize
        for idx in range(CapaExplorerDataModel.COLUMN_COUNT):
            self.header().setSectionResizeMode(idx, QtWidgets.QHeaderView.Interactive)

        # disable stretch to enable horizontal scroll for last column, when needed
        self.header().setStretchLastSection(False)

        # connect slots to resize columns when expanded or collapsed
        self.expanded.connect(self.slot_resize_columns_to_content)
        self.collapsed.connect(self.slot_resize_columns_to_content)

        # connect slots
        self.customContextMenuRequested.connect(self.slot_custom_context_menu_requested)
        self.doubleClicked.connect(self.slot_double_click)

        self.setStyleSheet("QTreeView::item {padding-right: 15 px;padding-bottom: 2 px;}")

    def reset_ui(self, should_sort=True):
        """reset user interface changes

        called when view should reset UI display e.g. expand items, resize columns

        @param should_sort: True, sort results after reset, False don't sort results after reset
        """
        if should_sort:
            self.sortByColumn(CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION, QtCore.Qt.AscendingOrder)

        self.should_resize_columns = False
        self.expandToDepth(0)
        self.should_resize_columns = True

        self.slot_resize_columns_to_content()

    def slot_resize_columns_to_content(self):
        """reset view columns to contents"""
        if self.should_resize_columns:
            self.header().resizeSections(QtWidgets.QHeaderView.ResizeToContents)

            # limit size of first section
            if self.header().sectionSize(0) > MAX_SECTION_SIZE:
                self.header().resizeSection(0, MAX_SECTION_SIZE)

    def map_index_to_source_item(self, model_index):
        """map proxy model index to source model item

        @param model_index: QModelIndex

        @retval QObject
        """
        # assume that self.model here is either:
        #  - CapaExplorerDataModel, or
        #  - QSortFilterProxyModel subclass
        #
        # The ProxyModels may be chained,
        #  so keep resolving the index the CapaExplorerDataModel.

        model = self.model
        while not isinstance(model, CapaExplorerDataModel):
            if not model_index.isValid():
                raise ValueError("invalid index")

            model_index = model.mapToSource(model_index)
            model = model.sourceModel()

        if not model_index.isValid():
            raise ValueError("invalid index")

        return model_index.internalPointer()

    def send_data_to_clipboard(self, data):
        """copy data to the clipboard

        @param data: data to be copied
        """
        clip = QtWidgets.QApplication.clipboard()
        clip.clear(mode=clip.Clipboard)
        clip.setText(data, mode=clip.Clipboard)

    def new_action(self, display, data, slot):
        """create action for context menu

        @param display: text displayed to user in context menu
        @param data: data passed to slot
        @param slot: slot to connect

        @retval QAction
        """
        action = QtWidgets.QAction(display, self.parent)
        action.setData(data)
        action.triggered.connect(lambda checked: slot(action))

        return action

    def load_default_context_menu_actions(self, data):
        """yield actions specific to function custom context menu

        @param data: tuple

        @yield QAction
        """
        default_actions = (
            ("Copy column", data, self.slot_copy_column),
            ("Copy row", data, self.slot_copy_row),
        )

        # add default actions
        for action in default_actions:
            yield self.new_action(*action)

    def load_function_context_menu_actions(self, data):
        """yield actions specific to function custom context menu

        @param data: tuple

        @yield QAction
        """
        function_actions = (("Rename function", data, self.slot_rename_function),)

        # add function actions
        for action in function_actions:
            yield self.new_action(*action)

        # add default actions
        for action in self.load_default_context_menu_actions(data):
            yield action

    def load_default_context_menu(self, pos, item, model_index):
        """create default custom context menu

        creates custom context menu containing default actions

        @param pos: cursor position
        @param item: CapaExplorerDataItem
        @param model_index: QModelIndex

        @retval QMenu
        """
        menu = QtWidgets.QMenu()

        for action in self.load_default_context_menu_actions((pos, item, model_index)):
            menu.addAction(action)

        return menu

    def load_function_item_context_menu(self, pos, item, model_index):
        """create function custom context menu

        creates custom context menu with both default actions and function actions

        @param pos: cursor position
        @param item: CapaExplorerDataItem
        @param model_index: QModelIndex

        @retval QMenu
        """
        menu = QtWidgets.QMenu()

        for action in self.load_function_context_menu_actions((pos, item, model_index)):
            menu.addAction(action)

        return menu

    def show_custom_context_menu(self, menu, pos):
        """display custom context menu in view

        @param menu: QMenu to display
        @param pos: cursor position
        """
        if menu:
            menu.exec_(self.viewport().mapToGlobal(pos))

    def slot_copy_column(self, action):
        """slot connected to custom context menu

        allows user to select a column and copy the data to clipboard

        @param action: QAction
        """
        _, item, model_index = action.data()
        self.send_data_to_clipboard(item.data(model_index.column()))

    def slot_copy_row(self, action):
        """slot connected to custom context menu

        allows user to select a row and copy the space-delimited data to clipboard

        @param action: QAction
        """
        _, item, _ = action.data()
        self.send_data_to_clipboard(str(item))

    def slot_rename_function(self, action):
        """slot connected to custom context menu

        allows user to select a edit a function name and push changes to IDA

        @param action: QAction
        """
        _, item, model_index = action.data()

        # make item temporary edit, reset after user is finished
        item.setIsEditable(True)
        self.edit(model_index)
        item.setIsEditable(False)

    def slot_custom_context_menu_requested(self, pos):
        """slot connected to custom context menu request

        displays custom context menu to user containing action relevant to the item selected

        @param pos: cursor position
        """
        model_index = self.indexAt(pos)

        if not model_index.isValid():
            return

        item = self.map_index_to_source_item(model_index)

        column = model_index.column()
        menu = None

        if CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION == column and isinstance(item, CapaExplorerFunctionItem):
            # user hovered function item
            menu = self.load_function_item_context_menu(pos, item, model_index)
        else:
            # user hovered default item
            menu = self.load_default_context_menu(pos, item, model_index)

        # show custom context menu at view position
        self.show_custom_context_menu(menu, pos)

    def slot_double_click(self, model_index):
        """slot connected to double-click event

        if address column clicked, navigate IDA to address, else un/expand item clicked

        @param model_index: QModelIndex
        """
        if not model_index.isValid():
            return

        item = self.map_index_to_source_item(model_index)
        column = model_index.column()

        if CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS == column and item.location:
            # user double-clicked virtual address column - navigate IDA to address
            idc.jumpto(item.location)

        if CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION == column:
            # user double-clicked information column - un/expand
            self.collapse(model_index) if self.isExpanded(model_index) else self.expand(model_index)
