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

# default colors used in views
COLOR_GREEN_RGB = (79, 121, 66)
COLOR_BLUE_RGB = (37, 147, 215)


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
        if not o.parent():
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

        self.setFont(QtGui.QFont("Courier", weight=QtGui.QFont.Bold))

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

        self.setHeaderLabels(["Feature", "Description"])
        self.header().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        self.setExpandsOnDoubleClick(False)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
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
        self.itemDoubleClicked.connect(self.slot_item_double_clicked)

        self.root = None
        self.reset_view()

    @staticmethod
    def get_column_feature_index():
        """ """
        return 0

    @staticmethod
    def get_column_description_index():
        """ """
        return 1

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

    def slot_remove_selected(self, action):
        """ """
        for o in self.selectedItems():
            # do not remove root node from tree
            if o == self.root:
                continue
            o.parent().removeChild(o)

    def slot_nest_features(self, action):
        """ """
        # create a new parent under root node, by default; new node added last position in tree
        new_parent = self.add_child_item(
            self.root,
            (action.data()[0], ""),
            drop_enabled=True,
            select_enabled=True,
            drag_enabled=True,
            has_children=True,
        )

        for o in self.get_features(selected=True):
            # take child from its parent by index, add to new parent
            new_parent.addChild(o.parent().takeChild(o.parent().indexOfChild(o)))

        # ensure new parent expanded
        new_parent.setExpanded(True)

    def slot_edit_expression(self, action):
        """ """
        expression, o = action.data()
        o.setText(CapaExplorerRulgenEditor.get_column_feature_index(), expression)

    def slot_clear_all(self, action):
        """ """
        self.reset_view()

    def slot_custom_context_menu_requested(self, pos):
        """ """
        if not self.indexAt(pos).isValid():
            # user selected invalid index
            self.load_custom_context_menu_invalid_index(pos)
        elif not self.itemAt(pos).flags() & QtCore.Qt.ItemIsEditable:
            # user selected expression node
            self.load_custom_context_menu_expression(pos)
        else:
            # user selected feature node
            self.load_custom_context_menu_feature(pos)

        # refresh views
        self.prune_expressions()
        self.update_preview()

    def slot_item_double_clicked(self, o, column):
        """ """
        if o.flags() & QtCore.Qt.ItemIsEditable:
            self.editItem(o, column)
        else:
            if column == CapaExplorerRulgenEditor.get_column_description_index():
                o.setFlags(o.flags() | QtCore.Qt.ItemIsEditable)
                self.editItem(o, column)
                o.setFlags(o.flags() & ~QtCore.Qt.ItemIsEditable)

    def update_preview(self):
        """ """
        rule_text = self.preview.toPlainText()
        rule_text = rule_text[: rule_text.find("features:") + len("features:")]
        rule_text += "\n"

        for o in iterate_tree(self):
            display = o.text(CapaExplorerRulgenEditor.get_column_feature_index())
            description = o.text(CapaExplorerRulgenEditor.get_column_description_index())
            depth_space = (calc_item_depth(o) * 2) + 4

            if not description:
                rule_text += "%s%s\n" % (" " * depth_space, display)
            else:
                if display.startswith(("- and", "- or", "- optional", "- basic block", "- not")):
                    rule_text += "%s%s\n" % (" " * depth_space, display)
                    rule_text += "%s- description: %s\n" % (" " * (depth_space + 2), description)
                elif display.startswith("- string"):
                    rule_text += "%s%s\n" % (" " * depth_space, display)
                    rule_text += "%sdescription: %s\n" % (" " * (depth_space + 2), description)
                else:
                    rule_text += "%s%s = %s\n" % (" " * depth_space, display, description)

        self.preview.setPlainText(rule_text)

    def load_custom_context_menu_invalid_index(self, pos):
        """ """
        actions = (("Remove all", (), self.slot_clear_all),)

        menu = build_custom_context_menu(self.parent(), actions)
        menu.exec_(self.viewport().mapToGlobal(pos))

    def load_custom_context_menu_feature(self, pos):
        """ """
        # sub_sub_actions = []

        actions = (("Remove selection", (), self.slot_remove_selected),)

        sub_actions = (
            ("and", ("- and:",), self.slot_nest_features),
            ("or", ("- or:",), self.slot_nest_features),
            ("not", ("- not:",), self.slot_nest_features),
            ("optional", ("- optional:",), self.slot_nest_features),
            ("basic block", ("- basic block:",), self.slot_nest_features),
        )

        feature_count = len(tuple(self.get_features(selected=True)))

        """
        for i in range(feature_count + 1):
            sub_sub_actions.append(("%d or more" % i, ("- %d or more:" % i,), self.slot_nest_features))

        sub_sub_menu = build_custom_context_menu(self.parent(), sub_sub_actions)
        sub_sub_menu.setTitle("N or more")
        """

        sub_menu = build_custom_context_menu(self.parent(), sub_actions)
        sub_menu.setTitle("Nest feature%s" % ("" if feature_count == 1 else "s"))
        # sub_menu.addMenu(sub_sub_menu)

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

        actions = []

        sub_menu = build_custom_context_menu(self.parent(), sub_actions)
        sub_menu.setTitle("Modify")

        if self.root != self.itemAt(pos):
            # only add remove option if not root
            actions.append(("Remove expression", (), self.slot_remove_selected))

        menu = build_custom_context_menu(self.parent(), actions)
        menu.addMenu(sub_menu)

        menu.exec_(self.viewport().mapToGlobal(pos))

    def style_parent_node(self, o):
        """ """
        font = QtGui.QFont()
        font.setBold(True)

        o.setFont(CapaExplorerRulgenEditor.get_column_feature_index(), font)

    def style_child_node(self, o):
        """ """
        font = QtGui.QFont()
        brush = QtGui.QBrush()

        font.setFamily("Courier")
        font.setWeight(QtGui.QFont.Medium)
        brush.setColor(QtGui.QColor(*COLOR_GREEN_RGB))

        o.setFont(CapaExplorerRulgenEditor.get_column_feature_index(), font)
        o.setForeground(CapaExplorerRulgenEditor.get_column_feature_index(), brush)

    def add_child_item(
        self,
        parent,
        values,
        data=None,
        drop_enabled=False,
        edit_enabled=False,
        select_enabled=False,
        drag_enabled=False,
        has_children=False,
    ):
        """ """
        c = QtWidgets.QTreeWidgetItem(parent)

        if has_children:
            # adding expression node, set bold
            self.style_parent_node(c)
        else:
            # adding feature node, set style, weight, and color
            self.style_child_node(c)

        if not select_enabled:
            c.setFlags(c.flags() & ~QtCore.Qt.ItemIsSelectable)
        if edit_enabled:
            c.setFlags(c.flags() | QtCore.Qt.ItemIsTristate | QtCore.Qt.ItemIsEditable)
        if not drop_enabled:
            c.setFlags(c.flags() & ~QtCore.Qt.ItemIsDropEnabled)
        if drag_enabled:
            c.setFlags(c.flags() | QtCore.Qt.ItemIsDragEnabled)

        for (i, v) in enumerate(values):
            c.setText(i, v)

        if data:
            c.setData(0, 0x100, data)

        return c

    def update_features(self, features):
        """ """
        if not self.root:
            # root node does not exist, create default node, set expanded
            self.root = self.add_child_item(
                self, ("- or:", ""), drop_enabled=True, select_enabled=True, has_children=True
            )
            self.root.setExpanded(True)

        # build feature counts
        counted = list(zip(Counter(features).keys(), Counter(features).values()))

        # single features
        for (k, v) in filter(lambda t: t[1] == 1, counted):
            display = "- %s: %s" % (k.name.lower(), k.get_value_str())
            self.add_child_item(self.root, (display, ""), edit_enabled=True, select_enabled=True, drag_enabled=True)

        # n > 1 features
        for (k, v) in filter(lambda t: t[1] > 1, counted):
            display = "- count(%s): %d" % (str(k), v)
            self.add_child_item(self.root, (display, ""), edit_enabled=True, select_enabled=True, drag_enabled=True)

        self.update_preview()

    def prune_expressions(self):
        """ """
        for o in self.get_expressions(ignore=(self.root,)):
            if not o.childCount():
                o.parent().removeChild(o)

    def get_features(self, selected=False, ignore=()):
        """ """
        for feature in filter(lambda o: o.flags() & QtCore.Qt.ItemIsEditable, tuple(iterate_tree(self))):
            if feature in ignore:
                continue
            if selected and not feature.isSelected():
                continue
            yield feature

    def get_expressions(self, selected=False, ignore=()):
        """ """
        for expression in filter(lambda o: not o.flags() & QtCore.Qt.ItemIsEditable, tuple(iterate_tree(self))):
            if expression in ignore:
                continue
            if selected and not expression.isSelected():
                continue
            yield expression


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

    @staticmethod
    def get_column_feature_index():
        """ """
        return 0

    @staticmethod
    def get_column_address_index():
        """ """
        return 1

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
        if column == CapaExplorerRulegenFeatures.get_column_address_index() and o.text(column):
            idc.jumpto(int(o.text(column), 0x10))

    def show_all_items(self):
        """ """
        for o in iterate_tree(self):
            o.setHidden(False)
            o.setExpanded(False)

    def filter_items_by_text(self, text):
        """ """
        if not text:
            self.show_all_items()
        else:
            for o in iterate_tree(self):
                data = o.data(0, 0x100)
                if data and text.lower() not in data.get_value_str().lower():
                    o.setHidden(True)
                    continue
                o.setHidden(False)
                o.setExpanded(True)

    def style_parent_node(self, o):
        """ """
        font = QtGui.QFont()
        font.setBold(True)

        o.setFont(CapaExplorerRulegenFeatures.get_column_feature_index(), font)

    def style_child_node(self, o):
        """ """
        font = QtGui.QFont("Courier", weight=QtGui.QFont.Bold)
        brush = QtGui.QBrush()

        o.setFont(CapaExplorerRulegenFeatures.get_column_feature_index(), font)
        o.setFont(CapaExplorerRulegenFeatures.get_column_address_index(), font)

        brush.setColor(QtGui.QColor(*COLOR_GREEN_RGB))
        o.setForeground(CapaExplorerRulegenFeatures.get_column_feature_index(), brush)

        brush.setColor(QtGui.QColor(*COLOR_BLUE_RGB))
        o.setForeground(CapaExplorerRulegenFeatures.get_column_address_index(), brush)

    def add_child_item(self, parent, values, feature=None, has_children=False):
        """ """
        c = QtWidgets.QTreeWidgetItem(parent)

        if has_children:
            self.style_parent_node(c)
            c.setFlags(c.flags() & ~QtCore.Qt.ItemIsSelectable)
        else:
            self.style_child_node(c)

        for (i, v) in enumerate(values):
            c.setText(i, v)

        if feature:
            c.setData(0, 0x100, feature)

        return c

    def load_features(self, features):
        """ """
        self.parent_items = {}

        for (feature, eas) in sorted(features.items(), key=lambda k: sorted(k[1])):
            # level 0
            if type(feature) not in self.parent_items:
                self.parent_items[type(feature)] = self.add_child_item(self, (feature.name.lower(),), has_children=True)

            # level 1
            if feature not in self.parent_items:
                self.parent_items[feature] = self.add_child_item(
                    self.parent_items[type(feature)],
                    (str(feature),),
                    feature=feature,
                    has_children=True if len(eas) > 1 else False,
                )

            # level n > 1
            if len(eas) > 1:
                for ea in sorted(eas):
                    self.add_child_item(
                        self.parent_items[feature], (str(feature), "%X" % ea), feature=feature, has_children=False
                    )
            else:
                ea = eas.pop()
                self.parent_items[feature].setText(0, str(feature))
                self.parent_items[feature].setText(1, "%X" % ea)
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
