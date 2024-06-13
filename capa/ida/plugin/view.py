# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import re
from typing import Dict, Optional
from collections import Counter

import idc
import idaapi
from PyQt5 import QtGui, QtCore, QtWidgets

import capa.rules
import capa.engine
import capa.ida.helpers
import capa.features.common
import capa.features.basicblock
from capa.ida.plugin.item import CapaExplorerFunctionItem
from capa.features.address import AbsoluteVirtualAddress, _NoAddress
from capa.ida.plugin.model import CapaExplorerDataModel

MAX_SECTION_SIZE = 750

# default colors used in views
COLOR_GREEN_RGB = (79, 121, 66)
COLOR_BLUE_RGB = (37, 147, 215)


def calc_indent_from_line(line, prev_level=0):
    """ """
    if not len(line.strip()):
        # blank line, which may occur for comments so we simply use the last level
        return prev_level
    stripped = line.lstrip()
    if stripped.startswith("description"):
        # need to adjust two spaces when encountering string description
        line = line[2:]
    # calc line level based on preceding whitespace
    indent = len(line) - len(stripped)

    # round up to nearest even number; helps keep parsing more sane
    return indent + (indent % 2)


def parse_yaml_line(feature):
    """ """
    description = ""
    comment = ""

    if feature.startswith("- count"):
        # count is weird, we need to handle special
        # first, we need to grab the comment, if exists
        # next, we need to check for an embedded description
        feature, _, comment = feature.partition("#")
        m = re.search(r"- count\(([a-zA-Z]+)\((.+)\s+=\s+(.+)\)\):\s*(.+)", feature)
        if m:
            # reconstruct count without description
            feature, value, description, count = m.groups()
            feature = f"- count({feature}({value})): {count}"
    elif not feature.startswith("#"):
        feature, _, comment = feature.partition("#")
        feature, _, description = feature.partition("=")

    return (o.strip() for o in (feature, description, comment))


def parse_node_for_feature(feature, description, comment, depth):
    """ """
    depth = (depth * 2) + 4
    display = ""

    if feature.startswith("#"):
        display += f"{' '*depth}{feature}\n"
    elif description:
        if feature.startswith(("- and", "- or", "- optional", "- basic block", "- not", "- instruction:")):
            display += f"{' '*depth}{feature}\n"
            if comment:
                display += f" # {comment}"
            display += f"\n{' '*(depth+2)}- description: {description}\n"
        elif feature.startswith("- string"):
            display += f"{' '*depth}{feature}\n"
            if comment:
                display += f" # {comment}"
            display += f"\n{' '*(depth+2)}description: {description}\n"
        elif feature.startswith("- count"):
            # count is weird, we need to format description based on feature type, so we parse with regex
            # assume format - count(<feature_name>(<feature_value>)): <count>
            m = re.search(r"- count\(([a-zA-Z]+)\((.+)\)\): (.+)", feature)
            if m:
                name, value, count = m.groups()
                if name in ("string",):
                    display += f"{' '*depth}{feature}"
                    if comment:
                        display += f" # {comment}"
                    display += f"\n{' '*(depth+2)}description: {description}\n"
                else:
                    display += f"{' '*depth}- count({name}({value} = {description})): {count}"
                    if comment:
                        display += f" # {comment}\n"
        else:
            display += f"{' '*depth}{feature} = {description}"
            if comment:
                display += f" # {comment}\n"
    else:
        display += f"{' '*depth}{feature}"
        if comment:
            display += f" # {comment}\n"

    return display if display.endswith("\n") else display + "\n"


def iterate_tree(o):
    """ """
    itr = QtWidgets.QTreeWidgetItemIterator(o)
    while itr.value():
        yield itr.value()
        itr += 1


def expand_tree(root):
    """ """
    for node in iterate_tree(root):
        if node.childCount() and not node.isExpanded():
            node.setExpanded(True)


def calc_item_depth(o):
    """ """
    depth = 0
    while True:
        if not o.parent():
            break
        depth += 1
        o = o.parent()
    return depth


def build_action(o, display, data, slot):
    """ """
    action = QtWidgets.QAction(display, o)

    action.setData(data)
    action.triggered.connect(lambda checked: slot(action))

    return action


def build_context_menu(o, actions):
    """ """
    menu = QtWidgets.QMenu()

    for action in actions:
        if isinstance(action, QtWidgets.QMenu):
            menu.addMenu(action)
        else:
            menu.addAction(build_action(o, *action))

    return menu


def resize_columns_to_content(header):
    """ """
    header.resizeSections(QtWidgets.QHeaderView.ResizeToContents)
    if header.sectionSize(0) > MAX_SECTION_SIZE:
        header.resizeSection(0, MAX_SECTION_SIZE)


class CapaExplorerRulegenPreview(QtWidgets.QTextEdit):
    INDENT = " " * 2

    def __init__(self, parent=None):
        """ """
        super().__init__(parent)

        self.setFont(QtGui.QFont("Courier", weight=QtGui.QFont.Bold))
        self.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        self.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        self.setAcceptRichText(False)

    def reset_view(self):
        """ """
        self.clear()

    def load_preview_meta(self, ea, author, scope):
        """ """
        metadata_default = [
            "# generated using capa explorer for IDA Pro",
            "rule:",
            "  meta:",
            "    name: <insert_name>",
            "    namespace: <insert_namespace>",
            "    authors:",
            f"      - {author}",
            "    scopes:",
            f"      static: {scope}",
            "      dynamic: unsupported",
            "    references:",
            "      - <insert_references>",
            "    examples:",
            (
                f"      - {capa.ida.helpers.get_file_md5().upper()}:{hex(ea)}"
                if ea
                else f"      - {capa.ida.helpers.get_file_md5().upper()}"
            ),
            "  features:",
        ]
        self.setText("\n".join(metadata_default))

    def keyPressEvent(self, e):
        """intercept key press events"""
        if e.key() in (QtCore.Qt.Key_Tab, QtCore.Qt.Key_Backtab):
            # apparently it's not easy to implement tabs as spaces, or multi-line tab or SHIFT + Tab
            # so we need to implement it ourselves so we can retain properly formatted capa rules
            # when a user uses the Tab key
            if self.textCursor().selection().isEmpty():
                # single line, only worry about Tab
                if e.key() == QtCore.Qt.Key_Tab:
                    self.insertPlainText(self.INDENT)
            else:
                # multi-line tab or SHIFT + Tab
                cur = self.textCursor()
                select_start_ppos = cur.selectionStart()
                select_end_ppos = cur.selectionEnd()

                scroll_ppos = self.verticalScrollBar().sliderPosition()

                # determine lineno for first selected line, and column
                cur.setPosition(select_start_ppos)
                start_lineno = self.count_previous_lines_from_block(cur.block())
                start_lineco = cur.columnNumber()

                # determine lineno for last selected line
                cur.setPosition(select_end_ppos)
                end_lineno = self.count_previous_lines_from_block(cur.block())

                # now we need to indent or dedent the selected lines. for now, we read the text, modify
                # the lines between start_lineno and end_lineno accordingly, and then reset the view
                # this might not be the best solution, but it avoids messing around with cursor positions
                # to determine the beginning of lines

                plain = self.toPlainText().splitlines()

                if e.key() == QtCore.Qt.Key_Tab:
                    # user Tab, indent selected lines
                    lines_modified = end_lineno - start_lineno
                    first_modified = True
                    change = [self.INDENT + line for line in plain[start_lineno : end_lineno + 1]]
                else:
                    # user SHIFT + Tab, dedent selected lines
                    lines_modified = 0
                    first_modified = False
                    change = []
                    for lineno, line in enumerate(plain[start_lineno : end_lineno + 1]):
                        if line.startswith(self.INDENT):
                            if lineno == 0:
                                # keep track if first line is modified, so we can properly display
                                # the text selection later
                                first_modified = True
                            lines_modified += 1
                            line = line[len(self.INDENT) :]
                        change.append(line)

                # apply modifications, and reset view
                plain[start_lineno : end_lineno + 1] = change
                self.setPlainText("\n".join(plain) + "\n")

                # now we need to properly adjust the selection positions, so users don't have to
                # re-select when indenting or dedenting the same lines repeatedly
                if e.key() == QtCore.Qt.Key_Tab:
                    # user Tab, increase increment selection positions
                    select_start_ppos += len(self.INDENT)
                    select_end_ppos += (lines_modified * len(self.INDENT)) + len(self.INDENT)
                elif lines_modified:
                    # user SHIFT + Tab, decrease selection positions
                    if start_lineco not in (0, 1) and first_modified:
                        # only decrease start position if not in first column
                        select_start_ppos -= len(self.INDENT)
                    select_end_ppos -= lines_modified * len(self.INDENT)

                # apply updated selection and restore previous scroll position
                self.set_selection(select_start_ppos, select_end_ppos, len(self.toPlainText()))
                self.verticalScrollBar().setSliderPosition(scroll_ppos)
        else:
            super().keyPressEvent(e)

    def count_previous_lines_from_block(self, block):
        """calculate number of lines preceding block"""
        count = 0
        while True:
            block = block.previous()
            if not block.isValid():
                break
            count += block.lineCount()
        return count

    def set_selection(self, start, end, max):
        """set text selection"""
        cursor = self.textCursor()
        cursor.setPosition(start)
        cursor.setPosition(end if end < max else max, QtGui.QTextCursor.KeepAnchor)
        self.setTextCursor(cursor)


class CapaExplorerRulegenEditor(QtWidgets.QTreeWidget):
    updated = QtCore.pyqtSignal()

    def __init__(self, preview, parent=None):
        """ """
        super().__init__(parent)

        self.preview = preview

        self.setHeaderLabels(["Feature", "Description", "Comment"])
        self.header().setStretchLastSection(False)
        self.setExpandsOnDoubleClick(False)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.setStyleSheet("QTreeView::item {padding-right: 15 px;padding-bottom: 2 px;}")

        # configure view columns to auto-resize
        for idx in range(3):
            self.header().setSectionResizeMode(idx, QtWidgets.QHeaderView.Interactive)

        # enable drag and drop
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDragDropMode(QtWidgets.QAbstractItemView.InternalMove)

        # connect slots
        self.itemChanged.connect(self.slot_item_changed)
        self.customContextMenuRequested.connect(self.slot_custom_context_menu_requested)
        self.itemDoubleClicked.connect(self.slot_item_double_clicked)
        self.expanded.connect(self.slot_resize_columns_to_content)
        self.collapsed.connect(self.slot_resize_columns_to_content)

        self.reset_view()

        self.is_editing = False

    @staticmethod
    def get_column_feature_index():
        """ """
        return 0

    @staticmethod
    def get_column_description_index():
        """ """
        return 1

    @staticmethod
    def get_column_comment_index():
        """ """
        return 2

    @staticmethod
    def get_node_type_expression():
        """ """
        return 0

    @staticmethod
    def get_node_type_feature():
        """ """
        return 1

    @staticmethod
    def get_node_type_comment():
        """ """
        return 2

    def dragMoveEvent(self, e):
        """ """
        super().dragMoveEvent(e)

    def dragEventEnter(self, e):
        """ """
        super().dragEventEnter(e)

    def dropEvent(self, e):
        """ """
        if not self.indexAt(e.pos()).isValid():
            return

        super().dropEvent(e)

        self.update_preview()
        expand_tree(self.invisibleRootItem())

    def reset_view(self):
        """ """
        self.clear()

    def slot_resize_columns_to_content(self):
        """ """
        resize_columns_to_content(self.header())

    def slot_item_changed(self, item, column):
        """ """
        if self.is_editing:
            self.update_preview()
            self.is_editing = False

    def slot_remove_selected(self, action):
        """ """
        for o in self.selectedItems():
            if o.parent() is None:
                # special handling for top-level items
                self.takeTopLevelItem(self.indexOfTopLevelItem(o))
                continue
            o.parent().removeChild(o)

    def slot_nest_features(self, action):
        """ """
        # we don't want to add new features under the invisible root because capa rules should
        # contain a single top-level node; this may not always be the case so we default to the last
        # child node that was added to the invisible root
        top_node = self.invisibleRootItem().child(self.invisibleRootItem().childCount() - 1)

        # create a new parent under top-level node
        new_parent = self.new_expression_node(top_node, (action.data()[0], ""))

        if "basic block" in action.data()[0]:
            # add default child expression when nesting under basic block
            new_parent.setExpanded(True)
            new_parent = self.new_expression_node(new_parent, ("- or:", ""))
        elif "instruction" in action.data()[0]:
            # add default child expression when nesting under instruction
            new_parent.setExpanded(True)
            new_parent = self.new_expression_node(new_parent, ("- or:", ""))

        for o in self.get_features(selected=True):
            # take child from its parent by index, add to new parent
            new_parent.addChild(o.parent().takeChild(o.parent().indexOfChild(o)))

        # ensure new parent expanded
        new_parent.setExpanded(True)

    def slot_edit_expression(self, action):
        """ """
        expression, o = action.data()
        if "basic block" in expression and "basic block" not in o.text(
            CapaExplorerRulegenEditor.get_column_feature_index()
        ):
            # current expression is "basic block", and not changing to "basic block" expression
            children = o.takeChildren()
            new_parent = self.new_expression_node(o, ("- or:", ""))
            for child in children:
                new_parent.addChild(child)
            new_parent.setExpanded(True)
        elif "instruction" in expression and "instruction" not in o.text(
            CapaExplorerRulegenEditor.get_column_feature_index()
        ):
            # current expression is "instruction", and not changing to "instruction" expression
            children = o.takeChildren()
            new_parent = self.new_expression_node(o, ("- or:", ""))
            for child in children:
                new_parent.addChild(child)
            new_parent.setExpanded(True)

        o.setText(CapaExplorerRulegenEditor.get_column_feature_index(), expression)

    def slot_clear_all(self, action):
        """ """
        self.reset_view()

    def slot_custom_context_menu_requested(self, pos):
        """ """
        if not self.indexAt(pos).isValid():
            # user selected invalid index
            self.load_custom_context_menu_invalid_index(pos)
        elif self.itemAt(pos).capa_type == CapaExplorerRulegenEditor.get_node_type_expression():
            # user selected expression node
            self.load_custom_context_menu_expression(pos)
        else:
            # user selected feature node
            self.load_custom_context_menu_feature(pos)

        self.update_preview()

    def slot_item_double_clicked(self, o, column):
        """ """
        if column in (
            CapaExplorerRulegenEditor.get_column_comment_index(),
            CapaExplorerRulegenEditor.get_column_description_index(),
        ):
            o.setFlags(o.flags() | QtCore.Qt.ItemIsEditable)
            self.editItem(o, column)
            o.setFlags(o.flags() & ~QtCore.Qt.ItemIsEditable)
            self.is_editing = True

    def update_preview(self):
        """ """
        rule_text = self.preview.toPlainText()

        if -1 != rule_text.find("features:"):
            rule_text = rule_text[: rule_text.find("features:") + len("features:")]
            rule_text += "\n"
        else:
            rule_text = rule_text.rstrip()
            rule_text += "\n  features:\n"

        for o in iterate_tree(self):
            feature, description, comment = (o.strip() for o in tuple(o.text(i) for i in range(3)))
            rule_text += parse_node_for_feature(feature, description, comment, calc_item_depth(o))

        # TODO(mike-hunhoff): we avoid circular update by disabling signals when updating
        # the preview. Preferably we would refactor the code to avoid this
        # in the first place.
        # https://github.com/mandiant/capa/issues/1600
        self.preview.blockSignals(True)
        self.preview.setPlainText(rule_text)
        self.preview.blockSignals(False)

        # emit signal so views can update
        self.updated.emit()

    def load_custom_context_menu_invalid_index(self, pos):
        """ """
        actions = (("Remove all", (), self.slot_clear_all),)

        menu = build_context_menu(self.parent(), actions)
        menu.exec_(self.viewport().mapToGlobal(pos))

    def load_custom_context_menu_feature(self, pos):
        """ """
        actions = (("Remove selection", (), self.slot_remove_selected),)

        sub_actions = (
            ("and", ("- and:",), self.slot_nest_features),
            ("or", ("- or:",), self.slot_nest_features),
            ("not", ("- not:",), self.slot_nest_features),
            ("optional", ("- optional:",), self.slot_nest_features),
            ("basic block", ("- basic block:",), self.slot_nest_features),
            ("instruction", ("- instruction:",), self.slot_nest_features),
        )

        # build submenu with modify actions
        sub_menu = build_context_menu(self.parent(), sub_actions)
        sub_menu.setTitle(f"Nest feature{'' if len(tuple(self.get_features(selected=True))) == 1 else 's'}")

        # build main menu with submenu + main actions
        menu = build_context_menu(self.parent(), (sub_menu,) + actions)

        menu.exec_(self.viewport().mapToGlobal(pos))

    def load_custom_context_menu_expression(self, pos):
        """ """
        actions = (("Remove expression", (), self.slot_remove_selected),)

        sub_actions = (
            ("and", ("- and:", self.itemAt(pos)), self.slot_edit_expression),
            ("or", ("- or:", self.itemAt(pos)), self.slot_edit_expression),
            ("not", ("- not:", self.itemAt(pos)), self.slot_edit_expression),
            ("optional", ("- optional:", self.itemAt(pos)), self.slot_edit_expression),
            ("basic block", ("- basic block:", self.itemAt(pos)), self.slot_edit_expression),
            ("instruction", ("- instruction:", self.itemAt(pos)), self.slot_edit_expression),
        )

        # build submenu with modify actions
        sub_menu = build_context_menu(self.parent(), sub_actions)
        sub_menu.setTitle("Modify")

        # build main menu with submenu + main actions
        menu = build_context_menu(self.parent(), (sub_menu,) + actions)

        menu.exec_(self.viewport().mapToGlobal(pos))

    def style_expression_node(self, o):
        """ """
        font = QtGui.QFont()
        font.setBold(True)

        o.setFont(CapaExplorerRulegenEditor.get_column_feature_index(), font)

    def style_feature_node(self, o):
        """ """
        font = QtGui.QFont()
        brush = QtGui.QBrush()

        font.setFamily("Courier")
        font.setWeight(QtGui.QFont.Medium)
        brush.setColor(QtGui.QColor(*COLOR_GREEN_RGB))

        o.setFont(CapaExplorerRulegenEditor.get_column_feature_index(), font)
        o.setForeground(CapaExplorerRulegenEditor.get_column_feature_index(), brush)

    def style_comment_node(self, o):
        """ """
        font = QtGui.QFont()
        font.setBold(True)
        font.setFamily("Courier")

        o.setFont(CapaExplorerRulegenEditor.get_column_feature_index(), font)

    def set_expression_node(self, o):
        """ """
        setattr(o, "capa_type", CapaExplorerRulegenEditor.get_node_type_expression())
        self.style_expression_node(o)

    def set_feature_node(self, o):
        """ """
        setattr(o, "capa_type", CapaExplorerRulegenEditor.get_node_type_feature())
        o.setFlags(o.flags() & ~QtCore.Qt.ItemIsDropEnabled)
        self.style_feature_node(o)

    def set_comment_node(self, o):
        """ """
        setattr(o, "capa_type", CapaExplorerRulegenEditor.get_node_type_comment())
        o.setFlags(o.flags() & ~QtCore.Qt.ItemIsDropEnabled)

        self.style_comment_node(o)

    def new_expression_node(self, parent, values=()):
        """ """
        o = QtWidgets.QTreeWidgetItem(parent)
        self.set_expression_node(o)
        for i, v in enumerate(values):
            o.setText(i, v)
        return o

    def new_feature_node(self, parent, values=()):
        """ """
        o = QtWidgets.QTreeWidgetItem(parent)
        self.set_feature_node(o)
        for i, v in enumerate(values):
            o.setText(i, v)
        return o

    def new_comment_node(self, parent, values=()):
        """ """
        o = QtWidgets.QTreeWidgetItem(parent)
        self.set_comment_node(o)
        for i, v in enumerate(values):
            o.setText(i, v)
        return o

    def update_features(self, features):
        """ """
        if not self.invisibleRootItem().childCount():
            # empty tree; add a default node
            self.new_expression_node(self.invisibleRootItem(), ("- or:", ""))

        # we don't want to add new features under the invisible root because capa rules should
        # contain a single top-level node; this may not always be the case so we default to the last
        # child node that was added to the invisible root
        top_node = self.invisibleRootItem().child(self.invisibleRootItem().childCount() - 1)

        # build feature counts
        counted = list(zip(Counter(features).keys(), Counter(features).values()))

        # single features
        for k, _ in filter(lambda t: t[1] == 1, counted):
            if isinstance(k, (capa.features.common.String,)):
                value = f'"{capa.features.common.escape_string(k.get_value_str())}"'
            else:
                value = k.get_value_str()
            self.new_feature_node(top_node, (f"- {k.name.lower()}: {value}", ""))

        # n > 1 features
        for k, v in filter(lambda t: t[1] > 1, counted):
            if k.value:
                if isinstance(k, (capa.features.common.String,)):
                    value = f'"{capa.features.common.escape_string(k.get_value_str())}"'
                else:
                    value = k.get_value_str()
                display = f"- count({k.name.lower()}({value})): {v}"
            else:
                display = f"- count({k.name.lower()}): {v}"
            self.new_feature_node(top_node, (display, ""))

        self.update_preview()
        expand_tree(self.invisibleRootItem())
        resize_columns_to_content(self.header())

    def make_child_node_from_feature(self, parent, feature):
        """ """
        feature, comment, description = feature

        # we need special handling for the "description" tag; meaning we don't add a new node but simply
        # set the "description" column for the appropriate parent node
        if feature.startswith("description:"):
            if not parent:
                # we shouldn't have description without a parent; do nothing
                return None

            # we don't add a new node for description; either set description column of parent's last child
            # or the parent itself
            if feature.startswith("description:"):
                description = feature[len("description:") :].lstrip()
                if parent.childCount():
                    parent.child(parent.childCount() - 1).setText(1, description)
                else:
                    parent.setText(1, description)
            return None
        elif feature.startswith("- description:"):
            if not parent:
                # we shouldn't have a description without a parent; do nothing
                return None

            # we don't add a new node for description; set the description column of the parent instead
            description = feature[len("- description:") :].lstrip()
            parent.setText(1, description)
            return None

        node = QtWidgets.QTreeWidgetItem(parent)

        # set node text to data parsed from feature
        for idx, text in enumerate((feature, comment, description)):
            node.setText(idx, text)

        # we need to set our own type so we can control the GUI accordingly
        if feature.startswith(("- and:", "- or:", "- not:", "- basic block:", "- instruction:", "- optional:")):
            setattr(node, "capa_type", CapaExplorerRulegenEditor.get_node_type_expression())
        elif feature.startswith("#"):
            setattr(node, "capa_type", CapaExplorerRulegenEditor.get_node_type_comment())
        else:
            setattr(node, "capa_type", CapaExplorerRulegenEditor.get_node_type_feature())

        # format the node based on its type
        (self.set_expression_node, self.set_feature_node, self.set_comment_node)[node.capa_type](node)

        parent.addChild(node)

        return node

    def load_features_from_yaml(self, rule_text, update_preview=False):
        """ """
        self.reset_view()

        # check for lack of features block
        if -1 == rule_text.find("features:"):
            return

        rule_features = rule_text[rule_text.find("features:") + len("features:") :].strip("\n")

        if not rule_features:
            # no features; nothing to do
            return

        # build tree from yaml text using stack-based algorithm to build parent -> child edges
        stack = [self.invisibleRootItem()]
        for line in rule_features.splitlines():
            if not len(line.strip()):
                continue

            indent = calc_indent_from_line(line)

            # we need to grow our stack to ensure proper parent -> child edges
            if indent > len(stack):
                stack.extend([None] * (indent - len(stack)))

            # shave the stack; divide by 2 because even indent, add 1 to avoid shaving root node
            stack[indent // 2 + 1 :] = []

            # find our parent; should be last node in stack not None
            parent = None
            for o in stack[::-1]:
                if o:
                    parent = o
                    break

            node = self.make_child_node_from_feature(parent, parse_yaml_line(line.strip()))

            # append our new node in case it's a parent for another node
            if node:
                stack.append(node)

        if update_preview:
            self.preview.blockSignals(True)
            self.preview.setPlainText(rule_text)
            self.preview.blockSignals(False)

        expand_tree(self.invisibleRootItem())

    def get_features(self, selected=False, ignore=()):
        """ """
        for feature in filter(
            lambda o: o.capa_type
            in (CapaExplorerRulegenEditor.get_node_type_feature(), CapaExplorerRulegenEditor.get_node_type_comment()),
            tuple(iterate_tree(self)),
        ):
            if feature in ignore:
                continue
            if selected and not feature.isSelected():
                continue
            yield feature

    def get_expressions(self, selected=False, ignore=()):
        """ """
        for expression in filter(
            lambda o: o.capa_type == CapaExplorerRulegenEditor.get_node_type_expression(), tuple(iterate_tree(self))
        ):
            if expression in ignore:
                continue
            if selected and not expression.isSelected():
                continue
            yield expression


class CapaExplorerRulegenFeatures(QtWidgets.QTreeWidget):
    def __init__(self, editor, parent=None):
        """ """
        super().__init__(parent)

        self.parent_items = {}
        self.editor = editor

        self.setHeaderLabels(["Feature", "Address"])
        self.setStyleSheet("QTreeView::item {padding-right: 15 px;padding-bottom: 2 px;}")

        # configure view columns to auto-resize
        for idx in range(2):
            self.header().setSectionResizeMode(idx, QtWidgets.QHeaderView.Interactive)

        self.setExpandsOnDoubleClick(False)
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)

        # connect slots
        self.itemDoubleClicked.connect(self.slot_item_double_clicked)
        self.customContextMenuRequested.connect(self.slot_custom_context_menu_requested)
        self.expanded.connect(self.slot_resize_columns_to_content)
        self.collapsed.connect(self.slot_resize_columns_to_content)

        self.reset_view()

    @staticmethod
    def get_column_feature_index():
        """ """
        return 0

    @staticmethod
    def get_column_address_index():
        """ """
        return 1

    @staticmethod
    def get_node_type_parent():
        """ """
        return 0

    @staticmethod
    def get_node_type_leaf():
        """ """
        return 1

    def reset_view(self):
        """ """
        self.clear()

    def slot_resize_columns_to_content(self):
        """ """
        resize_columns_to_content(self.header())

    def slot_add_selected_features(self, action):
        """ """
        selected = [item.data(0, 0x100) for item in self.selectedItems()]
        if selected:
            self.editor.update_features(selected)

    def slot_add_n_bytes_feature(self, action):
        """ """
        count = idaapi.ask_long(16, f"Enter number of bytes (1-{capa.features.common.MAX_BYTES_FEATURE_SIZE}):")
        if count and 1 <= count <= capa.features.common.MAX_BYTES_FEATURE_SIZE:
            item = self.selectedItems()[0].data(0, 0x100)
            item.value = item.value[:count]
            self.editor.update_features([item])

    def slot_custom_context_menu_requested(self, pos):
        """ """
        actions = []
        action_add_features_fmt = ""

        selected_items_count = len(self.selectedItems())
        if selected_items_count == 0:
            return

        if selected_items_count == 1:
            action_add_features_fmt = "Add feature"
            if isinstance(self.selectedItems()[0].data(0, 0x100), capa.features.common.Bytes):
                actions.append(("Add n bytes...", (), self.slot_add_n_bytes_feature))
        else:
            action_add_features_fmt = f"Add {selected_items_count} features"

        actions.append((action_add_features_fmt, (), self.slot_add_selected_features))

        menu = build_context_menu(self.parent(), actions)
        menu.exec_(self.viewport().mapToGlobal(pos))

    def slot_item_double_clicked(self, o, column):
        """ """
        if column == CapaExplorerRulegenFeatures.get_column_address_index() and o.text(column):
            idc.jumpto(int(o.text(column), 0x10))
        elif o.capa_type == CapaExplorerRulegenFeatures.get_node_type_leaf():
            self.editor.update_features([o.data(0, 0x100)])

    def show_all_items(self):
        """ """
        for o in iterate_tree(self):
            o.setHidden(False)
            o.setExpanded(False)

    def filter_items_by_text(self, text):
        """ """
        if text:
            for o in iterate_tree(self):
                data = o.data(0, 0x100)
                if data:
                    to_match = data.get_value_str()
                    if not to_match or text.lower() not in to_match.lower():
                        if not o.isHidden():
                            o.setHidden(True)
                        continue
                if o.isHidden():
                    o.setHidden(False)
                if o.childCount() and not o.isExpanded():
                    o.setExpanded(True)
        else:
            self.show_all_items()

    def filter_items_by_ea(self, min_ea, max_ea=None):
        """ """
        visited = []

        def show_item_and_parents(_o):
            """iteratively show and expand an item and its' parents"""
            while _o:
                visited.append(_o)
                if _o.isHidden():
                    _o.setHidden(False)
                if _o.childCount() and not _o.isExpanded():
                    _o.setExpanded(True)
                _o = _o.parent()

        for o in iterate_tree(self):
            if o in visited:
                # save some cycles, only visit item once
                continue

            # read ea from "Address" column
            o_ea = o.text(CapaExplorerRulegenFeatures.get_column_address_index())

            if o_ea == "":
                # ea may be empty, hide by default
                if not o.isHidden():
                    o.setHidden(True)
                continue

            o_ea = int(o_ea, 16)

            if max_ea is not None and min_ea <= o_ea <= max_ea:
                show_item_and_parents(o)
            elif o_ea == min_ea:
                show_item_and_parents(o)
            else:
                # made it here, hide by default
                if not o.isHidden():
                    o.setHidden(True)

        # resize the view for UX
        resize_columns_to_content(self.header())

    def style_parent_node(self, o):
        """ """
        font = QtGui.QFont()
        font.setBold(True)

        o.setFont(CapaExplorerRulegenFeatures.get_column_feature_index(), font)

    def style_leaf_node(self, o):
        """ """
        font = QtGui.QFont("Courier", weight=QtGui.QFont.Bold)
        brush = QtGui.QBrush()

        o.setFont(CapaExplorerRulegenFeatures.get_column_feature_index(), font)
        o.setFont(CapaExplorerRulegenFeatures.get_column_address_index(), font)

        brush.setColor(QtGui.QColor(*COLOR_GREEN_RGB))
        o.setForeground(CapaExplorerRulegenFeatures.get_column_feature_index(), brush)

        brush.setColor(QtGui.QColor(*COLOR_BLUE_RGB))
        o.setForeground(CapaExplorerRulegenFeatures.get_column_address_index(), brush)

    def set_parent_node(self, o):
        """ """
        o.setFlags(o.flags() & ~QtCore.Qt.ItemIsSelectable)
        setattr(o, "capa_type", CapaExplorerRulegenFeatures.get_node_type_parent())
        self.style_parent_node(o)

    def set_leaf_node(self, o):
        """ """
        setattr(o, "capa_type", CapaExplorerRulegenFeatures.get_node_type_leaf())
        self.style_leaf_node(o)

    def new_parent_node(self, parent, data, feature=None):
        """ """
        o = QtWidgets.QTreeWidgetItem(parent)

        self.set_parent_node(o)
        for i, v in enumerate(data):
            o.setText(i, v)
        if feature:
            o.setData(0, 0x100, feature)

        return o

    def new_leaf_node(self, parent, data, feature=None):
        """ """
        o = QtWidgets.QTreeWidgetItem(parent)

        self.set_leaf_node(o)
        for i, v in enumerate(data):
            o.setText(i, v)
        if feature:
            o.setData(0, 0x100, feature)

        return o

    def load_features(self, file_features, func_features: Optional[Dict] = None):
        """ """
        self.parse_features_for_tree(self.new_parent_node(self, ("File Scope",)), file_features)
        if func_features:
            self.parse_features_for_tree(self.new_parent_node(self, ("Function/Basic Block Scope",)), func_features)
        resize_columns_to_content(self.header())

    def parse_features_for_tree(self, parent, features):
        """ """
        self.parent_items = {}

        def format_address(e):
            if isinstance(e, AbsoluteVirtualAddress):
                return f"{hex(int(e))}"
            else:
                return ""

        def format_feature(feature):
            """ """
            name = feature.name.lower()
            value = feature.get_value_str()
            if isinstance(feature, (capa.features.common.String,)):
                value = f'"{capa.features.common.escape_string(value)}"'
            return f"{name}({value})"

        for feature, addrs in sorted(features.items(), key=lambda k: sorted(k[1])):
            if isinstance(feature, capa.features.basicblock.BasicBlock):
                # filter basic blocks for now, we may want to add these back in some time
                # in the future
                continue

            # level 0
            if type(feature) not in self.parent_items:
                self.parent_items[type(feature)] = self.new_parent_node(parent, (feature.name.lower(),))

            # level 1
            if feature not in self.parent_items:
                if len(addrs) > 1:
                    self.parent_items[feature] = self.new_parent_node(
                        self.parent_items[type(feature)], (format_feature(feature),), feature=feature
                    )
                else:
                    self.parent_items[feature] = self.new_leaf_node(
                        self.parent_items[type(feature)], (format_feature(feature),), feature=feature
                    )

            # level n > 1
            if len(addrs) > 1:
                for addr in sorted(addrs):
                    self.new_leaf_node(
                        self.parent_items[feature], (format_feature(feature), format_address(addr)), feature=feature
                    )
            else:
                if addrs:
                    addr = addrs.pop()
                else:
                    # some features may not have an address e.g. "format"
                    addr = _NoAddress()
                for i, v in enumerate((format_feature(feature), format_address(addr))):
                    self.parent_items[feature].setText(i, v)
                self.parent_items[feature].setData(0, 0x100, feature)


class CapaExplorerQtreeView(QtWidgets.QTreeView):
    """tree view used to display hierarchical capa results

    view controls UI action responses and displays data from CapaExplorerDataModel

    view does not modify CapaExplorerDataModel directly - data modifications should be implemented
    in CapaExplorerDataModel
    """

    def __init__(self, model, parent=None):
        """initialize view"""
        super().__init__(parent)

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
            resize_columns_to_content(self.header())

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
        yield from self.load_default_context_menu_actions(data)

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
