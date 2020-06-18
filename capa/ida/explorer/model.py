from PyQt5 import QtCore, QtGui
from collections import deque
import binascii

import idaapi
import idc

from capa.ida.explorer.item import (
    CapaExplorerDataItem,
    CapaExplorerDefaultItem,
    CapaExplorerFeatureItem,
    CapaExplorerFunctionItem,
    CapaExplorerRuleItem,
    CapaExplorerStringViewItem,
    CapaExplorerInstructionViewItem,
    CapaExplorerByteViewItem,
    CapaExplorerBlockItem
)

import capa.ida.helpers


# default highlight color used in IDA window
DEFAULT_HIGHLIGHT = 0xD096FF


class CapaExplorerDataModel(QtCore.QAbstractItemModel):
    ''' '''

    COLUMN_INDEX_RULE_INFORMATION = 0
    COLUMN_INDEX_VIRTUAL_ADDRESS = 1
    COLUMN_INDEX_DETAILS = 2

    COLUMN_COUNT = 3

    def __init__(self, parent=None):
        ''' '''
        super(CapaExplorerDataModel, self).__init__(parent)

        self._root = CapaExplorerDataItem(None, ['Rule Information', 'Address', 'Details'])

    def reset(self):
        ''' '''
        # reset checkboxes and color highlights
        # TODO: make less hacky
        for idx in range(self._root.childCount()):
            rindex = self.index(idx, 0, QtCore.QModelIndex())
            for mindex in self.iterateChildrenIndexFromRootIndex(rindex, ignore_root=False):
                mindex.internalPointer().setChecked(False)
                self._util_reset_ida_highlighting(mindex.internalPointer(), False)
                self.dataChanged.emit(mindex, mindex)

    def clear(self):
        ''' '''
        self.beginResetModel()
        # TODO: make sure this isn't for memory
        self._root.removeChildren()
        self.endResetModel()

    def columnCount(self, mindex):
        ''' get the number of columns for the children of the given parent

            @param mindex: QModelIndex*

            @retval column count
        '''
        if mindex.isValid():
            return mindex.internalPointer().columnCount()
        else:
            return self._root.columnCount()

    def data(self, mindex, role):
        ''' get data stored under the given role for the item referred to by the index

            @param mindex: QModelIndex*
            @param role: QtCore.Qt.*

            @retval data to be displayed
        '''
        if not mindex.isValid():
            return None

        if role == QtCore.Qt.DisplayRole:
            # display data in corresponding column
            return mindex.internalPointer().data(mindex.column())

        if role == QtCore.Qt.ToolTipRole and \
            CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION == mindex.column() and \
                isinstance(mindex.internalPointer(), CapaExplorerRuleItem):
            # show tooltip containing rule definition
            return mindex.internalPointer().definition

        if role == QtCore.Qt.CheckStateRole and mindex.column() == CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION:
            # inform view how to display content of checkbox - un/checked
            return QtCore.Qt.Checked if mindex.internalPointer().isChecked() else QtCore.Qt.Unchecked

        if role == QtCore.Qt.FontRole and mindex.column() in (CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS, CapaExplorerDataModel.COLUMN_INDEX_DETAILS):
            return QtGui.QFont('Courier', weight=QtGui.QFont.Medium)

        if role == QtCore.Qt.FontRole and mindex.internalPointer() == self._root:
            return QtCore.QFont(bold=True)

        return None

    def flags(self, mindex):
        ''' get item flags for given index

            @param mindex: QModelIndex*

            @retval QtCore.Qt.ItemFlags
        '''
        if not mindex.isValid():
            return QtCore.Qt.NoItemFlags

        return mindex.internalPointer().flags

    def headerData(self, section, orientation, role):
        ''' get data for the given role and section in the header with the specified orientation

            @param section: int
            @param orientation: QtCore.Qt.Orientation
            @param role: QtCore.Qt.DisplayRole

            @retval header data list()
        '''
        if orientation == QtCore.Qt.Horizontal and role == QtCore.Qt.DisplayRole:
            return self._root.data(section)

        return None

    def index(self, row, column, parent):
        ''' get index of the item in the model specified by the given row, column and parent index

            @param row: int
            @param column: int
            @param parent: QModelIndex*

            @retval QModelIndex*
        '''
        if not self.hasIndex(row, column, parent):
            return QtCore.QModelIndex()

        if not parent.isValid():
            parent_item = self._root
        else:
            parent_item = parent.internalPointer()

        child_item = parent_item.child(row)

        if child_item:
            return self.createIndex(row, column, child_item)
        else:
            return QtCore.QModelIndex()

    def parent(self, mindex):
        ''' get parent of the model item with the given index

            if the item has no parent, an invalid QModelIndex* is returned

            @param mindex: QModelIndex*

            @retval QModelIndex*
        '''
        if not mindex.isValid():
            return QtCore.QModelIndex()

        child = mindex.internalPointer()
        parent = child.parent()

        if parent == self._root:
            return QtCore.QModelIndex()

        return self.createIndex(parent.row(), 0, parent)

    def iterateChildrenIndexFromRootIndex(self, mindex, ignore_root=True):
        ''' depth-first traversal of child nodes

            @param mindex: QModelIndex*

            @retval yield QModelIndex*
        '''
        visited = set()
        stack = deque((mindex,))

        while True:
            try:
                cmindex = stack.pop()
            except IndexError:
                break

            if cmindex not in visited:
                if not ignore_root or cmindex is not mindex:
                    # ignore root
                    yield cmindex

                visited.add(cmindex)

                for idx in range(self.rowCount(cmindex)):
                    stack.append(cmindex.child(idx, 0))

    def _util_reset_ida_highlighting(self, item, checked):
        ''' '''
        if not isinstance(item, (CapaExplorerStringViewItem, CapaExplorerInstructionViewItem, CapaExplorerByteViewItem)):
            # ignore other item types
            return

        curr_highlight = idc.get_color(item.ea, idc.CIC_ITEM)

        if checked:
            # item checked - record current highlight and set to new
            item.ida_highlight = curr_highlight
            idc.set_color(item.ea, idc.CIC_ITEM, DEFAULT_HIGHLIGHT)
        else:
            # item unchecked - reset highlight
            if curr_highlight != DEFAULT_HIGHLIGHT:
                # user modified highlight - record new highlight and do not modify
                item.ida_highlight = curr_highlight
            else:
                # reset highlight to previous
                idc.set_color(item.ea, idc.CIC_ITEM, item.ida_highlight)

    def setData(self, mindex, value, role):
        ''' set the role data for the item at index to value

            @param mindex: QModelIndex*
            @param value: QVariant*
            @param role: QtCore.Qt.EditRole

            @retval True/False
        '''
        if not mindex.isValid():
            return False

        if role == QtCore.Qt.CheckStateRole and mindex.column() == CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION:
            # user un/checked box - un/check parent and children
            for cindex in self.iterateChildrenIndexFromRootIndex(mindex, ignore_root=False):
                cindex.internalPointer().setChecked(value)
                self._util_reset_ida_highlighting(cindex.internalPointer(), value)
                self.dataChanged.emit(cindex, cindex)
            return True

        if role == QtCore.Qt.EditRole and value and \
                mindex.column() == CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION and \
                isinstance(mindex.internalPointer(), CapaExplorerFunctionItem):
            # user renamed function - update IDA database and data model
            old_name = mindex.internalPointer().info
            new_name = str(value)

            if idaapi.set_name(mindex.internalPointer().ea, new_name):
                # success update IDA database - update data model
                self.update_function_name(old_name, new_name)
                return True

        # no handle
        return False

    def rowCount(self, mindex):
        ''' get the number of rows under the given parent

            when the parent is valid it means that is returning the number of
            children of parent

            @param mindex: QModelIndex*

            @retval row count
        '''
        if mindex.column() > 0:
            return 0

        if not mindex.isValid():
            item = self._root
        else:
            item = mindex.internalPointer()

        return item.childCount()

    def render_capa_results(self, rule_set, results):
        ''' populate data model with capa results

            @param rule_set: TODO
            @param results: TODO
        '''
        # prepare data model for changes
        self.beginResetModel()

        for (rule, ress) in results.items():
            if rule_set.rules[rule].meta.get('lib', False):
                # skip library rules
                continue

            # top level item is rule
            parent = CapaExplorerRuleItem(self._root, rule, len(ress), rule_set.rules[rule].definition)

            for (ea, res) in sorted(ress, key=lambda p: p[0]):
                if rule_set.rules[rule].scope == capa.rules.FILE_SCOPE:
                    # file scope - parent is rule
                    parent2 = parent
                elif rule_set.rules[rule].scope == capa.rules.FUNCTION_SCOPE:
                    parent2 = CapaExplorerFunctionItem(parent, idaapi.get_name(ea), ea)
                elif rule_set.rules[rule].scope == capa.rules.BASIC_BLOCK_SCOPE:
                    parent2 = CapaExplorerBlockItem(parent, ea)
                else:
                    # TODO: better way to notify a missed scope?
                    parent2 = CapaExplorerDefaultItem(parent, '', ea)

                self._render_result(rule_set, res, parent2)

        # reset data model after making changes
        self.endResetModel()

    def _render_result(self, rule_set, result, parent):
        ''' '''
        if not result.success:
            # TODO: display failed branches??
            return

        if isinstance(result.statement, capa.engine.Some):
            if result.statement.count == 0:
                if sum(map(lambda c: c.success, result.children)) > 0:
                    parent2 = CapaExplorerDefaultItem(parent, 'optional')
                else:
                    parent2 = parent
            else:
                parent2 = CapaExplorerDefaultItem(parent, '%d or more' % result.statement.count)
        elif not isinstance(result.statement, (capa.features.Feature, capa.engine.Element, capa.engine.Range, capa.engine.Regex)):
            # when rending a structural node (and/or/not) then we only care about the node name.
            '''
            succs = list(filter(lambda c: bool(c), result.children))
            if len(succs) == 1:
                # skip structural node with single succeeding child
                parent2 = parent
            else:
                parent2 = CapaExplorerDefaultItem(parent, result.statement.name.lower())
            '''
            parent2 = CapaExplorerDefaultItem(parent, result.statement.name.lower())
        else:
            # but when rendering a Feature, want to see any arguments to it
            if len(result.locations) == 1:
                # ea = result.locations.pop()
                ea = next(iter(result.locations))
                parent2 = self._render_feature(rule_set, parent, result.statement, ea, str(result.statement))
            else:
                parent2 = CapaExplorerDefaultItem(parent, str(result.statement))

                for ea in sorted(result.locations):
                    self._render_feature(rule_set, parent2, result.statement, ea)

        for child in result.children:
            self._render_result(rule_set, child, parent2)

    def _render_feature(self, rule_set, parent, feature, ea, name='-'):
        ''' render a given feature

            @param rule_set: TODO
            @param parent: TODO
            @param result: TODO
            @param ea: virtual address
            @param name: TODO
        '''
        instruction_view = (
            capa.features.Bytes,
            capa.features.String,
            capa.features.insn.API,
            capa.features.insn.Mnemonic,
            capa.features.insn.Number,
            capa.features.insn.Offset
        )

        byte_view = (
            capa.features.file.Section,
        )

        string_view = (
            capa.engine.Regex,
        )

        if isinstance(feature, instruction_view):
            return CapaExplorerInstructionViewItem(parent, name, ea)

        if isinstance(feature, byte_view):
            return CapaExplorerByteViewItem(parent, name, ea)

        if isinstance(feature, string_view):
            # TODO: move string collection to item constructor
            if isinstance(feature, capa.engine.Regex):
                return CapaExplorerStringViewItem(parent, name, ea, feature.match)

        if isinstance(feature, capa.features.Characteristic):
            # special rendering for characteristics
            if feature.name in ('loop', 'recursive call', 'tight loop', 'switch'):
                return CapaExplorerDefaultItem(parent, name)
            if feature.name in ('embedded pe',):
                return CapaExplorerByteViewItem(parent, name, ea)
            return CapaExplorerInstructionViewItem(parent, name, ea)

        if isinstance(feature, capa.features.MatchedRule):
            # render feature as a rule item
            return CapaExplorerRuleItem(parent, name, 0, rule_set.rules[feature.rule_name].definition)

        if isinstance(feature, capa.engine.Range):
            # render feature based upon type child
            return self._render_feature(rule_set, parent, feature.child, ea, name)

        # no handle, default to name and virtual address display
        return CapaExplorerDefaultItem(parent, name, ea)

    def update_function_name(self, old_name, new_name):
        ''' update all instances of function name

            @param old_name: previous function name
            @param new_name: new function name
        '''
        rmindex = self.index(0, 0, QtCore.QModelIndex())

        # convert name to view format for matching
        # TODO: handle this better
        old_name = CapaExplorerFunctionItem.view_fmt % old_name

        for mindex in self.match(rmindex, QtCore.Qt.DisplayRole, old_name, hits=-1, flags=QtCore.Qt.MatchRecursive):
            if not isinstance(mindex.internalPointer(), CapaExplorerFunctionItem):
                continue
            mindex.internalPointer().info = new_name
            self.dataChanged.emit(mindex, mindex)
