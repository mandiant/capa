# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from PyQt5 import QtCore
from PyQt5.QtCore import Qt

from capa.ida.plugin.model import CapaExplorerDataModel


class CapaExplorerRangeProxyModel(QtCore.QSortFilterProxyModel):
    """filter results based on virtual address range as seen by IDA

    implements filtering for "limit results by current function" checkbox in plugin UI

    minimum and maximum virtual addresses are used to filter results to a specific address range. this allows
    basic blocks to be included when limiting results to a specific function
    """

    def __init__(self, parent=None):
        """initialize proxy filter"""
        super().__init__(parent)
        self.min_ea = None
        self.max_ea = None

    def lessThan(self, left, right):
        """return True if left item is less than right item, else False

        @param left: QModelIndex of left
        @param right: QModelIndex of right
        """
        ldata = left.internalPointer().data(left.column())
        rdata = right.internalPointer().data(right.column())

        if (
            ldata
            and rdata
            and left.column() == CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS
            and left.column() == right.column()
        ):
            # convert virtual address before compare
            return int(ldata, 16) < int(rdata, 16)
        else:
            # compare as lowercase
            return ldata.lower() < rdata.lower()

    def filterAcceptsRow(self, row, parent):
        """return true if the item in the row indicated by the given row and parent should be included in the model;
        otherwise return false

        @param row: row number
        @param parent: QModelIndex of parent
        """
        if self.filter_accepts_row_self(row, parent):
            return True

        alpha = parent
        while alpha.isValid():
            if self.filter_accepts_row_self(alpha.row(), alpha.parent()):
                return True
            alpha = alpha.parent()

        if self.index_has_accepted_children(row, parent):
            return True

        return False

    def index_has_accepted_children(self, row, parent):
        """return True if parent has one or more children that match filter, else False

        @param row: row number
        @param parent: QModelIndex of parent
        """
        model_index = self.sourceModel().index(row, 0, parent)

        if model_index.isValid():
            for idx in range(self.sourceModel().rowCount(model_index)):
                if self.filter_accepts_row_self(idx, model_index):
                    return True
                if self.index_has_accepted_children(idx, model_index):
                    return True

        return False

    def filter_accepts_row_self(self, row, parent):
        """return True if filter accepts row, else False

        @param row: row number
        @param parent: QModelIndex of parent
        """
        # filter not set
        if self.min_ea is None or self.max_ea is None:
            return True

        index = self.sourceModel().index(row, 0, parent)
        data = index.internalPointer().data(CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS)

        # virtual address may be empty
        if not data:
            return False

        # convert virtual address str to int
        ea = int(data, 16)

        if self.min_ea <= ea and ea < self.max_ea:
            return True

        return False

    def add_address_range_filter(self, min_ea, max_ea):
        """add new address range filter

        called when user checks "limit results by current function" in plugin UI

        @param min_ea: minimum virtual address as seen by IDA
        @param max_ea: maximum virtual address as seen by IDA
        """
        self.min_ea = min_ea
        self.max_ea = max_ea

        self.setFilterKeyColumn(CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS)
        self.invalidateFilter()

    def reset_address_range_filter(self):
        """remove address range filter (accept all results)

        called when user un-checks "limit results by current function" in plugin UI
        """
        self.min_ea = None
        self.max_ea = None
        self.invalidateFilter()


class CapaExplorerSearchProxyModel(QtCore.QSortFilterProxyModel):
    """A SortFilterProxyModel that accepts rows with a substring match for a configurable query.

    Looks for matches in the text of all rows.
    Displays the entire tree row if any of the tree branches,
     that is, you can filter by rule name, or also
     filter by "characteristic(nzxor)" to filter matches with some feature.
    """

    def __init__(self, parent=None):
        """ """
        super().__init__(parent)
        self.query = ""
        self.setFilterKeyColumn(-1)  # all columns

    def filterAcceptsRow(self, row, parent):
        """true if the item in the row indicated by the given row and parent
        should be included in the model; otherwise returns false

        @param row: int
        @param parent: QModelIndex*

        @retval True/False
        """
        # this row matches, accept it
        if self.filter_accepts_row_self(row, parent):
            return True

        # the parent of this row matches, accept it
        alpha = parent
        while alpha.isValid():
            if self.filter_accepts_row_self(alpha.row(), alpha.parent()):
                return True
            alpha = alpha.parent()

        # this row is a parent, and a child matches, accept it
        if self.index_has_accepted_children(row, parent):
            return True

        return False

    def index_has_accepted_children(self, row, parent):
        """returns True if the given row or its children should be accepted"""
        source_model = self.sourceModel()
        model_index = source_model.index(row, 0, parent)

        if model_index.isValid():
            for idx in range(source_model.rowCount(model_index)):
                if self.filter_accepts_row_self(idx, model_index):
                    return True
                if self.index_has_accepted_children(idx, model_index):
                    return True

        return False

    def filter_accepts_row_self(self, row, parent):
        """returns True if the given row should be accepted"""
        if self.query == "":
            return True

        source_model = self.sourceModel()

        for column in (
            CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION,
            CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS,
            CapaExplorerDataModel.COLUMN_INDEX_DETAILS,
        ):
            index = source_model.index(row, column, parent)
            data = source_model.data(index, Qt.DisplayRole)

            if not data:
                continue

            if not isinstance(data, str):
                # sanity check: should already be a string, but double check
                continue

            # case in-sensitive matching
            if self.query.lower() in data.lower():
                return True

        return False

    def set_query(self, query):
        self.query = query
        self.invalidateFilter()

    def reset_query(self):
        self.set_query("")
