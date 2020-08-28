# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from PyQt5 import QtCore

from capa.ida.explorer.model import CapaExplorerDataModel


class CapaExplorerSortFilterProxyModel(QtCore.QSortFilterProxyModel):
    def __init__(self, parent=None):
        """ """
        super(CapaExplorerSortFilterProxyModel, self).__init__(parent)

        self.min_ea = None
        self.max_ea = None

    def lessThan(self, left, right):
        """true if the value of the left item is less than value of right item

        @param left: QModelIndex*
        @param right: QModelIndex*

        @retval True/False
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
        """true if the item in the row indicated by the given row and parent
        should be included in the model; otherwise returns false

        @param row: int
        @param parent: QModelIndex*

        @retval True/False
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
        """ """
        model_index = self.sourceModel().index(row, 0, parent)

        if model_index.isValid():
            for idx in range(self.sourceModel().rowCount(model_index)):
                if self.filter_accepts_row_self(idx, model_index):
                    return True
                if self.index_has_accepted_children(idx, model_index):
                    return True

        return False

    def filter_accepts_row_self(self, row, parent):
        """ """
        # filter not set
        if self.min_ea is None and self.max_ea is None:
            return True

        index = self.sourceModel().index(row, 0, parent)
        data = index.internalPointer().data(CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS)

        if not data:
            return False

        ea = int(data, 16)

        if self.min_ea <= ea and ea < self.max_ea:
            return True

        return False

    def add_address_range_filter(self, min_ea, max_ea):
        """ """
        self.min_ea = min_ea
        self.max_ea = max_ea

        self.setFilterKeyColumn(CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS)
        self.invalidateFilter()

    def reset_address_range_filter(self):
        """ """
        self.min_ea = None
        self.max_ea = None
        self.invalidateFilter()
