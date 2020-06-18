from PyQt5 import QtCore
from capa.ida.explorer.model import CapaExplorerDataModel


class CapaExplorerSortFilterProxyModel(QtCore.QSortFilterProxyModel):

    def __init__(self, parent=None):
        ''' '''
        super(CapaExplorerSortFilterProxyModel, self).__init__(parent)

    def lessThan(self, left, right):
        ''' true if the value of the left item is less than value of right item

            @param left: QModelIndex*
            @param right: QModelIndex*

            @retval True/False
        '''
        ldata = left.internalPointer().data(left.column())
        rdata = right.internalPointer().data(right.column())

        if ldata and rdata and left.column() == CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS and left.column() == right.column():
            # convert virtual address before compare
            return int(ldata, 16) < int(rdata, 16)
        else:
            # compare as lowercase
            return ldata.lower() < rdata.lower()

    def filterAcceptsRow(self, row, parent):
        ''' true if the item in the row indicated by the given row and parent
            should be included in the model; otherwise returns false
            @param row: int
            @param parent: QModelIndex*

            @retval True/False
        '''
        if self._filter_accepts_row_self(row, parent):
            return True

        alpha = parent
        while alpha.isValid():
            if self._filter_accepts_row_self(alpha.row(), alpha.parent()):
                return True
            alpha = alpha.parent()

        if self._index_has_accepted_children(row, parent):
            return True

        return False

    def add_single_string_filter(self, column, string):
        ''' add fixed string filter

            @param column: key column
            @param string: string to sort
        '''
        self.setFilterKeyColumn(column)
        self.setFilterFixedString(string)

    def _index_has_accepted_children(self, row, parent):
        ''' '''
        mindex = self.sourceModel().index(row, 0, parent)

        if mindex.isValid():
            for idx in range(self.sourceModel().rowCount(mindex)):
                if self._filter_accepts_row_self(idx, mindex):
                    return True
                if self._index_has_accepted_children(idx, mindex):
                    return True

        return False

    def _filter_accepts_row_self(self, row, parent):
        ''' '''
        return super(CapaExplorerSortFilterProxyModel, self).filterAcceptsRow(row, parent)
