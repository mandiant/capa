from PyQt5 import QtWidgets, QtCore, QtGui

import idaapi
import idc

from capa.ida.explorer.model import CapaExplorerDataModel
from capa.ida.explorer.item import CapaExplorerFunctionItem


class CapaExplorerQtreeView(QtWidgets.QTreeView):
    ''' capa explorer QTreeView implementation

        view controls UI action responses and displays data from
        CapaExplorerDataModel

        view does not modify CapaExplorerDataModel directly - data
        modifications should be implemented in CapaExplorerDataModel
    '''

    def __init__(self, model, parent=None):
        ''' initialize CapaExplorerQTreeView

            TODO

            @param model: TODO
            @param parent: TODO
        '''
        super(CapaExplorerQtreeView, self).__init__(parent)

        self.setModel(model)

        # TODO: get from parent??
        self._model = model
        self._parent = parent

        # configure custom UI controls
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.setExpandsOnDoubleClick(False)
        self.setSortingEnabled(True)
        self._model.setDynamicSortFilter(False)

        # configure view columns to auto-resize
        for idx in range(CapaExplorerDataModel.COLUMN_COUNT):
            self.header().setSectionResizeMode(idx, QtWidgets.QHeaderView.Interactive)

        # connect slots to resize columns when expanded or collapsed
        self.expanded.connect(self.resize_columns_to_content)
        self.collapsed.connect(self.resize_columns_to_content)

        # connect slots
        self.customContextMenuRequested.connect(self._slot_custom_context_menu_requested)
        self.doubleClicked.connect(self._slot_double_click)
        # self.clicked.connect(self._slot_click)

        self.setStyleSheet('QTreeView::item {padding-right: 15 px;padding-bottom: 2 px;}')

    def reset(self):
        ''' reset user interface changes

            called when view should reset any user interface changes
            made since the last reset e.g. IDA window highlighting
        '''
        self.collapseAll()
        self.resize_columns_to_content()

    def resize_columns_to_content(self):
        ''' reset view columns to contents

            TODO: prevent columns from shrinking
        '''
        self.header().resizeSections(QtWidgets.QHeaderView.ResizeToContents)

    def _map_index_to_source_item(self, mindex):
        ''' map proxy model index to source model item

            @param mindex: QModelIndex*

            @retval QObject*
        '''
        return self._model.mapToSource(mindex).internalPointer()

    def _send_data_to_clipboard(self, data):
        ''' copy data to the clipboard

            @param data: data to be copied
        '''
        clip = QtWidgets.QApplication.clipboard()
        clip.clear(mode=clip.Clipboard)
        clip.setText(data, mode=clip.Clipboard)

    def _new_action(self, display, data, slot):
        ''' create action for context menu

            @param display: text displayed to user in context menu
            @param data: data passed to slot
            @param slot: slot to connect

            @retval QAction*
        '''
        action = QtWidgets.QAction(display, self._parent)
        action.setData(data)
        action.triggered.connect(lambda checked: slot(action))

        return action

    def _load_default_context_menu_actions(self, data):
        ''' yield actions specific to function custom context menu

            @param data: tuple

            @yield QAction*
        '''
        default_actions = [
            ('Copy column', data, self._slot_copy_column),
            ('Copy row', data, self._slot_copy_row),
            # ('Filter', data, self._slot_filter),
        ]

        # add default actions
        for action in default_actions:
            yield self._new_action(*action)

    def _load_function_context_menu_actions(self, data):
        ''' yield actions specific to function custom context menu

            @param data: tuple

            @yield QAction*
        '''
        function_actions = [
            ('Rename function', data, self._slot_rename_function),
        ]

        # add function actions
        for action in function_actions:
            yield self._new_action(*action)

        # add default actions
        for action in self._load_default_context_menu_actions(data):
            yield action

    def _load_default_context_menu(self, pos, item, mindex):
        ''' create default custom context menu

            creates custom context menu containing default actions

            @param pos: TODO
            @param item: TODO
            @param mindex: TODO

            @retval QMenu*
        '''
        menu = QtWidgets.QMenu()

        for action in self._load_default_context_menu_actions((pos, item, mindex)):
            menu.addAction(action)

        return menu

    def _load_function_item_context_menu(self, pos, item, mindex):
        ''' create function custom context menu

            creates custom context menu containing actions specific to functions
            and the default actions

            @param pos: TODO
            @param item: TODO
            @param mindex: TODO

            @retval QMenu*
        '''
        menu = QtWidgets.QMenu()

        for action in self._load_function_context_menu_actions((pos, item, mindex)):
            menu.addAction(action)

        return menu

    def _show_custom_context_menu(self, menu, pos):
        ''' display custom context menu in view

            @param menu: TODO
            @param pos: TODO
        '''
        if not menu:
            return

        menu.exec_(self.viewport().mapToGlobal(pos))

    def _slot_copy_column(self, action):
        ''' slot connected to custom context menu

            allows user to select a column and copy the data
            to clipboard

            @param action: QAction*
        '''
        _, item, mindex = action.data()
        self._send_data_to_clipboard(item.data(mindex.column()))

    def _slot_copy_row(self, action):
        ''' slot connected to custom context menu

            allows user to select a row and copy the space-delimeted
            data to clipboard

            @param action: QAction*
        '''
        _, item, _ = action.data()
        self._send_data_to_clipboard(str(item))

    def _slot_rename_function(self, action):
        ''' slot connected to custom context menu

            allows user to select a edit a function name and push
            changes to IDA

            @param action: QAction*
        '''
        _, item, mindex = action.data()

        # make item temporary edit, reset after user is finished
        item.setIsEditable(True)
        self.edit(mindex)
        item.setIsEditable(False)

    def _slot_custom_context_menu_requested(self, pos):
        ''' slot connected to custom context menu request

            displays custom context menu to user containing action
            relevant to the data item selected

            @param pos: TODO
        '''
        mindex = self.indexAt(pos)

        if not mindex.isValid():
            return

        item = self._map_index_to_source_item(mindex)
        column = mindex.column()
        menu = None

        if CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION == column and isinstance(item, CapaExplorerFunctionItem):
            # user hovered function item
            menu = self._load_function_item_context_menu(pos, item, mindex)
        else:
            # user hovered default item
            menu = self._load_default_context_menu(pos, item, mindex)

        # show custom context menu at view position
        self._show_custom_context_menu(menu, pos)

    def _slot_click(self):
        ''' slot connected to single click event '''
        pass

    def _slot_double_click(self, mindex):
        ''' slot connected to double click event

            @param mindex: QModelIndex*
        '''
        if not mindex.isValid():
            return

        item = self._map_index_to_source_item(mindex)
        column = mindex.column()

        if CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS == column:
            # user double-clicked virtual address column - navigate IDA to address
            try:
                idc.jumpto(int(item.data(1), 16))
            except ValueError:
                pass

        if CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION == column:
            # user double-clicked information column - un/expand
            if self.isExpanded(mindex):
                self.collapse(mindex)
            else:
                self.expand(mindex)
