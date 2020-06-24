import os
import logging
import collections

from PyQt5.QtWidgets import (
    QHeaderView,
    QAbstractItemView,
    QMenuBar,
    QAction,
    QTabWidget,
    QWidget,
    QTextEdit,
    QMenu,
    QApplication,
    QVBoxLayout,
    QToolTip,
    QCheckBox,
    QTableWidget,
    QTableWidgetItem
)
from PyQt5.QtGui import QCursor, QIcon
from PyQt5.QtCore import Qt

import idaapi

import capa.main
import capa.rules
import capa.features.extractors.ida

from capa.ida.explorer.view import CapaExplorerQtreeView
from capa.ida.explorer.model import CapaExplorerDataModel
from capa.ida.explorer.proxy import CapaExplorerSortFilterProxyModel


PLUGIN_NAME = 'capa explorer'

SUPPORTED_FILE_TYPES = [
    'Portable executable for 80386 (PE)',
]

logger = logging.getLogger(PLUGIN_NAME)


class CapaExplorerIdaHooks(idaapi.UI_Hooks):

    def __init__(self, screen_ea_changed_hook, action_hooks):
        ''' facilitate IDA UI hooks

            @param screen_ea_changed: TODO
            @param action_hooks: TODO
        '''
        super(CapaExplorerIdaHooks, self).__init__()

        self._screen_ea_changed_hook = screen_ea_changed_hook
        self._process_action_hooks = action_hooks
        self._process_action_handle = None
        self._process_action_meta = {}

    def preprocess_action(self, name):
        ''' called prior to action completed

            @param name: name of action defined by idagui.cfg

            @retval must be 0
        '''
        self._process_action_handle = self._process_action_hooks.get(name, None)

        if self._process_action_handle:
            self._process_action_handle(self._process_action_meta)

        # must return 0 for IDA
        return 0

    def postprocess_action(self):
        ''' called after action completed '''
        if not self._process_action_handle:
            return

        self._process_action_handle(self._process_action_meta, post=True)
        self._reset()

    def screen_ea_changed(self, curr_ea, prev_ea):
        ''' called after screen ea is changed

            @param curr_ea: current ea
            @param prev_ea: prev ea
        '''
        self._screen_ea_changed_hook(idaapi.get_current_widget(), curr_ea, prev_ea)

    def _reset(self):
        ''' reset internal state '''
        self._process_action_handle = None
        self._process_action_meta.clear()


class CapaExplorerForm(idaapi.PluginForm):

    def __init__(self):
        ''' '''
        super(CapaExplorerForm, self).__init__()

        self.form_title = PLUGIN_NAME
        self.parent = None
        self._file_loc = __file__
        self._ida_hooks = None

        # models
        self._model_data = None
        self._model_proxy = None

        # user interface elements
        self._view_limit_results_by_function = None
        self._view_tree = None
        self._view_summary = None
        self._view_tabs = None
        self._view_menu_bar = None

    def OnCreate(self, form):
        ''' '''
        self.parent = self.FormToPyQtWidget(form)
        self._load_interface()
        self._load_capa_results()
        self._load_ida_hooks()

        self._view_tree.reset()

        logger.info('form created.')

    def Show(self):
        ''' '''
        return idaapi.PluginForm.Show(self, self.form_title, options=(
            idaapi.PluginForm.WOPN_TAB | idaapi.PluginForm.WCLS_CLOSE_LATER
        ))

    def OnClose(self, form):
        ''' form is closed '''
        self._unload_ida_hooks()
        self._ida_reset()

        logger.info('form closed.')

    def _load_interface(self):
        ''' load user interface '''
        # load models
        self._model_data = CapaExplorerDataModel()
        self._model_proxy = CapaExplorerSortFilterProxyModel()
        self._model_proxy.setSourceModel(self._model_data)

        # load tree
        self._view_tree = CapaExplorerQtreeView(self._model_proxy, self.parent)

        # load summary table
        self._load_view_summary()

        # load parent tab and children tab views
        self._load_view_tabs()
        self._load_view_checkbox_limit_by()
        self._load_view_summary_tab()
        self._load_view_tree_tab()

        # load menu bar and sub menus
        self._load_view_menu_bar()
        self._load_file_menu()

        # load parent view
        self._load_view_parent()

    def _load_view_tabs(self):
        ''' '''
        tabs = QTabWidget()

        self._view_tabs = tabs

    def _load_view_menu_bar(self):
        ''' '''
        bar = QMenuBar()
        # bar.hovered.connect(self._slot_menu_bar_hovered)

        self._view_menu_bar = bar

    def _load_view_summary(self):
        ''' '''
        table = QTableWidget()

        table.setColumnCount(4)
        table.verticalHeader().setVisible(False)
        table.setSortingEnabled(False)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setFocusPolicy(Qt.NoFocus)
        table.setSelectionMode(QAbstractItemView.NoSelection)
        table.setHorizontalHeaderLabels([
            'Objectives',
            'Behaviors',
            'Techniques',
            'Rule Hits'
        ])
        table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        table.setStyleSheet('QTableWidget::item { border: none; padding: 15px; }')
        table.setShowGrid(False)

        self._view_summary = table

    def _load_view_checkbox_limit_by(self):
        ''' '''
        check = QCheckBox('Limit results to current function')
        check.setChecked(False)
        check.stateChanged.connect(self._slot_checkbox_limit_by_changed)

        self._view_checkbox_limit_by = check

    def _load_view_parent(self):
        ''' load view parent '''
        layout = QVBoxLayout()
        layout.addWidget(self._view_tabs)
        layout.setMenuBar(self._view_menu_bar)

        self.parent.setLayout(layout)

    def _load_view_tree_tab(self):
        ''' load view tree tab '''
        layout = QVBoxLayout()
        layout.addWidget(self._view_checkbox_limit_by)
        layout.addWidget(self._view_tree)

        tab = QWidget()
        tab.setLayout(layout)

        self._view_tabs.addTab(tab, 'Tree View')

    def _load_view_summary_tab(self):
        ''' '''
        layout = QVBoxLayout()
        layout.addWidget(self._view_summary)

        tab = QWidget()
        tab.setLayout(layout)

        self._view_tabs.addTab(tab, 'Summary')

    def _load_file_menu(self):
        ''' load file menu actions '''
        actions = (
            ('Reset view', 'Reset plugin view', self.reset),
            ('Run analysis', 'Run capa analysis on current database', self.reload),
        )

        menu = self._view_menu_bar.addMenu('File')

        for name, _, handle in actions:
            action = QAction(name, self.parent)
            action.triggered.connect(handle)
            # action.setToolTip(tip)
            menu.addAction(action)

    def _load_ida_hooks(self):
        ''' '''
        action_hooks = {
            'MakeName': self._ida_hook_rename,
            'EditFunction': self._ida_hook_rename,
        }

        self._ida_hooks = CapaExplorerIdaHooks(self._ida_hook_screen_ea_changed, action_hooks)
        self._ida_hooks.hook()

    def _unload_ida_hooks(self):
        ''' unhook IDA user interface '''
        if self._ida_hooks:
            self._ida_hooks.unhook()

    def _ida_hook_rename(self, meta, post=False):
        ''' hook for IDA rename action

            called twice, once before action and once after
            action completes

            @param meta: TODO
            @param post: TODO
        '''
        ea = idaapi.get_screen_ea()
        if not ea or not capa.ida.helpers.is_func_start(ea):
            return

        curr_name = idaapi.get_name(ea)

        if post:
            # post action update data model w/ current name
            self._model_data.update_function_name(meta.get('prev_name', ''), curr_name)
        else:
            # pre action so save current name for replacement later
            meta['prev_name'] = curr_name

    def _ida_hook_screen_ea_changed(self, widget, new_ea, old_ea):
        ''' '''
        if not self._view_checkbox_limit_by.isChecked():
            # ignore if checkbox not selected
            return

        if idaapi.get_widget_type(widget) != idaapi.BWN_DISASM:
            # ignore views other than asm
            return

        # attempt to map virtual addresses to function start addresses
        new_func_start = capa.ida.helpers.get_func_start_ea(new_ea)
        old_func_start = capa.ida.helpers.get_func_start_ea(old_ea)

        if new_func_start and new_func_start == old_func_start:
            # navigated within the same function - do nothing
            return

        if new_func_start:
            # navigated to new function - filter for function start virtual address
            match = capa.ida.explorer.item.ea_to_hex_str(new_func_start)
        else:
            # navigated to virtual address not in valid function - clear filter
            match = ''

        # filter on virtual address to avoid updating filter string if function name is changed
        self._model_proxy.add_single_string_filter(CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS, match)

    def _load_capa_results(self):
        ''' '''
        logger.info('-' * 80)
        logger.info(' Using default embedded rules.')
        logger.info(' ')
        logger.info(' You can see the current default rule set here:')
        logger.info('     https://github.com/fireeye/capa-rules')
        logger.info('-' * 80)

        rules_path = os.path.join(os.path.dirname(self._file_loc), '../..', 'rules')
        rules = capa.main.get_rules(rules_path)
        rules = capa.rules.RuleSet(rules)
        capabilities = capa.main.find_capabilities(rules, capa.features.extractors.ida.IdaFeatureExtractor(), True)

        if capa.main.is_file_limitation(rules, capabilities):
            idaapi.info('capa encountered warnings during analysis. Please refer to the IDA Output window for more information.')

        logger.info('analysis completed.')

        self._model_data.render_capa_results(rules, capabilities)
        self._render_capa_summary(rules, capabilities)

        logger.info('render views completed.')

    def _render_capa_summary(self, ruleset, results):
        ''' render results summary table

            keep sync with capa.main

            @param ruleset: TODO
            @param results: TODO
        '''
        rules = set(filter(lambda x: not ruleset.rules[x].meta.get('lib', False), results.keys()))
        objectives = set()
        behaviors = set()
        techniques = set()

        for rule in rules:
            parts = ruleset.rules[rule].meta.get(capa.main.RULE_CATEGORY, '').split('/')
            if len(parts) == 0 or list(parts) == ['']:
                continue
            if len(parts) > 0:
                objective = parts[0].replace('-', ' ')
                objectives.add(objective)
            if len(parts) > 1:
                behavior = parts[1].replace('-', ' ')
                behaviors.add(behavior)
            if len(parts) > 2:
                technique = parts[2].replace('-', ' ')
                techniques.add(technique)
            if len(parts) > 3:
                raise capa.rules.InvalidRule(capa.main.RULE_CATEGORY + ' tag must have at most three components')

        # set row count to max set size
        self._view_summary.setRowCount(max(map(len, (rules, objectives, behaviors, techniques))))

        # format rule hits
        rules = map(lambda x: '%s (%d)' % (x, len(results[x])), rules)

        # sort results
        columns = list(map(lambda x: sorted(x, key=lambda s: s.lower()), (objectives, behaviors, techniques, rules)))

        # load results into table by column
        for idx, column in enumerate(columns):
            self._load_view_summary_column(idx, column)

        # resize columns to content
        self._view_summary.resizeColumnsToContents()

    def _load_view_summary_column(self, column, texts):
        ''' '''
        for row, text in enumerate(texts):
            self._view_summary.setItem(row, column, QTableWidgetItem(text))

    def _ida_reset(self):
        ''' reset IDA user interface '''
        self._model_data.reset()
        self._view_tree.reset()
        self._view_checkbox_limit_by.setChecked(False)

    def reload(self):
        ''' reload views and re-run capa analysis '''
        self._ida_reset()
        self._model_proxy.invalidate()
        self._model_data.clear()
        self._view_summary.setRowCount(0)
        self._load_capa_results()

        logger.info('reload complete.')
        idaapi.info('%s reload completed.' % PLUGIN_NAME)

    def reset(self):
        ''' reset user interface elements

            e.g. checkboxes and IDA highlighting
        '''
        self._ida_reset()

        logger.info('reset completed.')
        idaapi.info('%s reset completed.' % PLUGIN_NAME)

    def _slot_menu_bar_hovered(self, action):
        ''' display menu action tooltip

            @param action: QAction*

            @reference: https://stackoverflow.com/questions/21725119/why-wont-qtooltips-appear-on-qactions-within-a-qmenu
        '''
        QToolTip.showText(QCursor.pos(), action.toolTip(), self._view_menu_bar, self._view_menu_bar.actionGeometry(action))

    def _slot_checkbox_limit_by_changed(self):
        ''' slot activated if checkbox clicked

            if checked, configure function filter if screen ea is located
            in function, otherwise clear filter
        '''
        match = ''
        if self._view_checkbox_limit_by.isChecked():
            ea = capa.ida.helpers.get_func_start_ea(idaapi.get_screen_ea())
            if ea:
                match = capa.ida.explorer.item.ea_to_hex_str(ea)
        self._model_proxy.add_single_string_filter(CapaExplorerDataModel.COLUMN_INDEX_VIRTUAL_ADDRESS, match)

        self._view_tree.resize_columns_to_content()


def main():
    ''' TODO: move to idaapi.plugin_t class '''
    logging.basicConfig(level=logging.INFO)

    if idaapi.get_file_type_name() not in SUPPORTED_FILE_TYPES:
        logger.error('-' * 80)
        logger.error(' Input file does not appear to be a PE file.')
        logger.error(' ')
        logger.error(' capa explorer currently only supports analyzing PE files.')
        logger.error('-' * 80)
        idaapi.info('capa does not support the format of this file. Please refer to the IDA output window for more information.')
        return -1

    global CAPA_EXPLORER_FORM

    try:
        # there is an instance, reload it
        CAPA_EXPLORER_FORM
        CAPA_EXPLORER_FORM.Close()
        CAPA_EXPLORER_FORM = CapaExplorerForm()
    except Exception:
        # there is no instance yet
        CAPA_EXPLORER_FORM = CapaExplorerForm()

    CAPA_EXPLORER_FORM.Show()


if __name__ == '__main__':
    main()
