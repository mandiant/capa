# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os
import json
import logging
import collections

import idaapi
from PyQt5 import QtGui, QtCore, QtWidgets

import capa.main
import capa.rules
import capa.ida.helpers
import capa.render.utils as rutils
import capa.features.extractors.ida
from capa.ida.explorer.view import CapaExplorerQtreeView
from capa.ida.explorer.model import CapaExplorerDataModel
from capa.ida.explorer.proxy import CapaExplorerSortFilterProxyModel

PLUGIN_NAME = "capa explorer"

logger = logging.getLogger("capa")


class CapaExplorerIdaHooks(idaapi.UI_Hooks):
    def __init__(self, screen_ea_changed_hook, action_hooks):
        """facilitate IDA UI hooks

        @param screen_ea_changed_hook: function hook for IDA screen ea changed
        @param action_hooks: dict of IDA action handles
        """
        super(CapaExplorerIdaHooks, self).__init__()

        self.screen_ea_changed_hook = screen_ea_changed_hook
        self.process_action_hooks = action_hooks
        self.process_action_handle = None
        self.process_action_meta = {}

    def preprocess_action(self, name):
        """called prior to action completed

        @param name: name of action defined by idagui.cfg

        @retval must be 0
        """
        self.process_action_handle = self.process_action_hooks.get(name, None)

        if self.process_action_handle:
            self.process_action_handle(self.process_action_meta)

        # must return 0 for IDA
        return 0

    def postprocess_action(self):
        """ called after action completed """
        if not self.process_action_handle:
            return

        self.process_action_handle(self.process_action_meta, post=True)
        self.reset()

    def screen_ea_changed(self, curr_ea, prev_ea):
        """called after screen location is changed

        @param curr_ea: current location
        @param prev_ea: prev location
        """
        self.screen_ea_changed_hook(idaapi.get_current_widget(), curr_ea, prev_ea)

    def reset(self):
        """ reset internal state """
        self.process_action_handle = None
        self.process_action_meta.clear()


class CapaExplorerForm(idaapi.PluginForm):
    def __init__(self):
        """ """
        super(CapaExplorerForm, self).__init__()

        self.form_title = PLUGIN_NAME
        self.file_loc = __file__

        self.parent = None
        self.ida_hooks = None
        self.doc = None

        # models
        self.model_data = None
        self.model_proxy = None

        # user interface elements
        self.view_limit_results_by_function = None
        self.view_tree = None
        self.view_summary = None
        self.view_attack = None
        self.view_tabs = None
        self.view_menu_bar = None

    def OnCreate(self, form):
        """ """
        self.parent = self.FormToPyQtWidget(form)
        self.load_interface()
        self.load_capa_results()
        self.load_ida_hooks()

        self.view_tree.reset()

        logger.info("form created.")

    def Show(self):
        """ """
        return idaapi.PluginForm.Show(
            self, self.form_title, options=(idaapi.PluginForm.WOPN_TAB | idaapi.PluginForm.WCLS_CLOSE_LATER)
        )

    def OnClose(self, form):
        """ form is closed """
        self.unload_ida_hooks()
        self.ida_reset()

        logger.info("form closed.")

    def load_interface(self):
        """ load user interface """
        # load models
        self.model_data = CapaExplorerDataModel()
        self.model_proxy = CapaExplorerSortFilterProxyModel()
        self.model_proxy.setSourceModel(self.model_data)

        # load tree
        self.view_tree = CapaExplorerQtreeView(self.model_proxy, self.parent)

        # load summary table
        self.load_view_summary()
        self.load_view_attack()

        # load parent tab and children tab views
        self.load_view_tabs()
        self.load_view_checkbox_limit_by()
        self.load_view_summary_tab()
        self.load_view_attack_tab()
        self.load_view_tree_tab()

        # load menu bar and sub menus
        self.load_view_menu_bar()
        self.load_file_menu()

        # load parent view
        self.load_view_parent()

    def load_view_tabs(self):
        """ load tabs """
        tabs = QtWidgets.QTabWidget()
        self.view_tabs = tabs

    def load_view_menu_bar(self):
        """ load menu bar """
        bar = QtWidgets.QMenuBar()
        self.view_menu_bar = bar

    def load_view_summary(self):
        """ load capa summary table """
        table_headers = [
            "Capability",
            "Namespace",
        ]

        table = QtWidgets.QTableWidget()

        table.setColumnCount(len(table_headers))
        table.verticalHeader().setVisible(False)
        table.setSortingEnabled(False)
        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.setFocusPolicy(QtCore.Qt.NoFocus)
        table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        table.setHorizontalHeaderLabels(table_headers)
        table.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)
        table.setShowGrid(False)
        table.setStyleSheet("QTableWidget::item { padding: 25px; }")

        self.view_summary = table

    def load_view_attack(self):
        """ load MITRE ATT&CK table """
        table_headers = [
            "ATT&CK Tactic",
            "ATT&CK Technique ",
        ]

        table = QtWidgets.QTableWidget()

        table.setColumnCount(len(table_headers))
        table.verticalHeader().setVisible(False)
        table.setSortingEnabled(False)
        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.setFocusPolicy(QtCore.Qt.NoFocus)
        table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        table.setHorizontalHeaderLabels(table_headers)
        table.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)
        table.setShowGrid(False)
        table.setStyleSheet("QTableWidget::item { padding: 25px; }")

        self.view_attack = table

    def load_view_checkbox_limit_by(self):
        """ load limit results by function checkbox """
        check = QtWidgets.QCheckBox("Limit results to current function")
        check.setChecked(False)
        check.stateChanged.connect(self.slot_checkbox_limit_by_changed)

        self.view_limit_results_by_function = check

    def load_view_parent(self):
        """ load view parent """
        layout = QtWidgets.QVBoxLayout()

        layout.addWidget(self.view_tabs)
        layout.setMenuBar(self.view_menu_bar)

        self.parent.setLayout(layout)

    def load_view_tree_tab(self):
        """ load capa tree tab view """
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.view_limit_results_by_function)
        layout.addWidget(self.view_tree)

        tab = QtWidgets.QWidget()
        tab.setLayout(layout)

        self.view_tabs.addTab(tab, "Tree View")

    def load_view_summary_tab(self):
        """ load capa summary tab view """
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.view_summary)

        tab = QtWidgets.QWidget()
        tab.setLayout(layout)

        self.view_tabs.addTab(tab, "Summary")

    def load_view_attack_tab(self):
        """ load MITRE ATT&CK tab view """
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.view_attack)

        tab = QtWidgets.QWidget()
        tab.setLayout(layout)

        self.view_tabs.addTab(tab, "MITRE")

    def load_file_menu(self):
        """ load file menu actions """
        actions = (
            ("Reset view", "Reset plugin view", self.reset),
            ("Run analysis", "Run capa analysis on current database", self.reload),
            ("Export results...", "Export capa results as JSON file", self.export_json),
        )

        menu = self.view_menu_bar.addMenu("File")
        for (name, _, handle) in actions:
            action = QtWidgets.QAction(name, self.parent)
            action.triggered.connect(handle)
            menu.addAction(action)

    def export_json(self):
        """ export capa results as JSON file """
        if not self.doc:
            idaapi.info("No capa results to export.")
            return
        path = idaapi.ask_file(True, "*.json", "Choose file")
        if os.path.exists(path) and 1 != idaapi.ask_yn(1, "File already exists. Overwrite?"):
            return
        with open(path, "wb") as export_file:
            export_file.write(
                json.dumps(self.doc, sort_keys=True, cls=capa.render.CapaJsonObjectEncoder).encode("utf-8")
            )

    def load_ida_hooks(self):
        """ load IDA Pro UI hooks """
        action_hooks = {
            "MakeName": self.ida_hook_rename,
            "EditFunction": self.ida_hook_rename,
        }

        self.ida_hooks = CapaExplorerIdaHooks(self.ida_hook_screen_ea_changed, action_hooks)
        self.ida_hooks.hook()

    def unload_ida_hooks(self):
        """ unload IDA Pro UI hooks """
        if self.ida_hooks:
            self.ida_hooks.unhook()

    def ida_hook_rename(self, meta, post=False):
        """hook for IDA rename action

        called twice, once before action and once after
        action completes

        @param meta: metadata cache
        @param post: indicates pre or post action
        """
        location = idaapi.get_screen_ea()
        if not location or not capa.ida.helpers.is_func_start(location):
            return

        curr_name = idaapi.get_name(location)

        if post:
            # post action update data model w/ current name
            self.model_data.update_function_name(meta.get("prev_name", ""), curr_name)
        else:
            # pre action so save current name for replacement later
            meta["prev_name"] = curr_name

    def ida_hook_screen_ea_changed(self, widget, new_ea, old_ea):
        """hook for IDA screen ea changed

        this hook is currently only relevant for limiting results displayed in the UI

        @param widget: IDA widget type
        @param new_ea: destination ea
        @param old_ea: source ea
        """
        if not self.view_limit_results_by_function.isChecked():
            # ignore if limit checkbox not selected
            return

        if idaapi.get_widget_type(widget) != idaapi.BWN_DISASM:
            # ignore views not the assembly view
            return

        if idaapi.get_func(new_ea) == idaapi.get_func(old_ea):
            # user navigated same function - ignore
            return

        self.limit_results_to_function(idaapi.get_func(new_ea))
        self.view_tree.resize_columns_to_content()

    def load_capa_results(self):
        """ run capa analysis and render results in UI """
        logger.info("-" * 80)
        logger.info(" Using default embedded rules.")
        logger.info(" ")
        logger.info(" You can see the current default rule set here:")
        logger.info("     https://github.com/fireeye/capa-rules")
        logger.info("-" * 80)

        rules_path = os.path.join(os.path.dirname(self.file_loc), "../..", "rules")
        rules = capa.main.get_rules(rules_path)
        rules = capa.rules.RuleSet(rules)

        meta = capa.ida.helpers.collect_metadata()

        capabilities, counts = capa.main.find_capabilities(
            rules, capa.features.extractors.ida.IdaFeatureExtractor(), True
        )
        meta["analysis"].update(counts)

        # support binary files specifically for x86/AMD64 shellcode
        # warn user binary file is loaded but still allow capa to process it
        # TODO: check specific architecture of binary files based on how user configured IDA processors
        if idaapi.get_file_type_name() == "Binary file":
            logger.warning("-" * 80)
            logger.warning(" Input file appears to be a binary file.")
            logger.warning(" ")
            logger.warning(
                " capa currently only supports analyzing binary files containing x86/AMD64 shellcode with IDA."
            )
            logger.warning(
                " This means the results may be misleading or incomplete if the binary file loaded in IDA is not x86/AMD64."
            )
            logger.warning(" If you don't know the input file type, you can try using the `file` utility to guess it.")
            logger.warning("-" * 80)

            capa.ida.helpers.inform_user_ida_ui("capa encountered warnings during analysis")

        if capa.main.has_file_limitation(rules, capabilities, is_standalone=False):
            capa.ida.helpers.inform_user_ida_ui("capa encountered warnings during analysis")

        logger.info("analysis completed.")

        self.doc = capa.render.convert_capabilities_to_result_document(meta, rules, capabilities)

        self.model_data.render_capa_doc(self.doc)
        self.render_capa_doc_summary()
        self.render_capa_doc_mitre_summary()

        self.set_view_tree_default_sort_order()

        logger.info("render views completed.")

    def set_view_tree_default_sort_order(self):
        """ set capa tree view default sort order """
        self.view_tree.sortByColumn(CapaExplorerDataModel.COLUMN_INDEX_RULE_INFORMATION, QtCore.Qt.AscendingOrder)

    def render_capa_doc_summary(self):
        """ render capa summary results """
        for (row, rule) in enumerate(rutils.capability_rules(self.doc)):
            count = len(rule["matches"])

            if count == 1:
                capability = rule["meta"]["name"]
            else:
                capability = "%s (%d matches)" % (rule["meta"]["name"], count)

            self.view_summary.setRowCount(row + 1)

            self.view_summary.setItem(row, 0, self.render_new_table_header_item(capability))
            self.view_summary.setItem(row, 1, QtWidgets.QTableWidgetItem(rule["meta"]["namespace"]))

        # resize columns to content
        self.view_summary.resizeColumnsToContents()

    def render_capa_doc_mitre_summary(self):
        """ render capa MITRE ATT&CK results """
        tactics = collections.defaultdict(set)

        for rule in rutils.capability_rules(self.doc):
            if not rule["meta"].get("att&ck"):
                continue

            for attack in rule["meta"]["att&ck"]:
                tactic, _, rest = attack.partition("::")
                if "::" in rest:
                    technique, _, rest = rest.partition("::")
                    subtechnique, _, id = rest.rpartition(" ")
                    tactics[tactic].add((technique, subtechnique, id))
                else:
                    technique, _, id = rest.rpartition(" ")
                    tactics[tactic].add((technique, id))

        column_one = []
        column_two = []

        for (tactic, techniques) in sorted(tactics.items()):
            column_one.append(tactic.upper())
            # add extra space when more than one technique
            column_one.extend(["" for i in range(len(techniques) - 1)])

            for spec in sorted(techniques):
                if len(spec) == 2:
                    technique, id = spec
                    column_two.append("%s %s" % (technique, id))
                elif len(spec) == 3:
                    technique, subtechnique, id = spec
                    column_two.append("%s::%s %s" % (technique, subtechnique, id))
                else:
                    raise RuntimeError("unexpected ATT&CK spec format")

        self.view_attack.setRowCount(max(len(column_one), len(column_two)))

        for row, value in enumerate(column_one):
            self.view_attack.setItem(row, 0, self.render_new_table_header_item(value))

        for row, value in enumerate(column_two):
            self.view_attack.setItem(row, 1, QtWidgets.QTableWidgetItem(value))

        # resize columns to content
        self.view_attack.resizeColumnsToContents()

    def render_new_table_header_item(self, text):
        """ create new table header item with default style """
        item = QtWidgets.QTableWidgetItem(text)
        item.setForeground(QtGui.QColor(88, 139, 174))

        font = QtGui.QFont()
        font.setBold(True)

        item.setFont(font)

        return item

    def ida_reset(self):
        """ reset IDA UI """
        self.model_data.reset()
        self.view_tree.reset()
        self.view_limit_results_by_function.setChecked(False)
        self.set_view_tree_default_sort_order()

    def reload(self):
        """ reload views and re-run capa analysis """
        self.ida_reset()
        self.model_proxy.invalidate()
        self.model_data.clear()
        self.view_summary.setRowCount(0)
        self.load_capa_results()

        logger.info("reload complete.")
        idaapi.info("%s reload completed." % PLUGIN_NAME)

    def reset(self):
        """reset UI elements

        e.g. checkboxes and IDA highlighting
        """
        self.ida_reset()

        logger.info("reset completed.")
        idaapi.info("%s reset completed." % PLUGIN_NAME)

    def slot_menu_bar_hovered(self, action):
        """display menu action tooltip

        @param action: QtWidgets.QAction*

        @reference: https://stackoverflow.com/questions/21725119/why-wont-qtooltips-appear-on-qactions-within-a-qmenu
        """
        QtWidgets.QToolTip.showText(
            QtGui.QCursor.pos(), action.toolTip(), self.view_menu_bar, self.view_menu_bar.actionGeometry(action)
        )

    def slot_checkbox_limit_by_changed(self):
        """slot activated if checkbox clicked

        if checked, configure function filter if screen location is located
        in function, otherwise clear filter
        """
        if self.view_limit_results_by_function.isChecked():
            self.limit_results_to_function(idaapi.get_func(idaapi.get_screen_ea()))
        else:
            self.model_proxy.reset_address_range_filter()

        self.view_tree.reset()

    def limit_results_to_function(self, f):
        """add filter to limit results to current function

        @param f: (IDA func_t)
        """
        if f:
            self.model_proxy.add_address_range_filter(f.start_ea, f.end_ea)
        else:
            # if function not exists don't display any results (address should not be -1)
            self.model_proxy.add_address_range_filter(-1, -1)


def main():
    """ TODO: move to idaapi.plugin_t class """
    logging.basicConfig(level=logging.INFO)

    if not capa.ida.helpers.is_supported_ida_version():
        return -1

    if not capa.ida.helpers.is_supported_file_type():
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


if __name__ == "__main__":
    main()
