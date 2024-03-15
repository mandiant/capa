# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import copy
import logging
import itertools
import collections
from enum import IntFlag
from typing import Any, List, Optional
from pathlib import Path

import idaapi
import ida_kernwin
import ida_settings
from PyQt5 import QtGui, QtCore, QtWidgets

import capa.main
import capa.rules
import capa.engine
import capa.version
import capa.ida.helpers
import capa.render.json
import capa.features.common
import capa.capabilities.common
import capa.render.result_document
import capa.features.extractors.ida.extractor
from capa.rules import Rule
from capa.engine import FeatureSet
from capa.rules.cache import compute_ruleset_cache_identifier
from capa.ida.plugin.icon import ICON
from capa.ida.plugin.view import (
    CapaExplorerQtreeView,
    CapaExplorerRulegenEditor,
    CapaExplorerRulegenPreview,
    CapaExplorerRulegenFeatures,
)
from capa.ida.plugin.cache import CapaRuleGenFeatureCache
from capa.ida.plugin.error import UserCancelledError
from capa.ida.plugin.hooks import CapaExplorerIdaHooks
from capa.ida.plugin.model import CapaExplorerDataModel
from capa.ida.plugin.proxy import CapaExplorerRangeProxyModel, CapaExplorerSearchProxyModel
from capa.ida.plugin.extractor import CapaExplorerFeatureExtractor
from capa.features.extractors.base_extractor import FunctionHandle

logger = logging.getLogger(__name__)
settings = ida_settings.IDASettings("capa")

CAPA_SETTINGS_RULE_PATH = "rule_path"
CAPA_SETTINGS_RULEGEN_AUTHOR = "rulegen_author"
CAPA_SETTINGS_RULEGEN_SCOPE = "rulegen_scope"
CAPA_SETTINGS_ANALYZE = "analyze"


CAPA_OFFICIAL_RULESET_URL = f"https://github.com/mandiant/capa-rules/releases/tag/v{capa.version.__version__}"
CAPA_RULESET_DOC_URL = "https://github.com/mandiant/capa/blob/master/doc/rules.md"


class Options(IntFlag):
    NO_ANALYSIS = 0  # No auto analysis
    ANALYZE_AUTO = 1  # Runs the analysis when starting the explorer, see details below
    ANALYZE_ASK = 2


AnalyzeOptionsText = {
    Options.NO_ANALYSIS: "Do not analyze",
    Options.ANALYZE_AUTO: "Analyze on plugin start (load cached results)",
    Options.ANALYZE_ASK: "Analyze on plugin start (ask before loading cached results)",
}


def write_file(path: Path, data):
    """ """
    path.write_bytes(data)


def trim_function_name(f, max_length=25):
    """ """
    n = idaapi.get_name(f.start_ea)
    if len(n) > max_length:
        n = f"{n[:max_length]}..."
    return n


def update_wait_box(text):
    """update the IDA wait box"""
    ida_kernwin.replace_wait_box(f"capa explorer...{text}")


class QLineEditClicked(QtWidgets.QLineEdit):
    def __init__(self, content, parent=None):
        """ """
        super().__init__(content, parent)

    def mouseReleaseEvent(self, e):
        """ """
        old = self.text()
        new = str(
            QtWidgets.QFileDialog.getExistingDirectory(
                self.parent(), "Please select a capa rules directory", settings.user.get(CAPA_SETTINGS_RULE_PATH, "")
            )
        )
        if new:
            self.setText(new)
        else:
            self.setText(old)


class CapaSettingsInputDialog(QtWidgets.QDialog):
    def __init__(self, title, parent=None):
        """ """
        super().__init__(parent)

        self.setWindowTitle(title)
        self.setMinimumWidth(500)
        self.setWindowFlags(self.windowFlags() & ~QtCore.Qt.WindowContextHelpButtonHint)

        self.edit_rule_path = QLineEditClicked(settings.user.get(CAPA_SETTINGS_RULE_PATH, ""))
        self.edit_rule_author = QtWidgets.QLineEdit(settings.user.get(CAPA_SETTINGS_RULEGEN_AUTHOR, ""))
        self.edit_rule_scope = QtWidgets.QComboBox()
        self.edit_rules_link = QtWidgets.QLabel()
        self.edit_analyze = QtWidgets.QComboBox()
        self.btn_delete_results = QtWidgets.QPushButton(
            self.style().standardIcon(QtWidgets.QStyle.SP_BrowserStop), "Delete cached capa results"
        )

        self.edit_rules_link.setText(
            f'<a href="{CAPA_OFFICIAL_RULESET_URL}">Download and extract official capa rules</a>'
        )
        self.edit_rules_link.setOpenExternalLinks(True)

        scopes = ("file", "function", "basic block", "instruction")
        self.edit_rule_scope.addItems(scopes)
        self.edit_rule_scope.setCurrentIndex(scopes.index(settings.user.get(CAPA_SETTINGS_RULEGEN_SCOPE, "function")))

        self.edit_analyze.addItems(AnalyzeOptionsText.values())
        # set the default analysis option here
        self.edit_analyze.setCurrentIndex(settings.user.get(CAPA_SETTINGS_ANALYZE, Options.NO_ANALYSIS))

        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel, self)

        layout = QtWidgets.QFormLayout(self)
        layout.addRow("capa rules path", self.edit_rule_path)
        layout.addRow("", self.edit_rules_link)

        layout.addRow("Plugin start option", self.edit_analyze)
        if capa.ida.helpers.idb_contains_cached_results():
            self.btn_delete_results.clicked.connect(capa.ida.helpers.delete_cached_results)
            self.btn_delete_results.clicked.connect(lambda state: self.btn_delete_results.setEnabled(False))
        else:
            self.btn_delete_results.setEnabled(False)
        layout.addRow("", self.btn_delete_results)

        layout.addRow("Rule Generator options", None)
        layout.addRow("Default rule author", self.edit_rule_author)
        layout.addRow("Default rule scope", self.edit_rule_scope)

        layout.addWidget(buttons)

        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

    def get_values(self):
        """ """
        return (
            self.edit_rule_path.text(),
            self.edit_rule_author.text(),
            self.edit_rule_scope.currentText(),
            self.edit_analyze.currentIndex(),
        )


class CapaExplorerForm(idaapi.PluginForm):
    """form element for plugin interface"""

    def __init__(self, name: str, option=Options.NO_ANALYSIS):
        """initialize form elements"""
        super().__init__()

        self.form_title: str = name
        self.process_total: int = 0
        self.process_count: int = 0

        self.parent: Any  # QtWidget
        self.ida_hooks: CapaExplorerIdaHooks

        # caches used to speed up capa explorer analysis - these must be init to None
        self.resdoc_cache: Optional[capa.render.result_document.ResultDocument] = None
        self.program_analysis_ruleset_cache: Optional[capa.rules.RuleSet] = None
        self.feature_extractor: Optional[CapaExplorerFeatureExtractor] = None
        self.rulegen_feature_extractor: Optional[CapaExplorerFeatureExtractor] = None
        self.rulegen_feature_cache: Optional[CapaRuleGenFeatureCache] = None
        self.rulegen_ruleset_cache: Optional[capa.rules.RuleSet] = None
        self.rulegen_current_function: Optional[FunctionHandle] = None

        # models
        self.model_data: CapaExplorerDataModel
        self.range_model_proxy: CapaExplorerRangeProxyModel
        self.search_model_proxy: CapaExplorerSearchProxyModel

        # UI controls
        self.view_limit_results_by_function: QtWidgets.QCheckBox
        self.view_show_results_by_function: QtWidgets.QCheckBox
        self.view_search_bar: QtWidgets.QLineEdit
        self.view_tree: CapaExplorerQtreeView
        self.view_tabs: QtWidgets.QTabWidget
        self.view_tab_rulegen = None
        self.view_status_label: QtWidgets.QLabel
        self.view_status_label_analysis_cache: str = ""
        self.view_status_label_rulegen_cache: str = ""
        self.view_buttons: QtWidgets.QHBoxLayout
        self.view_analyze_button: QtWidgets.QPushButton
        self.view_reset_button: QtWidgets.QPushButton
        self.view_settings_button: QtWidgets.QPushButton
        self.view_save_button: QtWidgets.QPushButton

        # UI controls for rule generator
        self.view_rulegen_preview: CapaExplorerRulegenPreview
        self.view_rulegen_features: CapaExplorerRulegenFeatures
        self.view_rulegen_editor: CapaExplorerRulegenEditor
        self.view_rulegen_header_label: QtWidgets.QLabel
        self.view_rulegen_search: QtWidgets.QLineEdit
        self.view_rulegen_limit_features_by_ea: QtWidgets.QCheckBox
        self.view_rulegen_status_label: QtWidgets.QLabel

        self.Show()

        analyze = settings.user.get(CAPA_SETTINGS_ANALYZE)
        if analyze != Options.NO_ANALYSIS or (option & Options.ANALYZE_AUTO) == Options.ANALYZE_AUTO:
            self.analyze_program(analyze=analyze)

    def OnCreate(self, form):
        """called when plugin form is created

        load interface and install hooks but do not analyze database
        """
        self.parent = self.FormToPyQtWidget(form)

        pixmap = QtGui.QPixmap()
        pixmap.loadFromData(ICON)

        self.parent.setWindowIcon(QtGui.QIcon(pixmap))

        self.load_interface()
        self.load_ida_hooks()

    def Show(self):
        """creates form if not already create, else brings plugin to front"""
        return super().Show(
            self.form_title,
            options=(
                idaapi.PluginForm.WOPN_TAB
                | idaapi.PluginForm.WOPN_RESTORE
                | idaapi.PluginForm.WCLS_CLOSE_LATER
                | idaapi.PluginForm.WCLS_SAVE
            ),
        )

    def OnClose(self, form):
        """called when form is closed

        ensure any plugin modifications (e.g. hooks and UI changes) are reset before the plugin is closed
        """
        self.unload_ida_hooks()
        self.model_data.reset()

    def load_interface(self):
        """load user interface"""
        # load models
        self.model_data = CapaExplorerDataModel()

        # model <- filter range <- filter search <- view

        self.range_model_proxy = CapaExplorerRangeProxyModel()
        self.range_model_proxy.setSourceModel(self.model_data)

        self.search_model_proxy = CapaExplorerSearchProxyModel()
        self.search_model_proxy.setSourceModel(self.range_model_proxy)

        self.view_tree = CapaExplorerQtreeView(self.search_model_proxy, self.parent)

        # load parent tab and children tab views
        self.load_view_tabs()
        self.load_view_checkbox_limit_by()
        self.load_view_checkbox_show_matches_by_function()
        self.load_view_search_bar()
        self.load_view_tree_tab()
        self.load_view_rulegen_tab()
        self.load_view_status_label()
        self.load_view_buttons()

        # reset on tab change program analysis/rule generator
        self.view_tabs.currentChanged.connect(self.slot_tabview_change)

        # load parent view
        self.load_view_parent()

    def load_view_tabs(self):
        """load tabs"""
        tabs = QtWidgets.QTabWidget()
        self.view_tabs = tabs

    def load_view_checkbox_limit_by(self):
        """load limit results by function checkbox"""
        check = QtWidgets.QCheckBox("Limit results to current function")
        check.setChecked(False)
        check.stateChanged.connect(self.slot_checkbox_limit_by_changed)

        self.view_limit_results_by_function = check

    def load_view_checkbox_show_matches_by_function(self):
        """load limit results by function checkbox"""
        check = QtWidgets.QCheckBox("Show matches by function")
        check.setChecked(False)
        check.stateChanged.connect(self.slot_checkbox_show_results_by_function_changed)

        self.view_show_results_by_function = check

    def load_view_status_label(self):
        """load status label"""
        status: str = "Click Analyze to get started..."

        label = QtWidgets.QLabel()
        label.setAlignment(QtCore.Qt.AlignLeft)
        label.setText(status)

        self.view_status_label_rulegen_cache = status
        self.view_status_label_analysis_cache = status

        self.view_status_label = label

    def load_view_buttons(self):
        """load the button controls"""
        analyze_button = QtWidgets.QPushButton("Analyze")
        reset_button = QtWidgets.QPushButton("Reset Selections")
        save_button = QtWidgets.QPushButton("Save")
        settings_button = QtWidgets.QPushButton("Settings")

        analyze_button.clicked.connect(self.slot_analyze)
        reset_button.clicked.connect(self.slot_reset)
        save_button.clicked.connect(self.slot_save)
        settings_button.clicked.connect(self.slot_settings)

        layout = QtWidgets.QHBoxLayout()
        layout.addWidget(analyze_button)
        layout.addWidget(reset_button)
        layout.addWidget(settings_button)
        layout.addStretch(3)
        layout.addWidget(save_button, alignment=QtCore.Qt.AlignRight)

        self.view_analyze_button = analyze_button
        self.view_reset_button = reset_button
        self.view_settings_button = settings_button
        self.view_save_button = save_button
        self.view_buttons = layout

    def load_view_search_bar(self):
        """load the search bar control"""
        line = QtWidgets.QLineEdit()
        line.setPlaceholderText("search...")
        line.textChanged.connect(self.slot_limit_results_to_search)

        self.view_search_bar = line

    def load_view_parent(self):
        """load view parent"""
        layout = QtWidgets.QVBoxLayout()

        layout.addWidget(self.view_tabs)
        layout.addLayout(self.view_buttons)
        layout.addWidget(self.view_status_label)

        self.parent.setLayout(layout)

    def load_view_tree_tab(self):
        """load tree view tab"""
        layout2 = QtWidgets.QHBoxLayout()
        layout2.addWidget(self.view_limit_results_by_function)
        layout2.addWidget(self.view_show_results_by_function)

        checkboxes = QtWidgets.QWidget()
        checkboxes.setLayout(layout2)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(checkboxes)
        layout.addWidget(self.view_search_bar)
        layout.addWidget(self.view_tree)

        tab = QtWidgets.QWidget()
        tab.setLayout(layout)

        self.view_tabs.addTab(tab, "Program Analysis")

    def load_view_rulegen_tab(self):
        """ """
        layout = QtWidgets.QHBoxLayout()
        layout1 = QtWidgets.QVBoxLayout()
        layout2 = QtWidgets.QVBoxLayout()
        layout3 = QtWidgets.QVBoxLayout()

        right_top = QtWidgets.QWidget()
        right_top.setLayout(layout1)
        right_bottom = QtWidgets.QWidget()
        right_bottom.setLayout(layout3)

        left = QtWidgets.QWidget()
        left.setLayout(layout2)

        font = QtGui.QFont()
        font.setBold(True)
        font.setPointSize(11)

        label1 = QtWidgets.QLabel()
        label1.setAlignment(QtCore.Qt.AlignLeft)
        label1.setText("Preview")
        label1.setFont(font)

        label2 = QtWidgets.QLabel()
        label2.setAlignment(QtCore.Qt.AlignLeft)
        label2.setText("Editor")
        label2.setFont(font)

        self.view_rulegen_limit_features_by_ea = QtWidgets.QCheckBox("Limit features to current disassembly address")
        self.view_rulegen_limit_features_by_ea.setChecked(False)
        self.view_rulegen_limit_features_by_ea.stateChanged.connect(self.slot_checkbox_limit_features_by_ea)

        self.view_rulegen_status_label = QtWidgets.QLabel()
        self.view_rulegen_status_label.setAlignment(QtCore.Qt.AlignLeft)
        self.view_rulegen_status_label.setText("")

        self.view_rulegen_search = QtWidgets.QLineEdit()
        self.view_rulegen_search.setPlaceholderText("search...")
        self.view_rulegen_search.setClearButtonEnabled(True)
        self.view_rulegen_search.textChanged.connect(self.slot_limit_rulegen_features_to_search)

        self.view_rulegen_header_label = QtWidgets.QLabel()
        self.view_rulegen_header_label.setAlignment(QtCore.Qt.AlignLeft)
        self.view_rulegen_header_label.setText("Features")
        self.view_rulegen_header_label.setFont(font)

        self.view_rulegen_preview = CapaExplorerRulegenPreview(parent=self.parent)
        self.view_rulegen_editor = CapaExplorerRulegenEditor(self.view_rulegen_preview, parent=self.parent)
        self.view_rulegen_features = CapaExplorerRulegenFeatures(self.view_rulegen_editor, parent=self.parent)

        self.view_rulegen_preview.textChanged.connect(self.slot_rulegen_preview_update)
        self.view_rulegen_editor.updated.connect(self.slot_rulegen_editor_update)

        self.set_rulegen_preview_border_neutral()

        layout1.addWidget(label1)
        layout1.addWidget(self.view_rulegen_preview, 45)
        layout1.addWidget(self.view_rulegen_status_label)
        layout3.addWidget(label2)
        layout3.addWidget(self.view_rulegen_editor, 65)

        layout2.addWidget(self.view_rulegen_header_label)
        layout2.addWidget(self.view_rulegen_limit_features_by_ea)
        layout2.addWidget(self.view_rulegen_search)
        layout2.addWidget(self.view_rulegen_features)

        splitter2 = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        splitter2.addWidget(right_top)
        splitter2.addWidget(right_bottom)

        splitter1 = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        splitter1.addWidget(left)
        splitter1.addWidget(splitter2)

        layout.addWidget(splitter1)

        tab = QtWidgets.QWidget()
        tab.setLayout(layout)

        self.view_tabs.addTab(tab, "Rule Generator")

    def load_ida_hooks(self):
        """load IDA UI hooks"""
        # map named action (defined in idagui.cfg) to Python function
        action_hooks = {
            "MakeName": self.ida_hook_rename,
            "EditFunction": self.ida_hook_rename,
            "RebaseProgram": self.ida_hook_rebase,
        }

        self.ida_hooks = CapaExplorerIdaHooks(self.ida_hook_screen_ea_changed, action_hooks)
        self.ida_hooks.hook()

    def unload_ida_hooks(self):
        """unload IDA Pro UI hooks

        must be called before plugin is completely destroyed
        """
        if self.ida_hooks:
            self.ida_hooks.unhook()

    def ida_hook_rename(self, meta, post=False):
        """function hook for IDA "MakeName" and "EditFunction" actions

        called twice, once before action and once after action completes

        @param meta: dict of key/value pairs set when action first called (may be empty)
        @param post: False if action first call, True if action second call
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

    def update_view_tree_limit_results_to_function(self, ea):
        """ """
        self.limit_results_to_function(idaapi.get_func(ea))
        self.view_tree.reset_ui()

    def update_rulegen_tree_limit_features_to_selection(self, ea):
        """ """
        self.view_rulegen_features.filter_items_by_ea(ea)

    def ida_hook_screen_ea_changed(self, widget, new_ea, old_ea):
        """function hook for IDA "screen ea changed" action

        called twice, once before action and once after action completes. this hook is currently only relevant
        for limiting results displayed in the UI

        @param widget: IDA widget type
        @param new_ea: destination ea
        @param old_ea: source ea
        """
        if self.view_tabs.currentIndex() not in (0, 1):
            return

        if idaapi.get_widget_type(widget) != idaapi.BWN_DISASM:
            # ignore views not the assembly view
            return

        if not idaapi.get_func(new_ea):
            return

        if self.view_tabs.currentIndex() == 1 and self.view_rulegen_limit_features_by_ea.isChecked():
            return self.update_rulegen_tree_limit_features_to_selection(new_ea)

        if idaapi.get_func(new_ea) == idaapi.get_func(old_ea):
            # user navigated same function - ignore
            return

        if self.view_tabs.currentIndex() == 0 and self.view_limit_results_by_function.isChecked():
            return self.update_view_tree_limit_results_to_function(new_ea)

    def ida_hook_rebase(self, meta, post=False):
        """function hook for IDA "RebaseProgram" action

        called twice, once before action and once after action completes

        @param meta: dict of key/value pairs set when action first called (may be empty)
        @param post: False if action first call, True if action second call
        """
        if post:
            if idaapi.get_imagebase() != meta.get("prev_base", -1):
                capa.ida.helpers.inform_user_ida_ui("Running capa analysis using new program base")
                self.slot_analyze()
        else:
            meta["prev_base"] = idaapi.get_imagebase()
            self.model_data.reset()

    def ensure_capa_settings_rule_path(self):
        try:
            path: str = settings.user.get(CAPA_SETTINGS_RULE_PATH, "")

            # resolve rules directory - check self and settings first, then ask user
            # pathlib.Path considers "" equivalent to "." so we first check if rule path is an empty string
            if not path or not Path(path).exists():
                # configure rules selection messagebox
                rules_message = QtWidgets.QMessageBox()
                rules_message.setIcon(QtWidgets.QMessageBox.Information)
                rules_message.setWindowTitle("capa explorer")
                rules_message.setText("You must specify a directory containing capa rules before running analysis.")
                rules_message.setInformativeText(
                    "Click 'Ok' to specify a local directory of rules or you can download and extract the official "
                    + "rules from the URL listed in the details."
                )
                rules_message.setDetailedText(f"{CAPA_OFFICIAL_RULESET_URL}")
                rules_message.setStandardButtons(QtWidgets.QMessageBox.Ok | QtWidgets.QMessageBox.Cancel)

                # display rules selection messagebox, check user button selection
                pressed = rules_message.exec_()
                if pressed == QtWidgets.QMessageBox.Cancel:
                    raise UserCancelledError()

                path = self.ask_user_directory()
                if not path:
                    raise UserCancelledError()

                if not Path(path).exists():
                    logger.error("rule path %s does not exist or cannot be accessed", path)
                    return False

                settings.user[CAPA_SETTINGS_RULE_PATH] = path
        except UserCancelledError:
            capa.ida.helpers.inform_user_ida_ui("Analysis requires capa rules")
            logger.warning(
                "You must specify a directory containing capa rules before running analysis.%s",
                f"Download and extract the official rules from {CAPA_OFFICIAL_RULESET_URL} (recommended).",
            )
            return False
        except Exception as e:
            capa.ida.helpers.inform_user_ida_ui("Failed to load capa rules")
            logger.exception("Failed to load capa rules (error: %s).", e)
            return False

        if ida_kernwin.user_cancelled():
            logger.info("User cancelled analysis.")
            return False

        return True

    def load_capa_rules(self):
        """load capa rules from directory specified by user, either using IDA UI or settings"""
        if not self.ensure_capa_settings_rule_path():
            return False

        rule_path: Path = Path(settings.user.get(CAPA_SETTINGS_RULE_PATH, ""))
        try:

            def on_load_rule(_, i, total):
                update_wait_box(f"loading capa rules from {rule_path} ({i+1} of {total})")
                if ida_kernwin.user_cancelled():
                    raise UserCancelledError("user cancelled")

            return capa.rules.get_rules([rule_path], on_load_rule=on_load_rule)
        except UserCancelledError:
            logger.info("User cancelled analysis.")
            return None
        except Exception as e:
            capa.ida.helpers.inform_user_ida_ui(
                f"Failed to load capa rules from {settings.user[CAPA_SETTINGS_RULE_PATH]}"
            )

            logger.error("Failed to load capa rules from %s (error: %s).", settings.user[CAPA_SETTINGS_RULE_PATH], e)
            logger.error(
                "Make sure your file directory contains properly "  # noqa: G003 [logging statement uses +]
                + "formatted capa rules. You can download and extract the official rules from %s. "
                + "Or, for more details, see the rules documentation here: %s",
                CAPA_OFFICIAL_RULESET_URL,
                CAPA_RULESET_DOC_URL,
            )

            settings.user[CAPA_SETTINGS_RULE_PATH] = ""
            return None

    def load_capa_results(self, new_analysis, from_cache):
        """run capa analysis and render results in UI

        note: this function must always return, exception or not, in order for plugin to safely close the IDA
        wait box
        """
        new_view_status: str = self.view_status_label.text()
        self.set_view_status_label("Loading...")

        if new_analysis:
            if from_cache:
                # load cached results from disk
                try:
                    update_wait_box("loading rules")

                    self.program_analysis_ruleset_cache = self.load_capa_rules()
                    if self.program_analysis_ruleset_cache is None:
                        return False

                    if ida_kernwin.user_cancelled():
                        logger.info("User cancelled analysis.")
                        return False

                    update_wait_box("loading cached results")

                    self.resdoc_cache = capa.ida.helpers.load_and_verify_cached_results()
                    if self.resdoc_cache is None:
                        logger.error("Cached results are not valid. Please reanalyze your program.")
                        return False

                    if ida_kernwin.user_cancelled():
                        logger.info("User cancelled analysis.")
                        return False

                    update_wait_box("verifying cached results")

                    count_source_rules = self.program_analysis_ruleset_cache.source_rule_count
                    user_settings = settings.user[CAPA_SETTINGS_RULE_PATH]
                    view_status_rules: str = f"{user_settings} ({count_source_rules} rules)"

                    # warn user about potentially outdated rules, depending on the use-case this may be expected
                    if (
                        compute_ruleset_cache_identifier(self.program_analysis_ruleset_cache)
                        != capa.ida.helpers.load_rules_cache_id()
                    ):
                        # expand items and resize columns, otherwise view looks incomplete until user closes the popup
                        self.view_tree.reset_ui()

                        capa.ida.helpers.inform_user_ida_ui("Cached results were generated using different capas rules")
                        logger.warning(
                            "capa is showing you cached results from a previous analysis run.%s ",
                            "Your rules have changed since and you should reanalyze the program to see new results.",
                        )
                        view_status_rules = "no rules matched for cache"

                    cached_results_time = self.resdoc_cache.meta.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    new_view_status = f"capa rules: {view_status_rules}, cached results (created {cached_results_time})"
                except Exception as e:
                    logger.exception("Failed to load cached capa results (error: %s).", e)
                    return False
            else:
                # load results from fresh anlaysis
                self.resdoc_cache = None
                self.process_total = 0
                self.process_count = 1

                def slot_progress_feature_extraction(text):
                    """slot function to handle feature extraction progress updates"""
                    update_wait_box(f"{text} ({self.process_count} of {self.process_total})")
                    self.process_count += 1

                try:
                    self.feature_extractor = CapaExplorerFeatureExtractor()
                    self.feature_extractor.indicator.progress.connect(slot_progress_feature_extraction)
                except Exception as e:
                    logger.exception("Failed to initialize feature extractor (error: %s)", e)
                    return False

                if ida_kernwin.user_cancelled():
                    logger.info("User cancelled analysis.")
                    return False

                update_wait_box("calculating analysis")

                try:
                    self.process_total += len(tuple(self.feature_extractor.get_functions()))
                except Exception as e:
                    logger.exception("Failed to calculate analysis (error: %s).", e)
                    return False

                if ida_kernwin.user_cancelled():
                    logger.info("User cancelled analysis.")
                    return False

                update_wait_box("loading rules")

                self.program_analysis_ruleset_cache = self.load_capa_rules()
                if self.program_analysis_ruleset_cache is None:
                    return False

                # matching operations may update rule instances,
                # so we'll work with a local copy of the ruleset.
                ruleset = copy.deepcopy(self.program_analysis_ruleset_cache)

                if ida_kernwin.user_cancelled():
                    logger.info("User cancelled analysis.")
                    return False

                update_wait_box("extracting features")

                try:
                    meta = capa.ida.helpers.collect_metadata([Path(settings.user[CAPA_SETTINGS_RULE_PATH])])
                    capabilities, counts = capa.capabilities.common.find_capabilities(
                        ruleset, self.feature_extractor, disable_progress=True
                    )

                    meta.analysis.feature_counts = counts["feature_counts"]
                    meta.analysis.library_functions = counts["library_functions"]
                    meta.analysis.layout = capa.loader.compute_layout(ruleset, self.feature_extractor, capabilities)
                except UserCancelledError:
                    logger.info("User cancelled analysis.")
                    return False
                except Exception as e:
                    logger.exception("Failed to extract capabilities from database (error: %s)", e)
                    return False

                if ida_kernwin.user_cancelled():
                    logger.info("User cancelled analysis.")
                    return False

                update_wait_box("checking for file limitations")

                try:
                    # support binary files specifically for x86/AMD64 shellcode
                    # warn user binary file is loaded but still allow capa to process it
                    # TODO(mike-hunhoff): check specific architecture of binary files based on how user configured IDA processors
                    # https://github.com/mandiant/capa/issues/1603
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
                        logger.warning(
                            " If you don't know the input file type, you can try using the `file` utility to guess it."
                        )
                        logger.warning("-" * 80)

                        capa.ida.helpers.inform_user_ida_ui("capa encountered file type warnings during analysis")

                    if capa.capabilities.common.has_file_limitation(ruleset, capabilities, is_standalone=False):
                        capa.ida.helpers.inform_user_ida_ui("capa encountered file limitation warnings during analysis")
                except Exception as e:
                    logger.exception("Failed to check for file limitations (error: %s)", e)
                    return False

                if ida_kernwin.user_cancelled():
                    logger.info("User cancelled analysis.")
                    return False

                update_wait_box("collecting results")

                try:
                    self.resdoc_cache = capa.render.result_document.ResultDocument.from_capa(
                        meta, ruleset, capabilities
                    )
                except Exception as e:
                    logger.exception("Failed to collect results (error: %s)", e)
                    return False

                if ida_kernwin.user_cancelled():
                    logger.info("User cancelled analysis.")
                    return False

                update_wait_box("saving results to database")

                # cache results across IDA sessions
                try:
                    capa.ida.helpers.save_cached_results(self.resdoc_cache)
                    ruleset_id = compute_ruleset_cache_identifier(ruleset)
                    capa.ida.helpers.save_rules_cache_id(ruleset_id)
                    logger.info("Saved cached results to database")
                except Exception as e:
                    logger.exception("Failed to save results to database (error: %s)", e)
                    return False
                user_settings = settings.user[CAPA_SETTINGS_RULE_PATH]
                count_source_rules = self.program_analysis_ruleset_cache.source_rule_count
                new_view_status = f"capa rules: {user_settings} ({count_source_rules} rules)"
        # regardless of new analysis, render results - e.g. we may only want to render results after checking
        # show results by function

        if ida_kernwin.user_cancelled():
            logger.info("User cancelled analysis.")
            return False

        update_wait_box("rendering results")

        try:
            # either the results are cached and the doc already exists, or the doc was just created above
            assert self.resdoc_cache is not None
            assert self.program_analysis_ruleset_cache is not None

            self.model_data.render_capa_doc(self.resdoc_cache, self.view_show_results_by_function.isChecked())
        except Exception as e:
            logger.exception("Failed to render results (error: %s)", e)
            return False

        self.set_view_status_label(new_view_status)

        return True

    def reset_view_tree(self):
        """reset tree view UI controls

        called when user selects plugin reset from menu
        """
        self.view_limit_results_by_function.setChecked(False)
        # self.view_show_results_by_function.setChecked(False)
        self.view_search_bar.setText("")
        self.view_tree.reset_ui()

    def analyze_program(self, new_analysis=True, from_cache=False, analyze=Options.ANALYZE_ASK):
        """ """
        # determine cache handling before model/view is reset in case user cancels
        if new_analysis:
            try:
                ida_kernwin.show_wait_box("capa explorer")
                from_cache = self.get_ask_use_persistent_cache(analyze)
            except UserCancelledError:
                return
            finally:
                ida_kernwin.hide_wait_box()

        self.range_model_proxy.invalidate()
        self.search_model_proxy.invalidate()
        self.model_data.reset()
        self.model_data.clear()

        ida_kernwin.show_wait_box("capa explorer")
        success = self.load_capa_results(new_analysis, from_cache)
        ida_kernwin.hide_wait_box()

        self.reset_view_tree()

        if not success:
            self.set_view_status_label("Click Analyze to get started...")
            capa.ida.helpers.inform_user_ida_ui("Failed to load capabilities")

    def get_ask_use_persistent_cache(self, analyze):
        if analyze and analyze != Options.NO_ANALYSIS:
            update_wait_box("checking for cached results")

            try:
                has_cache: bool = capa.ida.helpers.idb_contains_cached_results()
            except Exception as e:
                capa.ida.helpers.inform_user_ida_ui("Failed to check for cached results, reanalyzing program")
                logger.exception("Failed to check for cached results (error: %s)", e)
                return False

            if ida_kernwin.user_cancelled():
                logger.info("User cancelled analysis.")
                raise UserCancelledError

            if has_cache:
                if analyze == Options.ANALYZE_AUTO:
                    return True

                elif analyze == Options.ANALYZE_ASK:
                    update_wait_box("verifying cached results")

                    try:
                        results: Optional[capa.render.result_document.ResultDocument] = (
                            capa.ida.helpers.load_and_verify_cached_results()
                        )
                    except Exception as e:
                        capa.ida.helpers.inform_user_ida_ui("Failed to verify cached results, reanalyzing program")
                        logger.exception("Failed to verify cached results (error: %s)", e)
                        return False

                    if results is None:
                        capa.ida.helpers.inform_user_ida_ui("Cached results are not valid, reanalyzing program")
                        logger.error("Cached results are not valid.")
                        return False

                    btn_id = ida_kernwin.ask_buttons(
                        "Load existing results",
                        "Reanalyze program",
                        "",
                        ida_kernwin.ASKBTN_YES,
                        "This database contains capa results generated on "
                        + results.meta.timestamp.strftime("%Y-%m-%d at %H:%M:%S")
                        + ".\nLoad existing data or analyze program again?",
                    )

                    if btn_id == ida_kernwin.ASKBTN_CANCEL:
                        raise UserCancelledError

                    return btn_id == ida_kernwin.ASKBTN_YES
                else:
                    logger.error("unknown analysis option %d", analyze)

        return False

    def load_capa_function_results(self):
        """ """
        if self.rulegen_ruleset_cache is None:
            # only reload rules if cache is empty
            self.rulegen_ruleset_cache = self.load_capa_rules()
        else:
            logger.info("Using cached capa rules, click Clear to load rules from disk.")

        if self.rulegen_ruleset_cache is None:
            return False

        # matching operations may update rule instances,
        # so we'll work with a local copy of the ruleset.
        ruleset = copy.deepcopy(self.rulegen_ruleset_cache)

        # clear cached function
        if self.rulegen_current_function is not None:
            self.rulegen_current_function = None

        # these are init once objects, create on tab change
        if self.rulegen_feature_cache is None or self.rulegen_feature_extractor is None:
            try:
                update_wait_box("performing one-time file analysis")
                self.rulegen_feature_extractor = CapaExplorerFeatureExtractor()
                self.rulegen_feature_cache = CapaRuleGenFeatureCache(self.rulegen_feature_extractor)
            except Exception as e:
                logger.exception("Failed to initialize feature extractor (error: %s)", e)
                return False
        else:
            logger.info("Reusing prior rulegen cache")

        if ida_kernwin.user_cancelled():
            logger.info("User cancelled analysis.")
            return False

        update_wait_box("extracting features")

        # resolve function selected in disassembly view
        try:
            f = idaapi.get_func(idaapi.get_screen_ea())
            if f is not None:
                self.rulegen_current_function = self.rulegen_feature_extractor.get_function(f.start_ea)
        except Exception as e:
            logger.exception("Failed to resolve function at address 0x%X (error: %s)", f.start_ea, e)
            return False

        if ida_kernwin.user_cancelled():
            logger.info("User cancelled analysis.")
            return False

        update_wait_box("generating function rule matches")

        all_function_features: FeatureSet = collections.defaultdict(set)
        try:
            if self.rulegen_current_function is not None:
                _, func_matches, bb_matches, insn_matches = self.rulegen_feature_cache.find_code_capabilities(
                    ruleset, self.rulegen_current_function
                )
                all_function_features.update(
                    self.rulegen_feature_cache.get_all_function_features(self.rulegen_current_function)
                )

                for name, result in itertools.chain(func_matches.items(), bb_matches.items(), insn_matches.items()):
                    rule = ruleset[name]
                    if rule.is_subscope_rule():
                        continue
                    for addr, _ in result:
                        all_function_features[capa.features.common.MatchedRule(name)].add(addr)
        except Exception as e:
            logger.exception("Failed to generate rule matches (error: %s)", e)
            return False

        if ida_kernwin.user_cancelled():
            logger.info("User cancelled analysis.")
            return False

        update_wait_box("generating file rule matches")

        all_file_features: FeatureSet = collections.defaultdict(set)
        try:
            _, file_matches = self.rulegen_feature_cache.find_file_capabilities(ruleset)
            all_file_features.update(self.rulegen_feature_cache.get_all_file_features())

            for name, result in file_matches.items():
                rule = ruleset[name]
                if rule.is_subscope_rule():
                    continue
                for addr, _ in result:
                    all_file_features[capa.features.common.MatchedRule(name)].add(addr)
        except Exception as e:
            logger.exception("Failed to generate file rule matches (error: %s)", e)
            return False

        if ida_kernwin.user_cancelled():
            logger.info("User cancelled analysis.")
            return False

        update_wait_box("rendering views")

        try:
            # load preview and feature tree
            self.view_rulegen_preview.load_preview_meta(
                self.rulegen_current_function.address if self.rulegen_current_function else None,
                settings.user.get(CAPA_SETTINGS_RULEGEN_AUTHOR, "<insert_author>"),
                settings.user.get(CAPA_SETTINGS_RULEGEN_SCOPE, "function"),
            )

            self.view_rulegen_features.load_features(all_file_features, all_function_features)

            self.set_view_status_label(f"capa rules: {settings.user[CAPA_SETTINGS_RULE_PATH]}")
        except Exception as e:
            logger.exception("Failed to render views (error: %s)", e)
            return False

        return True

    def analyze_function(self):
        """ """
        self.reset_function_analysis_views(is_analyze=True)
        self.set_view_status_label("Loading...")

        ida_kernwin.show_wait_box("capa explorer")
        success = self.load_capa_function_results()
        ida_kernwin.hide_wait_box()

        if not success:
            self.set_view_status_label("Click Analyze to get started...")
            capa.ida.helpers.inform_user_ida_ui("Failed to load features")

    def reset_program_analysis_views(self):
        """ """
        logger.info("Resetting program analysis views.")

        self.model_data.reset()
        self.reset_view_tree()

        logger.info("Reset completed.")

    def reset_function_analysis_views(self, is_analyze=False):
        """ """
        logger.info("Resetting rule generator views.")

        # self.view_rulegen_header_label.setText("Features")
        self.view_rulegen_features.reset_view()
        self.view_rulegen_editor.reset_view()
        self.view_rulegen_preview.reset_view()
        self.view_rulegen_search.clear()
        self.view_rulegen_limit_features_by_ea.setChecked(False)
        self.set_rulegen_preview_border_neutral()
        self.rulegen_current_function = None
        self.view_rulegen_status_label.clear()

        if not is_analyze:
            # clear rules and ruleset cache only if user clicked "Reset"
            self.rulegen_ruleset_cache = None
            self.set_view_status_label("Click Analyze to get started...")

        logger.info("Reset completed.")

    def set_rulegen_status(self, e):
        """ """
        self.view_rulegen_status_label.setText(e)

    def set_rulegen_preview_border_error(self):
        """ """
        self.view_rulegen_preview.setStyleSheet("border: 3px solid red")

    def set_rulegen_preview_border_neutral(self):
        """ """
        self.view_rulegen_preview.setStyleSheet("border: 3px solid grey")

    def set_rulegen_preview_border_warn(self):
        """ """
        self.view_rulegen_preview.setStyleSheet("border: 3px solid yellow")

    def set_rulegen_preview_border_success(self):
        """ """
        self.view_rulegen_preview.setStyleSheet("border: 3px solid green")

    def update_rule_status(self, rule_text: str):
        """ """
        rule: capa.rules.Rule
        rules: List[Rule]
        ruleset: capa.rules.RuleSet

        if self.view_rulegen_editor.invisibleRootItem().childCount() == 0:
            # assume nothing to do if no items found in editor pane
            self.set_rulegen_preview_border_neutral()
            self.view_rulegen_status_label.clear()
            return

        try:
            # we don't expect either cache to be empty at this point
            assert self.rulegen_ruleset_cache is not None
            assert self.rulegen_feature_cache is not None
        except Exception as e:
            logger.exception("Failed to access cache (error: %s)", e)
            self.set_rulegen_status("Error: see console output for more details")
            return

        self.set_rulegen_preview_border_error()

        try:
            rule = capa.rules.Rule.from_yaml(rule_text)
            # import here to avoid circular dependency
            from capa.render.result_document import RuleMetadata

            # validate meta data fields
            _ = RuleMetadata.from_capa(rule)
        except Exception as e:
            self.set_rulegen_status(f"Failed to compile rule ({e})")
            return

        # we must create a deep copy of rules because any rule matching operations modify the original rule
        # the ruleset may derive subscope rules from the source rules loaded from disk.
        # by ignoring them, we reconstruct the collection of rules provided by the user.
        rules = copy.deepcopy([r for r in self.rulegen_ruleset_cache.rules.values() if not r.is_subscope_rule()])
        rules.append(rule)

        try:
            # create a new ruleset using our rule and its dependencies
            ruleset = capa.rules.RuleSet(list(capa.rules.get_rules_and_dependencies(rules, rule.name)))
        except Exception as e:
            self.set_rulegen_status(f"Failed to create ruleset ({e})")
            return

        is_match: bool = False
        if self.rulegen_current_function is not None and any(
            s in rule.scopes
            for s in (
                capa.rules.Scope.FUNCTION,
                capa.rules.Scope.BASIC_BLOCK,
                capa.rules.Scope.INSTRUCTION,
            )
        ):
            try:
                _, func_matches, bb_matches, insn_matches = self.rulegen_feature_cache.find_code_capabilities(
                    ruleset, self.rulegen_current_function
                )
            except Exception as e:
                self.set_rulegen_status(f"Failed to create function rule matches from rule set ({e})")
                return

            if capa.rules.Scope.FUNCTION in rule.scopes and rule.name in func_matches:
                is_match = True
            elif capa.rules.Scope.BASIC_BLOCK in rule.scopes and rule.name in bb_matches:
                is_match = True
            elif capa.rules.Scope.INSTRUCTION in rule.scopes and rule.name in insn_matches:
                is_match = True
        elif capa.rules.Scope.FILE in rule.scopes:
            try:
                _, file_matches = self.rulegen_feature_cache.find_file_capabilities(ruleset)
            except Exception as e:
                self.set_rulegen_status(f"Failed to create file rule matches from rule set ({e})")
                return
            if rule.name in file_matches:
                is_match = True
        else:
            is_match = False

        if is_match:
            # made it here, rule compiled and match was found
            self.set_rulegen_preview_border_success()
            self.set_rulegen_status("Rule compiled and matched")
        else:
            # made it here, rule compiled but no match found, may be intended so we warn user
            self.set_rulegen_preview_border_warn()
            self.set_rulegen_status("Rule compiled, but not matched")

    def slot_tabview_change(self, index):
        if index not in (0, 1):
            return

        status_prev: str = self.view_status_label.text()
        if index == 0:
            self.set_view_status_label(self.view_status_label_analysis_cache)
            self.view_status_label_rulegen_cache = status_prev

            self.view_reset_button.setText("Reset Selections")
        elif index == 1:
            self.set_view_status_label(self.view_status_label_rulegen_cache)
            self.view_status_label_analysis_cache = status_prev
            self.view_reset_button.setText("Clear")

    def slot_rulegen_editor_update(self):
        """ """
        rule_text = self.view_rulegen_preview.toPlainText()
        self.update_rule_status(rule_text)

    def slot_rulegen_preview_update(self):
        """ """
        rule_text = self.view_rulegen_preview.toPlainText()
        self.view_rulegen_editor.load_features_from_yaml(rule_text, False)
        self.update_rule_status(rule_text)

    def slot_limit_rulegen_features_to_search(self, text):
        """ """
        self.view_rulegen_features.filter_items_by_text(text)

    def slot_analyze(self):
        """run capa analysis and reload UI controls

        called when user selects plugin reload from menu
        """
        if self.view_tabs.currentIndex() == 0:
            self.analyze_program()
        elif self.view_tabs.currentIndex() == 1:
            self.analyze_function()

    def slot_reset(self):
        """reset UI elements

        e.g. checkboxes and IDA highlighting
        """
        if self.view_tabs.currentIndex() == 0:
            self.reset_program_analysis_views()
        elif self.view_tabs.currentIndex() == 1:
            self.reset_function_analysis_views()

    def slot_save(self):
        """ """
        if self.view_tabs.currentIndex() == 0:
            self.save_program_analysis()
        elif self.view_tabs.currentIndex() == 1:
            self.save_function_analysis()

    def slot_settings(self):
        """ """
        dialog = CapaSettingsInputDialog("capa explorer settings", parent=self.parent)
        if dialog.exec_():
            (
                settings.user[CAPA_SETTINGS_RULE_PATH],
                settings.user[CAPA_SETTINGS_RULEGEN_AUTHOR],
                settings.user[CAPA_SETTINGS_RULEGEN_SCOPE],
                settings.user[CAPA_SETTINGS_ANALYZE],
            ) = dialog.get_values()

    def save_program_analysis(self):
        """ """
        if not self.resdoc_cache:
            idaapi.info("No program analysis to save.")
            return

        s = self.resdoc_cache.model_dump_json().encode("utf-8")

        path = Path(self.ask_user_capa_json_file())
        if not path.exists():
            return

        write_file(path, s)

    def save_function_analysis(self):
        """ """
        s = self.view_rulegen_preview.toPlainText().encode("utf-8")
        if not s:
            idaapi.info("No rule to save.")
            return

        rule_file_path = self.ask_user_capa_rule_file()
        if not rule_file_path:
            # dialog canceled
            return

        path = Path(rule_file_path)
        if not path.parent.exists():
            logger.warning("Failed to save file: parent directory '%s' does not exist.", path.parent)
            return

        logger.info("Saving rule to %s.", path)
        write_file(path, s)

    def slot_checkbox_limit_by_changed(self, state):
        """slot activated if checkbox clicked

        if checked, configure function filter if screen location is located in function, otherwise clear filter

        @param state: checked state
        """
        if state == QtCore.Qt.Checked:
            self.limit_results_to_function(idaapi.get_func(idaapi.get_screen_ea()))
        else:
            self.range_model_proxy.reset_address_range_filter()

        self.view_tree.reset_ui()

    def slot_checkbox_limit_features_by_ea(self, state):
        """ """
        if state == QtCore.Qt.Checked:
            self.view_rulegen_features.filter_items_by_ea(idaapi.get_screen_ea())
        else:
            self.view_rulegen_features.show_all_items()

    def slot_checkbox_show_results_by_function_changed(self, state):
        """slot activated if checkbox clicked

        if checked, configure function filter if screen location is located in function, otherwise clear filter

        @param state: checked state
        """
        if self.resdoc_cache is not None:
            self.analyze_program(new_analysis=False)

    def limit_results_to_function(self, f):
        """add filter to limit results to current function

        adds new address range filter to include function bounds, allowing basic blocks matched within a function
        to be included in the results

        @param f: (IDA func_t)
        """
        if f:
            self.range_model_proxy.add_address_range_filter(f.start_ea, f.end_ea)
        else:
            # if function not exists don't display any results (assume address never -1)
            self.range_model_proxy.add_address_range_filter(-1, -1)

    def slot_limit_results_to_search(self, text):
        """limit tree view results to search matches

        reset view after filter to maintain level 1 expansion
        """
        self.search_model_proxy.set_query(text)
        self.view_tree.reset_ui(should_sort=False)

    def ask_user_directory(self):
        """create Qt dialog to ask user for a directory"""
        return str(
            QtWidgets.QFileDialog.getExistingDirectory(
                self.parent, "Please select a capa rules directory", settings.user.get(CAPA_SETTINGS_RULE_PATH, "")
            )
        )

    def ask_user_capa_rule_file(self):
        """ """
        return QtWidgets.QFileDialog.getSaveFileName(
            None,
            "Please select a location to save capa rule file",
            settings.user.get(CAPA_SETTINGS_RULE_PATH, ""),
            "*.yml",
        )[0]

    def ask_user_capa_json_file(self):
        """ """
        return QtWidgets.QFileDialog.getSaveFileName(
            None, "Please select a location to save capa JSON file", "", "*.json"
        )[0]

    def set_view_status_label(self, text):
        """update status label control

        @param text: updated text
        """
        self.view_status_label.setText(text)
