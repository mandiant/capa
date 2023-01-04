# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os
import copy
import logging
import itertools
import collections
from typing import Any, Set, Dict, List, Optional

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
import capa.render.result_document
import capa.features.extractors.ida.extractor
from capa.engine import FeatureSet
from capa.features.common import Feature
from capa.ida.plugin.icon import QICON
from capa.ida.plugin.view import (
    CapaExplorerQtreeView,
    CapaExplorerRulegenEditor,
    CapaExplorerRulegenPreview,
    CapaExplorerRulegenFeatures,
)
from capa.features.address import NO_ADDRESS, Address
from capa.ida.plugin.hooks import CapaExplorerIdaHooks
from capa.ida.plugin.model import CapaExplorerDataModel
from capa.ida.plugin.proxy import CapaExplorerRangeProxyModel, CapaExplorerSearchProxyModel
from capa.features.extractors.base_extractor import FunctionHandle

logger = logging.getLogger(__name__)
settings = ida_settings.IDASettings("capa")

CAPA_SETTINGS_RULE_PATH = "rule_path"
CAPA_SETTINGS_RULEGEN_AUTHOR = "rulegen_author"
CAPA_SETTINGS_RULEGEN_SCOPE = "rulegen_scope"

from enum import IntFlag


class Options(IntFlag):
    DEFAULT = 0
    ANALYZE = 1  # Runs the analysis when starting the explorer


def write_file(path, data):
    """ """
    with open(path, "wb") as save_file:
        save_file.write(data)


def trim_function_name(f, max_length=25):
    """ """
    n = idaapi.get_name(f.start_ea)
    if len(n) > max_length:
        n = "%s..." % n[:max_length]
    return n


def find_func_features(fh: FunctionHandle, extractor):
    """ """
    func_features: Dict[Feature, Set[Address]] = collections.defaultdict(set)
    bb_features: Dict[Address, Dict[Feature, Set[Address]]] = collections.defaultdict(dict)

    for (feature, addr) in extractor.extract_function_features(fh):
        func_features[feature].add(addr)

    for bbh in extractor.get_basic_blocks(fh):
        _bb_features: Dict[Feature, Set[Address]] = collections.defaultdict(set)

        for (feature, addr) in extractor.extract_basic_block_features(fh, bbh):
            _bb_features[feature].add(addr)
            func_features[feature].add(addr)

        for insn in extractor.get_instructions(fh, bbh):
            for (feature, addr) in extractor.extract_insn_features(fh, bbh, insn):
                _bb_features[feature].add(addr)
                func_features[feature].add(addr)

        bb_features[bbh.address] = _bb_features

    return func_features, bb_features


def find_func_matches(f: FunctionHandle, ruleset, func_features, bb_features):
    """ """
    func_matches = collections.defaultdict(list)
    bb_matches = collections.defaultdict(list)

    # create copy of function features, to add rule matches for basic blocks
    func_features = collections.defaultdict(set, copy.copy(func_features))

    # find rule matches for basic blocks
    for (bb, features) in bb_features.items():
        _, matches = capa.engine.match(ruleset.basic_block_rules, features, bb)
        for (name, res) in matches.items():
            bb_matches[name].extend(res)
            for (ea, _) in res:
                func_features[capa.features.common.MatchedRule(name)].add(ea)

    # find rule matches for function, function features include rule matches for basic blocks
    _, matches = capa.engine.match(ruleset.function_rules, func_features, f.address)
    for (name, res) in matches.items():
        func_matches[name].extend(res)

    return func_matches, bb_matches


def find_file_features(extractor):
    """ """
    file_features = collections.defaultdict(set)  # type: FeatureSet
    for (feature, addr) in extractor.extract_file_features():
        if addr:
            file_features[feature].add(addr)
        else:
            if feature not in file_features:
                file_features[feature] = set()
    return file_features


def find_file_matches(ruleset, file_features: FeatureSet):
    """ """
    _, matches = capa.engine.match(ruleset.file_rules, file_features, NO_ADDRESS)
    return matches


def update_wait_box(text):
    """update the IDA wait box"""
    ida_kernwin.replace_wait_box("capa explorer...%s" % text)


class UserCancelledError(Exception):
    """throw exception when user cancels action"""

    pass


class CapaExplorerProgressIndicator(QtCore.QObject):
    """implement progress signal, used during feature extraction"""

    progress = QtCore.pyqtSignal(str)

    def __init__(self):
        """initialize signal object"""
        super().__init__()

    def update(self, text):
        """emit progress update

        check if user cancelled action, raise exception for parent function to catch
        """
        if ida_kernwin.user_cancelled():
            raise UserCancelledError("user cancelled")
        self.progress.emit("extracting features from %s" % text)


class CapaExplorerFeatureExtractor(capa.features.extractors.ida.extractor.IdaFeatureExtractor):
    """subclass the IdaFeatureExtractor

    track progress during feature extraction, also allow user to cancel feature extraction
    """

    def __init__(self):
        super().__init__()
        self.indicator = CapaExplorerProgressIndicator()

    def extract_function_features(self, fh: FunctionHandle):
        self.indicator.update("function at 0x%X" % fh.inner.start_ea)
        return super().extract_function_features(fh)


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

        scopes = ("file", "function", "basic block")

        self.edit_rule_scope.addItems(scopes)
        self.edit_rule_scope.setCurrentIndex(scopes.index(settings.user.get(CAPA_SETTINGS_RULEGEN_SCOPE, "function")))

        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel, self)

        layout = QtWidgets.QFormLayout(self)
        layout.addRow("capa rules path", self.edit_rule_path)
        layout.addRow("Default rule author", self.edit_rule_author)
        layout.addRow("Default rule scope", self.edit_rule_scope)

        layout.addWidget(buttons)

        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

    def get_values(self):
        """ """
        return self.edit_rule_path.text(), self.edit_rule_author.text(), self.edit_rule_scope.currentText()


class CapaExplorerForm(idaapi.PluginForm):
    """form element for plugin interface"""

    def __init__(self, name: str, option=Options.DEFAULT):
        """initialize form elements"""
        super().__init__()

        self.form_title: str = name
        self.process_total: int = 0
        self.process_count: int = 0

        self.parent: Any  # QtWidget
        self.ida_hooks: CapaExplorerIdaHooks
        self.doc: Optional[capa.render.result_document.ResultDocument] = None

        self.rule_paths: Optional[List[str]]
        self.rules_cache: Optional[List[capa.rules.Rule]]
        self.ruleset_cache: Optional[capa.rules.RuleSet]

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
        self.view_buttons: QtWidgets.QHBoxLayout
        self.view_analyze_button: QtWidgets.QPushButton
        self.view_reset_button: QtWidgets.QPushButton
        self.view_settings_button: QtWidgets.QPushButton
        self.view_save_button: QtWidgets.QPushButton

        self.view_rulegen_preview: CapaExplorerRulegenPreview
        self.view_rulegen_features: CapaExplorerRulegenFeatures
        self.view_rulegen_editor: CapaExplorerRulegenEditor
        self.view_rulegen_header_label: QtWidgets.QLabel
        self.view_rulegen_search: QtWidgets.QLineEdit
        self.view_rulegen_limit_features_by_ea: QtWidgets.QCheckBox
        self.rulegen_current_function: Optional[FunctionHandle]
        self.rulegen_bb_features_cache: Dict[Address, Dict[Feature, Set[Address]]] = {}
        self.rulegen_func_features_cache: Dict[Feature, Set[Address]] = {}
        self.rulegen_file_features_cache: Dict[Feature, Set[Address]] = {}
        self.view_rulegen_status_label: QtWidgets.QLabel

        self.Show()

        if (option & Options.ANALYZE) == Options.ANALYZE:
            self.analyze_program()

    def OnCreate(self, form):
        """called when plugin form is created

        load interface and install hooks but do not analyze database
        """
        self.parent = self.FormToPyQtWidget(form)
        self.parent.setWindowIcon(QICON)

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
        label = QtWidgets.QLabel()
        label.setAlignment(QtCore.Qt.AlignLeft)
        label.setText("Click Analyze to get started...")

        self.view_status_label = label

    def load_view_buttons(self):
        """load the button controls"""
        analyze_button = QtWidgets.QPushButton("Analyze")
        reset_button = QtWidgets.QPushButton("Reset")
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
        if not self.view_tabs.currentIndex() in (0, 1):
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
                capa.ida.helpers.inform_user_ida_ui("Running capa analysis again after program rebase")
                self.slot_analyze()
        else:
            meta["prev_base"] = idaapi.get_imagebase()
            self.model_data.reset()

    def load_capa_rules(self):
        """ """
        self.rule_paths = None
        self.ruleset_cache = None
        self.rules_cache = None

        try:
            # resolve rules directory - check self and settings first, then ask user
            if not os.path.exists(settings.user.get(CAPA_SETTINGS_RULE_PATH, "")):
                idaapi.info("Please select a file directory containing capa rules.")
                path = self.ask_user_directory()
                if not path:
                    logger.warning(
                        "You must select a file directory containing capa rules before analysis can be run. The standard collection of capa rules can be downloaded from https://github.com/mandiant/capa-rules."
                    )
                    return False
                settings.user[CAPA_SETTINGS_RULE_PATH] = path
        except Exception as e:
            logger.error("Failed to load capa rules (error: %s).", e)
            return False

        if ida_kernwin.user_cancelled():
            logger.info("User cancelled analysis.")
            return False

        rule_path = settings.user[CAPA_SETTINGS_RULE_PATH]
        try:
            # TODO refactor: this first part is identical to capa.main.get_rules
            if not os.path.exists(rule_path):
                raise IOError("rule path %s does not exist or cannot be accessed" % rule_path)

            rule_paths = []
            if os.path.isfile(rule_path):
                rule_paths.append(rule_path)
            elif os.path.isdir(rule_path):
                for root, dirs, files in os.walk(rule_path):
                    if ".git" in root:
                        # the .github directory contains CI config in capa-rules
                        # this includes some .yml files
                        # these are not rules
                        # additionally, .git has files that are not .yml and generate the warning
                        # skip those too
                        continue
                    for file in files:
                        if not file.endswith(".yml"):
                            if not (file.startswith(".git") or file.endswith((".git", ".md", ".txt"))):
                                # expect to see .git* files, readme.md, format.md, and maybe a .git directory
                                # other things maybe are rules, but are mis-named.
                                logger.warning("skipping non-.yml file: %s", file)
                            continue
                        rule_path = os.path.join(root, file)
                        rule_paths.append(rule_path)

            rules = []
            total_paths = len(rule_paths)
            for (i, rule_path) in enumerate(rule_paths):
                update_wait_box(
                    "loading capa rules from %s (%d of %d)"
                    % (settings.user[CAPA_SETTINGS_RULE_PATH], i + 1, total_paths)
                )
                if ida_kernwin.user_cancelled():
                    raise UserCancelledError("user cancelled")
                try:
                    rule = capa.rules.Rule.from_yaml_file(rule_path)
                except capa.rules.InvalidRule:
                    raise
                else:
                    rule.meta["capa/path"] = rule_path
                    if capa.main.is_nursery_rule_path(rule_path):
                        rule.meta["capa/nursery"] = True
                    rules.append(rule)
            _rules = copy.copy(rules)
            ruleset = capa.rules.RuleSet(_rules)
        except UserCancelledError:
            logger.info("User cancelled analysis.")
            return False
        except Exception as e:
            capa.ida.helpers.inform_user_ida_ui(
                "Failed to load capa rules from %s" % settings.user[CAPA_SETTINGS_RULE_PATH]
            )
            logger.error("Failed to load rules from %s (error: %s).", settings.user[CAPA_SETTINGS_RULE_PATH], e)
            logger.error(
                "Make sure your file directory contains properly formatted capa rules. You can download the standard "
                "collection of capa rules from https://github.com/mandiant/capa-rules/releases."
            )
            logger.error(
                "Please ensure you're using the rules that correspond to your major version of capa (%s)",
                capa.version.get_major_version(),
            )
            logger.error(
                "Or, for more details, see the rule set documentation here: %s",
                "https://github.com/mandiant/capa/blob/master/doc/rules.md",
            )
            settings.user[CAPA_SETTINGS_RULE_PATH] = ""
            return False

        self.rule_paths = rule_paths
        self.ruleset_cache = ruleset
        self.rules_cache = rules

        return True

    def load_capa_results(self, use_cache=False):
        """run capa analysis and render results in UI

        note: this function must always return, exception or not, in order for plugin to safely close the IDA
        wait box
        """
        if not use_cache:
            # new analysis, new doc
            self.doc = None
            self.process_total = 0
            self.process_count = 1

            def slot_progress_feature_extraction(text):
                """slot function to handle feature extraction progress updates"""
                update_wait_box("%s (%d of %d)" % (text, self.process_count, self.process_total))
                self.process_count += 1

            extractor = CapaExplorerFeatureExtractor()
            extractor.indicator.progress.connect(slot_progress_feature_extraction)

            update_wait_box("calculating analysis")

            try:
                self.process_total += len(tuple(extractor.get_functions()))
            except Exception as e:
                logger.error("Failed to calculate analysis (error: %s).", e)
                return False

            if ida_kernwin.user_cancelled():
                logger.info("User cancelled analysis.")
                return False

            update_wait_box("loading rules")

            if not self.load_capa_rules():
                return False

            assert self.rules_cache is not None
            assert self.ruleset_cache is not None

            if ida_kernwin.user_cancelled():
                logger.info("User cancelled analysis.")
                return False

            update_wait_box("extracting features")

            try:
                meta = capa.ida.helpers.collect_metadata(self.rule_paths)
                capabilities, counts = capa.main.find_capabilities(self.ruleset_cache, extractor, disable_progress=True)
                meta["analysis"].update(counts)
                meta["analysis"]["layout"] = capa.main.compute_layout(self.ruleset_cache, extractor, capabilities)
            except UserCancelledError:
                logger.info("User cancelled analysis.")
                return False
            except Exception as e:
                logger.error("Failed to extract capabilities from database (error: %s)", e)
                return False

            update_wait_box("checking for file limitations")

            try:
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
                    logger.warning(
                        " If you don't know the input file type, you can try using the `file` utility to guess it."
                    )
                    logger.warning("-" * 80)

                    capa.ida.helpers.inform_user_ida_ui("capa encountered file type warnings during analysis")

                if capa.main.has_file_limitation(self.ruleset_cache, capabilities, is_standalone=False):
                    capa.ida.helpers.inform_user_ida_ui("capa encountered file limitation warnings during analysis")
            except Exception as e:
                logger.error("Failed to check for file limitations (error: %s)", e)
                return False

            if ida_kernwin.user_cancelled():
                logger.info("User cancelled analysis.")
                return False

            update_wait_box("rendering results")

            try:
                self.doc = capa.render.result_document.ResultDocument.from_capa(meta, self.ruleset_cache, capabilities)
            except Exception as e:
                logger.error("Failed to collect results (error: %s)", e, exc_info=True)
                return False

        try:
            # either the results are cached and the doc already exists,
            # or the doc was just created above
            assert self.doc is not None
            # same with rules cache, either it's cached or it was just loaded
            assert self.rules_cache is not None
            assert self.ruleset_cache is not None

            self.model_data.render_capa_doc(self.doc, self.view_show_results_by_function.isChecked())
            self.set_view_status_label(
                "capa rules directory: %s (%d rules)" % (settings.user[CAPA_SETTINGS_RULE_PATH], len(self.rules_cache))
            )
        except Exception as e:
            logger.error("Failed to render results (error: %s)", e, exc_info=True)
            return False

        return True

    def reset_view_tree(self):
        """reset tree view UI controls

        called when user selects plugin reset from menu
        """
        self.view_limit_results_by_function.setChecked(False)
        # self.view_show_results_by_function.setChecked(False)
        self.view_search_bar.setText("")
        self.view_tree.reset_ui()

    def analyze_program(self, use_cache=False):
        """ """
        self.range_model_proxy.invalidate()
        self.search_model_proxy.invalidate()
        self.model_data.reset()
        self.model_data.clear()
        self.set_view_status_label("Loading...")

        ida_kernwin.show_wait_box("capa explorer")
        success = self.load_capa_results(use_cache)
        ida_kernwin.hide_wait_box()

        self.reset_view_tree()

        if not success:
            self.set_view_status_label("Click Analyze to get started...")
            logger.info("Analysis failed.")
        else:
            logger.info("Analysis completed.")

    def load_capa_function_results(self):
        """ """
        if not self.rules_cache or not self.ruleset_cache:
            # only reload rules if caches are empty
            if not self.load_capa_rules():
                return False
        else:
            logger.info('Using cached ruleset, click "Reset" to reload rules from disk.')

        assert self.rules_cache is not None
        assert self.ruleset_cache is not None

        if ida_kernwin.user_cancelled():
            logger.info("User cancelled analysis.")
            return False
        update_wait_box("loading IDA extractor")

        try:
            # must use extractor to get function, as capa analysis requires casted object
            extractor = CapaExplorerFeatureExtractor()
        except Exception as e:
            logger.error("Failed to load IDA feature extractor (error: %s)", e)
            return False

        if ida_kernwin.user_cancelled():
            logger.info("User cancelled analysis.")
            return False
        update_wait_box("extracting function features")

        try:
            f = idaapi.get_func(idaapi.get_screen_ea())
            if f:
                fh: Optional[FunctionHandle] = extractor.get_function(f.start_ea)
                assert fh is not None
                self.rulegen_current_function = fh

                func_features, bb_features = find_func_features(fh, extractor)
                self.rulegen_func_features_cache = collections.defaultdict(set, copy.copy(func_features))
                self.rulegen_bb_features_cache = collections.defaultdict(dict, copy.copy(bb_features))

                if ida_kernwin.user_cancelled():
                    logger.info("User cancelled analysis.")
                    return False
                update_wait_box("matching function/basic block rule scope")

                try:
                    # add function and bb rule matches to function features, for display purposes
                    func_matches, bb_matches = find_func_matches(fh, self.ruleset_cache, func_features, bb_features)
                    for (name, addrs) in itertools.chain(func_matches.items(), bb_matches.items()):
                        rule = self.ruleset_cache[name]
                        if rule.is_subscope_rule():
                            continue
                        for (addr, _) in addrs:
                            func_features[capa.features.common.MatchedRule(name)].add(addr)
                except Exception as e:
                    logger.error("Failed to match function/basic block rule scope (error: %s)", e)
                    return False
            else:
                fh = None
                func_features = {}
        except UserCancelledError:
            logger.info("User cancelled analysis.")
            return False
        except Exception as e:
            logger.error("Failed to extract function features (error: %s)", e)
            return False

        if ida_kernwin.user_cancelled():
            logger.info("User cancelled analysis.")
            return False
        update_wait_box("extracting file features")

        try:
            file_features = find_file_features(extractor)
            self.rulegen_file_features_cache = copy.copy(file_features)

            if ida_kernwin.user_cancelled():
                logger.info("User cancelled analysis.")
                return False
            update_wait_box("matching file rule scope")

            try:
                # add file matches to file features, for display purposes
                for (name, addrs) in find_file_matches(self.ruleset_cache, file_features).items():
                    rule = self.ruleset_cache[name]
                    if rule.is_subscope_rule():
                        continue
                    for (addr, _) in addrs:
                        file_features[capa.features.common.MatchedRule(name)].add(addr)
            except Exception as e:
                logger.error("Failed to match file scope rules (error: %s)", e)
                return False
        except Exception as e:
            logger.error("Failed to extract file features (error: %s)", e)
            return False

        if ida_kernwin.user_cancelled():
            logger.info("User cancelled analysis.")
            return False
        update_wait_box("rendering views")

        try:
            # load preview and feature tree
            self.view_rulegen_preview.load_preview_meta(
                fh.address if fh else None,
                settings.user.get(CAPA_SETTINGS_RULEGEN_AUTHOR, "<insert_author>"),
                settings.user.get(CAPA_SETTINGS_RULEGEN_SCOPE, "function"),
            )
            self.view_rulegen_features.load_features(file_features, func_features)

            # self.view_rulegen_header_label.setText("Function Features (%s)" % trim_function_name(f))
            self.set_view_status_label(
                "capa rules directory: %s (%d rules)" % (settings.user[CAPA_SETTINGS_RULE_PATH], len(self.rules_cache))
            )
        except Exception as e:
            logger.error("Failed to render views (error: %s)", e, exc_info=True)
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
            logger.info("Analysis failed.")
        else:
            logger.info("Analysis completed.")

    def reset_program_analysis_views(self):
        """ """
        logger.info("Resetting program analysis views.")

        self.model_data.reset()
        self.reset_view_tree()

        self.rules_cache = None
        self.ruleset_cache = None

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
        self.rulegen_func_features_cache = {}
        self.rulegen_bb_features_cache = {}
        self.rulegen_file_features_cache = {}
        self.view_rulegen_status_label.clear()

        if not is_analyze:
            # clear rules and ruleset cache only if user clicked "Reset"
            self.rules_cache = None
            self.ruleset_cache = None

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

    def update_rule_status(self, rule_text):
        """ """
        assert self.rules_cache is not None

        if not self.view_rulegen_editor.invisibleRootItem().childCount():
            self.set_rulegen_preview_border_neutral()
            self.view_rulegen_status_label.clear()
            return

        self.set_rulegen_preview_border_error()

        try:
            rule = capa.rules.Rule.from_yaml(rule_text)
        except Exception as e:
            self.set_rulegen_status("Failed to compile rule (%s)" % e)
            return

        # create deep copy of current rules, add our new rule
        rules = copy.copy(self.rules_cache)

        # ensure subscope rules are included
        for sub in rule.extract_subscope_rules():
            rules.append(sub)

        # include our new rule in the list
        rules.append(rule)

        try:
            file_features = copy.copy(dict(self.rulegen_file_features_cache))
            if self.rulegen_current_function:
                func_matches, bb_matches = find_func_matches(
                    self.rulegen_current_function,
                    capa.rules.RuleSet(list(capa.rules.get_rules_and_dependencies(rules, rule.name))),
                    self.rulegen_func_features_cache,
                    self.rulegen_bb_features_cache,
                )
                file_features.update(copy.copy(self.rulegen_func_features_cache))
            else:
                func_matches = {}
                bb_matches = {}

            _, file_matches = capa.engine.match(
                capa.rules.RuleSet(list(capa.rules.get_rules_and_dependencies(rules, rule.name))).file_rules,
                file_features,
                NO_ADDRESS,
            )
        except Exception as e:
            self.set_rulegen_status("Failed to match rule (%s)" % e)
            return

        if tuple(
            filter(
                lambda m: m[0] == rule.name,
                itertools.chain(file_matches.items(), func_matches.items(), bb_matches.items()),
            )
        ):
            # made it here, rule compiled and match was found
            self.set_rulegen_preview_border_success()
            self.set_rulegen_status("Rule compiled and matched")
        else:
            # made it here, rule compiled but no match found, may be intended so we warn user
            self.set_rulegen_preview_border_warn()
            self.set_rulegen_status("Rule compiled, but not matched")

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
            ) = dialog.get_values()

    def save_program_analysis(self):
        """ """
        if not self.doc:
            idaapi.info("No program analysis to save.")
            return

        s = self.doc.json().encode("utf-8")

        path = self.ask_user_capa_json_file()
        if not path:
            return

        write_file(path, s)

    def save_function_analysis(self):
        """ """
        s = self.view_rulegen_preview.toPlainText().encode("utf-8")
        if not s:
            idaapi.info("No rule to save.")
            return

        path = self.ask_user_capa_rule_file()
        if not path:
            return

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
        if self.doc:
            self.analyze_program(use_cache=True)

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
