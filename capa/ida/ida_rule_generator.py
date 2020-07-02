# TODO documentation

import logging
import binascii
import textwrap
from collections import Counter, defaultdict

import idc
import idaapi
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QTextEdit, QHeaderView, QTreeWidget, QTreeWidgetItem

import capa
import capa.main
import capa.features.extractors.ida.helpers
from capa.ida import plugin_helpers

logger = logging.getLogger("rulegen")


AUTHOR_NAME = ""
COLOR_HIGHLIGHT = 0xD096FF


def get_func_start(ea):
    f = idaapi.get_func(ea)
    if f:
        return f.start_ea
    else:
        return None


class Hooks(idaapi.UI_Hooks):
    """
    Notifies the plugin when navigating to another function
    NOTE: it uses the global variable FLEX to access the
    PluginForm object. This looks nasty, maybe there is a better way?
    """

    def screen_ea_changed(self, ea, prev_ea):
        widget = idaapi.get_current_widget()
        if idaapi.get_widget_type(widget) != idaapi.BWN_DISASM:
            # Ignore non disassembly views
            return

        try:
            f1 = get_func_start(ea)
            f2 = get_func_start(prev_ea)

            if f1 != f2:
                # changed to another function
                RULE_GEN_FORM.reload_features_tree()
        except Exception as e:
            logger.warn("exception: %s", e)


class RuleGeneratorForm(idaapi.PluginForm):
    def __init__(self):
        super(RuleGeneratorForm, self).__init__()
        self.title = "capa rule generator"

        self.parent = None
        self.parent_items = {}
        self.orig_colors = None

        self.hooks = Hooks()  # dirty?
        if self.hooks.hook():
            logger.info("UI notification hook installed successfully")

    def init_ui(self):
        self.tree = QTreeWidget()
        self.rule_text = QTextEdit()
        self.rule_text.setMinimumWidth(350)

        self.reload_features_tree()

        button_reset = QtWidgets.QPushButton("&Reset")
        button_reset.clicked.connect(self.reset)

        h_layout = QtWidgets.QHBoxLayout()
        v_layout = QtWidgets.QVBoxLayout()

        h_layout.addWidget(self.tree)
        h_layout.addWidget(self.rule_text)

        v_layout.addLayout(h_layout)
        v_layout.addWidget(button_reset)

        self.parent.setLayout(v_layout)

    def reset(self):
        plugin_helpers.reset_selection(self.tree)
        plugin_helpers.reset_colors(self.orig_colors)
        self.rule_text.setText("")

    def reload_features_tree(self):
        self.reset()
        self.tree.clear()
        self.orig_colors = None
        self.parent_items = {}

        features = self.get_features()

        if not features:
            return

        feature_vas = set().union(*features.values())
        self.orig_colors = plugin_helpers.get_orig_color_feature_vas(feature_vas)
        self.create_tree(features)
        self.tree.update()

    def get_features(self):
        # load like standalone tool
        extractor = capa.features.extractors.ida.IdaFeatureExtractor()
        f = idaapi.get_func(idaapi.get_screen_ea())
        if not f:
            logger.info("function does not exist at 0x%x", idaapi.get_screen_ea())
            return

        return self.extract_function_features(f)

    def extract_function_features(self, f):
        features = defaultdict(set)
        for bb in idaapi.FlowChart(f, flags=idaapi.FC_PREDS):
            for insn in capa.features.extractors.ida.helpers.get_instructions_in_range(bb.start_ea, bb.end_ea):
                for feature, va in capa.features.extractors.ida.insn.extract_features(f, bb, insn):
                    features[feature].add(va)
            for feature, va in capa.features.extractors.ida.basicblock.extract_features(f, bb):
                features[feature].add(va)
        return features

    def create_tree(self, features):
        self.tree.setMinimumWidth(400)
        # self.tree.setMinimumHeight(300)
        self.tree.setHeaderLabels(["Feature", "Virtual Address", "Disassembly"])
        # auto resize columns
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.tree.itemClicked.connect(self.on_item_clicked)

        # features sorted by location of first occurrence
        # TODO fix characteristic features display and rule text
        for feature, vas in sorted(features.items(), key=lambda k: sorted(k[1])):
            # level 0
            if type(feature) not in self.parent_items:
                self.parent_items[type(feature)] = plugin_helpers.add_child_item(self.tree, [feature.name.lower()])

            # level 1
            if feature not in self.parent_items:
                self.parent_items[feature] = plugin_helpers.add_child_item(
                    self.parent_items[type(feature)], [str(feature)]
                )

            # level n > 1
            if len(vas) > 1:
                for va in sorted(vas):
                    plugin_helpers.add_child_item(
                        self.parent_items[feature],
                        [str(feature), "0x%X" % va, plugin_helpers.get_disasm_line(va)],
                        feature,
                    )
            else:
                va = vas.pop()
                self.parent_items[feature].setText(0, str(feature))
                self.parent_items[feature].setText(1, "0x%X" % va)
                self.parent_items[feature].setText(2, plugin_helpers.get_disasm_line(va))
                self.parent_items[feature].setData(0, 0x100, feature)

    # @QtCore.pyqtSlot(QTreeWidgetItem, int)
    def on_item_clicked(self, it, col):
        # logger.debug('clicked %s, %s, %s', it, col, it.text(col))
        # jump to address
        if col == 1 and it.text(col):
            va = int(it.text(col), 0x10)
            if va:
                idc.jumpto(va)

        # highlight in disassembly
        plugin_helpers.reset_colors(self.orig_colors)
        selected = self.get_selected_items()
        for va in selected.keys():
            idc.set_color(va, idc.CIC_ITEM, COLOR_HIGHLIGHT)

        self.update_rule_text()

    def update_rule_text(self):
        features = self.get_selected_items().values()
        rule = self.get_rule_from_features(features)
        self.rule_text.setText(rule)

    def get_rule_from_features(self, features):
        rule_parts = []
        counted = zip(
            Counter(features).keys(), Counter(features).values()  # equals to list(set(words))
        )  # counts the elements' frequency

        # single features
        for k, v in filter(lambda t: t[1] == 1, counted):
            # TODO args to hex if int
            if k.name.lower() == "bytes":
                # Convert raw bytes to uppercase hex representation (e.g., '12 34 56')
                upper_hex_bytes = binascii.hexlify(args_to_str(k.args)).upper()
                rule_value_str = ""
                for i in range(0, len(upper_hex_bytes), 2):
                    rule_value_str += upper_hex_bytes[i : i + 2] + " "
                r = "    - %s: %s" % (k.name.lower(), rule_value_str)
            else:
                r = "    - %s: %s" % (k.name.lower(), args_to_str(k.args))
            rule_parts.append(r)

        # counted features
        for k, v in filter(lambda t: t[1] > 1, counted):
            r = "    - count(%s): %d" % (str(k), v)
            rule_parts.append(r)

        rule_prefix = textwrap.dedent(
            """
        rule:
          meta:
            name:
            author: %s
            scope: function
            examples:
              - %s:0x%X
          features:
        """
            % (AUTHOR_NAME, idc.retrieve_input_file_md5(), get_func_start(idc.here()))
        ).strip()
        return "%s\n%s" % (rule_prefix, "\n".join(sorted(rule_parts)))

    # TODO merge into capa_idautils, get feature data
    def get_selected_items(self):
        selected = {}
        iterator = QtWidgets.QTreeWidgetItemIterator(self.tree, QtWidgets.QTreeWidgetItemIterator.Checked)
        while iterator.value():
            item = iterator.value()
            if item.text(1):
                # logger.debug('selected %s, %s, %s', item.text(1), item.text(0), item.data(0, 0x100))
                selected[int(item.text(1), 0x10)] = item.data(0, 0x100)
            iterator += 1
        return selected

    # ----------------------------------------------------------
    # IDA Plugin API
    # ----------------------------------------------------------
    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.init_ui()

    def Show(self):
        return idaapi.PluginForm.Show(
            self, self.title, options=(idaapi.PluginForm.WOPN_RESTORE | idaapi.PluginForm.WOPN_PERSIST)
        )

    def OnClose(self, form):
        self.reset()
        if self.hooks.unhook():
            logger.info("UI notification hook uninstalled successfully")
        logger.info("RuleGeneratorForm closed")


def args_to_str(args):
    a = []
    for arg in args:
        if (isinstance(arg, int) or isinstance(arg, long)) and arg > 10:
            a.append("0x%X" % arg)
        else:
            a.append(str(arg))
    return ",".join(a)


def main():
    logging.basicConfig(level=logging.INFO)

    global RULE_GEN_FORM
    try:
        # there is an instance, reload it
        RULE_GEN_FORM
        RULE_GEN_FORM.Close()
        RULE_GEN_FORM = RuleGeneratorForm()
    except Exception:
        # there is no instance yet
        RULE_GEN_FORM = RuleGeneratorForm()

    RULE_GEN_FORM.Show()


if __name__ == "__main__":
    main()
