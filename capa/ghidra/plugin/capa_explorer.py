# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Run capa against loaded Ghidra database and render results in Ghidra UI

# @author Colton Gabertan (gabertan.colton@gmail.com)
# @category capa
# @runtime PyGhidra

import json
import logging
import pathlib
from typing import Any

from java.util import ArrayList
from ghidra.util import Msg
from ghidra.app.cmd.label import AddLabelCmd, CreateNamespacesCmd
from ghidra.util.exception import CancelledException
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import Namespace, SourceType, SymbolType

import capa
import capa.main
import capa.rules
import capa.version
import capa.render.json
import capa.ghidra.helpers
import capa.capabilities.common
import capa.features.extractors.ghidra.context
import capa.features.extractors.ghidra.extractor

logger = logging.getLogger("capa_explorer")


def show_monitor_message(msg):
    capa.ghidra.helpers.get_monitor().checkCanceled()
    capa.ghidra.helpers.get_monitor().setMessage(msg)


def show_error(msg):
    Msg.showError(None, None, "capa explorer", msg)


def show_warn(msg):
    Msg.showWarn(None, None, "capa explorer", msg)


def show_info(msg):
    Msg.showInfo(None, None, "capa explorer", msg)


def add_bookmark(addr, txt, category="CapaExplorer"):
    """create bookmark at addr"""
    capa.ghidra.helpers.get_current_program().getBookmarkManager().setBookmark(addr, "Info", category, txt)


def create_namespace(namespace_str):
    """create new Ghidra namespace for each capa namespace"""
    cmd = CreateNamespacesCmd(namespace_str, SourceType.USER_DEFINED)
    cmd.applyTo(capa.ghidra.helpers.get_current_program())
    return cmd.getNamespace()


def create_label(ghidra_addr, name, capa_namespace):
    """custom label cmd to overlay symbols under capa-generated namespaces"""

    # prevent duplicate labels under the same capa-generated namespace
    symbol_table = capa.ghidra.helpers.get_current_program().getSymbolTable()
    for sym in symbol_table.getSymbols(ghidra_addr):
        if sym.getName(True) == capa_namespace.getName(True) + Namespace.DELIMITER + name:
            return

    # create SymbolType.LABEL at addr
    # prioritize capa-generated namespace (duplicate match @ new addr), else put under global Ghidra one (new match)
    cmd = AddLabelCmd(ghidra_addr, name, True, SourceType.USER_DEFINED)
    cmd.applyTo(capa.ghidra.helpers.get_current_program())

    # assign new match overlay label to capa-generated namespace
    cmd.getSymbol().setNamespace(capa_namespace)
    return


class CapaMatchData:
    def __init__(
        self,
        namespace,
        scope,
        capability,
        matches,
        attack: list[dict[Any, Any]],
        mbc: list[dict[Any, Any]],
    ):
        self.namespace = namespace
        self.scope = scope
        self.capability = capability
        self.matches = matches
        self.attack = attack
        self.mbc = mbc

    def bookmark_functions(self):
        """create bookmarks for MITRE ATT&CK & MBC mappings"""

        if self.attack == [] and self.mbc == []:
            return

        for key in self.matches.keys():
            addr = capa.ghidra.helpers.get_flat_api().toAddr(hex(key))
            func = capa.ghidra.helpers.get_flat_api().getFunctionContaining(addr)

            # bookmark & tag MITRE ATT&CK tactics & MBC @ function scope
            if func is not None:
                func_addr = func.getEntryPoint()

                if self.attack != []:
                    for item in self.attack:
                        attack_txt = ""
                        for part in item.get("parts", {}):
                            attack_txt = attack_txt + part + Namespace.DELIMITER
                        attack_txt = attack_txt + item.get("id", {})
                        add_bookmark(func_addr, attack_txt, "CapaExplorer::MITRE ATT&CK")

                if self.mbc != []:
                    for item in self.mbc:
                        mbc_txt = ""
                        for part in item.get("parts", {}):
                            mbc_txt = mbc_txt + part + Namespace.DELIMITER
                        mbc_txt = mbc_txt + item.get("id", {})
                        add_bookmark(func_addr, mbc_txt, "CapaExplorer::MBC")

    def set_plate_comment(self, ghidra_addr):
        """set plate comments at matched functions"""
        comment = capa.ghidra.helpers.get_flat_api().getPlateComment(ghidra_addr)
        rule_path = self.namespace.replace(Namespace.DELIMITER, "/")
        # 2 calls to avoid duplicate comments via subsequent script runs
        if comment is None:
            # first comment @ function
            comment = rule_path + "\n"
            capa.ghidra.helpers.get_flat_api().setPlateComment(ghidra_addr, comment)
        elif rule_path not in comment:
            comment = comment + rule_path + "\n"
            capa.ghidra.helpers.get_flat_api().setPlateComment(ghidra_addr, comment)
        else:
            return

    def set_pre_comment(self, ghidra_addr, sub_type, description):
        """set pre comments at subscoped matches of main rules"""
        comment = capa.ghidra.helpers.get_flat_api().getPreComment(ghidra_addr)
        if comment is None:
            comment = "capa: " + sub_type + "(" + description + ")" + ' matched in "' + self.capability + '"\n'
            capa.ghidra.helpers.get_flat_api().setPreComment(ghidra_addr, comment)
        elif self.capability not in comment:
            comment = (
                comment + "capa: " + sub_type + "(" + description + ")" + ' matched in "' + self.capability + '"\n'
            )
            capa.ghidra.helpers.get_flat_api().setPreComment(ghidra_addr, comment)
        else:
            return

    def label_matches(self, do_namespaces, do_comments):
        """label findings at function scopes and comment on subscope matches"""
        capa_namespace = None
        if do_namespaces:
            capa_namespace = create_namespace(self.namespace)

        symbol_table = capa.ghidra.helpers.get_current_program().getSymbolTable()

        # handle function main scope of matched rule
        # these will typically contain further matches within
        if self.scope == "function":
            for addr in self.matches.keys():
                ghidra_addr = capa.ghidra.helpers.get_flat_api().toAddr(hex(addr))

                # classify new function label under capa-generated namespace
                if do_namespaces:
                    sym = symbol_table.getPrimarySymbol(ghidra_addr)
                    if sym is not None:
                        if sym.getSymbolType() == SymbolType.FUNCTION:
                            create_label(ghidra_addr, sym.getName(), capa_namespace)

                if do_comments:
                    self.set_plate_comment(ghidra_addr)

                # parse the corresponding nodes, and pre-comment subscope matched features
                # under the encompassing function(s)
                for sub_match in self.matches.get(addr):
                    for loc, node in sub_match.items():
                        sub_ghidra_addr = capa.ghidra.helpers.get_flat_api().toAddr(hex(loc))
                        if sub_ghidra_addr == ghidra_addr:
                            # skip duplicates
                            continue

                        # precomment subscope matches under the function
                        if node != {} and do_comments:
                            for sub_type, description in parse_node(node):
                                self.set_pre_comment(sub_ghidra_addr, sub_type, description)
        else:
            # resolve the encompassing function for the capa namespace
            # of non-function scoped main matches
            for addr in self.matches.keys():
                ghidra_addr = capa.ghidra.helpers.get_flat_api().toAddr(hex(addr))

                # basic block / insn scoped main matches
                # Ex. See "Create Process on Windows" Rule
                func = capa.ghidra.helpers.get_flat_api().getFunctionContaining(ghidra_addr)
                if func is not None:
                    func_addr = func.getEntryPoint()
                    if do_namespaces:
                        create_label(func_addr, func.getName(), capa_namespace)
                    if do_comments:
                        self.set_plate_comment(func_addr)

                # create subscope match precomments
                for sub_match in self.matches.get(addr):
                    for loc, node in sub_match.items():
                        sub_ghidra_addr = capa.ghidra.helpers.get_flat_api().toAddr(hex(loc))

                        if node != {}:
                            if func is not None:
                                # basic block/ insn scope under resolved function
                                if do_comments:
                                    for sub_type, description in parse_node(node):
                                        self.set_pre_comment(sub_ghidra_addr, sub_type, description)
                            else:
                                # this would be a global/file scoped main match
                                # try to resolve the encompassing function via the subscope match, instead
                                # Ex. "run as service" rule
                                sub_func = capa.ghidra.helpers.get_flat_api().getFunctionContaining(sub_ghidra_addr)
                                if sub_func is not None:
                                    sub_func_addr = sub_func.getEntryPoint()
                                    # place function in capa namespace & create the subscope match label in Ghidra's global namespace
                                    if do_namespaces:
                                        create_label(sub_func_addr, sub_func.getName(), capa_namespace)
                                    if do_comments:
                                        self.set_plate_comment(sub_func_addr)

                                    if do_comments:
                                        for sub_type, description in parse_node(node):
                                            self.set_pre_comment(sub_ghidra_addr, sub_type, description)
                                else:
                                    # addr is in some other file section like .data
                                    # represent this location with a label symbol under the capa namespace
                                    # Ex. See "Reference Base64 String" rule
                                    if do_namespaces:
                                        for _sub_type, _description in parse_node(node):
                                            # in many cases, these will be ghidra-labeled data, so just add the existing
                                            # label symbol to the capa namespace
                                            for sym in symbol_table.getSymbols(sub_ghidra_addr):
                                                if sym.getSymbolType() == SymbolType.LABEL:
                                                    sym.setNamespace(capa_namespace)
                                    if do_comments:
                                        for sub_type, description in parse_node(node):
                                            self.set_pre_comment(sub_ghidra_addr, sub_type, description)


def get_capabilities():
    rules_dir = ""

    show_monitor_message(f"requesting capa {capa.version.__version__} rules directory")
    selected_dir = askDirectory(f"choose capa {capa.version.__version__} rules directory", "Ok")  # type: ignore [name-defined] # noqa: F821

    if selected_dir:
        rules_dir = selected_dir.getPath()

    if not rules_dir:
        raise CancelledException

    rules_path: pathlib.Path = pathlib.Path(rules_dir)

    show_monitor_message(f"loading rules from {rules_path}")
    rules = capa.rules.get_rules([rules_path])

    show_monitor_message("collecting binary metadata")
    meta = capa.ghidra.helpers.collect_metadata([rules_path])

    show_monitor_message("running capa analysis")
    extractor = capa.features.extractors.ghidra.extractor.GhidraFeatureExtractor()
    capabilities = capa.capabilities.common.find_capabilities(rules, extractor, True)

    show_monitor_message("checking for static limitations")
    if capa.capabilities.common.has_static_limitation(rules, capabilities, is_standalone=False):
        show_warn(
            "capa explorer encountered warnings during analysis. Please check the console output for more information.",
        )

    show_monitor_message("rendering results")
    return capa.render.json.render(meta, rules, capabilities.matches)


def get_locations(match_dict):
    """recursively collect match addresses and associated nodes"""

    for loc in match_dict.get("locations", {}):
        # either an rva (absolute)
        # or an offset into a file (file)
        if loc.get("type", "") in ("absolute", "file"):
            yield loc.get("value"), match_dict.get("node")

    for child in match_dict.get("children", {}):
        yield from get_locations(child)


def parse_node(node_data):
    """pull match descriptions and sub features by parsing node dicts"""

    node = node_data.get(node_data.get("type"))

    if "description" in node:
        yield "description", node.get("description")

    data = node.get(node.get("type"))
    if isinstance(data, (str, int)):
        feat_type = node.get("type")
        if isinstance(data, int):
            data = hex(data)
        yield feat_type, data


def parse_json(capa_data):
    """Parse json produced by capa"""

    for rule, capability in capa_data.get("rules", {}).items():
        # structure to contain rule match address & supporting feature data
        # {rule match addr:[{feature addr:{node_data}}]}
        rule_matches: dict[Any, list[Any]] = {}
        for i in range(len(capability.get("matches"))):
            # grab rule match location
            match_loc = capability.get("matches")[i][0].get("value")
            if match_loc is None:
                # Ex. See "Reference Base64 string"
                # {'type':'no address'}
                match_loc = i
            rule_matches[match_loc] = []

            # grab extracted feature locations & corresponding node data
            # feature[0]: location
            # feature[1]: node
            features = capability.get("matches")[i][1]
            feat_dict = {}
            for feature in get_locations(features):
                feat_dict[feature[0]] = feature[1]
                rule_matches[match_loc].append(feat_dict)

        # dict data of currently matched rule
        meta = capability["meta"]

        # get MITRE ATT&CK and MBC
        attack = meta.get("attack")
        if attack is None:
            attack = []
        mbc = meta.get("mbc")
        if mbc is None:
            mbc = []

        # scope match for the rule
        scope = meta["scopes"].get("static")

        fmt_rule = Namespace.DELIMITER + rule.replace(" ", "-")
        if "namespace" in meta:
            # split into list to help define child namespaces
            # this requires the correct delimiter used by Ghidra
            # Ex. 'communication/named-pipe/create/create pipe' -> capa::communication::named-pipe::create::create-pipe
            namespace_str = Namespace.DELIMITER.join(meta["namespace"].split("/"))
            namespace = "capa_explorer" + Namespace.DELIMITER + namespace_str + fmt_rule
        else:
            # lib rules via the official rules repo will not contain data
            # for the "namespaces" key, so format using rule itself
            # Ex. 'contain loop' -> capa::lib::contain-loop
            namespace = "capa_explorer" + Namespace.DELIMITER + "lib" + fmt_rule

        yield CapaMatchData(namespace, scope, rule, rule_matches, attack, mbc)


def main():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    choices = ["namespaces", "bookmarks", "comments"]
    # use ArrayList to resolve ambiguous askChoices overloads (List vs List, List) in PyGhidra
    choices_java = ArrayList()
    for c in choices:
        choices_java.add(c)

    choice_labels = [
        'add "capa_explorer" namespace for matched functions',
        "add bookmarks for matched functions",
        "add comments to matched functions",
    ]
    # use ArrayList to resolve ambiguous askChoices overloads (List vs List, List) in PyGhidra
    choice_labels_java = ArrayList()
    for c in choice_labels:
        choice_labels_java.add(c)

    selected = list(askChoices("capa explorer", "select actions:", choices_java, choice_labels_java))  # type: ignore [name-defined] # noqa: F821

    do_namespaces = "namespaces" in selected
    do_comments = "comments" in selected
    do_bookmarks = "bookmarks" in selected

    if not any((do_namespaces, do_comments, do_bookmarks)):
        raise CancelledException("no actions selected")

    # initialize the context for the extractor/helpers
    capa.features.extractors.ghidra.context.set_context(
        currentProgram,  # type: ignore [name-defined] # noqa: F821
        FlatProgramAPI(currentProgram),  # type: ignore [name-defined] # noqa: F821
        monitor,  # type: ignore [name-defined] # noqa: F821
    )

    show_monitor_message("checking supported Ghidra version")
    if not capa.ghidra.helpers.is_supported_ghidra_version():
        show_error("unsupported Ghidra version")
        return capa.main.E_UNSUPPORTED_GHIDRA_VERSION

    show_monitor_message("checking supported file type")
    if not capa.ghidra.helpers.is_supported_file_type():
        show_error("unsupported file type")
        return capa.main.E_INVALID_FILE_TYPE

    show_monitor_message("checking supported file architecture")
    if not capa.ghidra.helpers.is_supported_arch_type():
        show_error("unsupported file architecture")
        return capa.main.E_INVALID_FILE_ARCH

    # capa_data will always contain {'meta':..., 'rules':...}
    # if the 'rules' key contains no values, then there were no matches
    capa_data = json.loads(get_capabilities())
    if capa_data.get("rules") is None:
        show_info("capa explorer found no matches.")
        return capa.main.E_EMPTY_REPORT

    show_monitor_message("processing matches")
    for item in parse_json(capa_data):
        if do_bookmarks:
            show_monitor_message("adding bookmarks")
            item.bookmark_functions()
        if do_namespaces or do_comments:
            show_monitor_message("adding labels")
            item.label_matches(do_namespaces, do_comments)

    show_info("capa explorer analysis complete.")

    return 0


if __name__ == "__main__":
    try:
        if main() != 0:
            show_error(
                "capa explorer encountered errors during analysis. Please check the console output for more information.",
            )
    except CancelledException:
        show_info("capa explorer analysis cancelled.")
