# Run capa against loaded Ghidra database and render results in Ghidra UI
# @author Colton Gabertan (gabertan.colton@gmail.com)
# @category Python 3.capa

# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import sys
import json
import logging
import pathlib
from typing import Any, Dict, List

from ghidra.app.cmd.label import AddLabelCmd, CreateNamespacesCmd
from ghidra.program.model.symbol import Namespace, SourceType, SymbolType

import capa
import capa.main
import capa.rules
import capa.render.json
import capa.ghidra.helpers
import capa.capabilities.common
import capa.features.extractors.ghidra.extractor

logger = logging.getLogger("capa_explorer")


def add_bookmark(addr, txt, category="CapaExplorer"):
    """create bookmark at addr"""
    currentProgram().getBookmarkManager().setBookmark(addr, "Info", category, txt)  # type: ignore [name-defined] # noqa: F821


def create_namespace(namespace_str):
    """create new Ghidra namespace for each capa namespace"""

    cmd = CreateNamespacesCmd(namespace_str, SourceType.USER_DEFINED)
    cmd.applyTo(currentProgram())  # type: ignore [name-defined] # noqa: F821
    return cmd.getNamespace()


def create_label(ghidra_addr, name, capa_namespace):
    """custom label cmd to overlay symbols under capa-generated namespaces"""

    # prevent duplicate labels under the same capa-generated namespace
    symbol_table = currentProgram().getSymbolTable()  # type: ignore [name-defined] # noqa: F821
    for sym in symbol_table.getSymbols(ghidra_addr):
        if sym.getName(True) == capa_namespace.getName(True) + Namespace.DELIMITER + name:
            return

    # create SymbolType.LABEL at addr
    # prioritize capa-generated namespace (duplicate match @ new addr), else put under global Ghidra one (new match)
    cmd = AddLabelCmd(ghidra_addr, name, True, SourceType.USER_DEFINED)
    cmd.applyTo(currentProgram())  # type: ignore [name-defined] # noqa: F821

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
        attack: List[Dict[Any, Any]],
        mbc: List[Dict[Any, Any]],
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
            addr = toAddr(hex(key))  # type: ignore [name-defined] # noqa: F821
            func = getFunctionContaining(addr)  # type: ignore [name-defined] # noqa: F821

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
        comment = getPlateComment(ghidra_addr)  # type: ignore [name-defined] # noqa: F821
        rule_path = self.namespace.replace(Namespace.DELIMITER, "/")
        # 2 calls to avoid duplicate comments via subsequent script runs
        if comment is None:
            # first comment @ function
            comment = rule_path + "\n"
            setPlateComment(ghidra_addr, comment)  # type: ignore [name-defined] # noqa: F821
        elif rule_path not in comment:
            comment = comment + rule_path + "\n"
            setPlateComment(ghidra_addr, comment)  # type: ignore [name-defined] # noqa: F821
        else:
            return

    def set_pre_comment(self, ghidra_addr, sub_type, description):
        """set pre comments at subscoped matches of main rules"""
        comment = getPreComment(ghidra_addr)  # type: ignore [name-defined] # noqa: F821
        if comment is None:
            comment = "capa: " + sub_type + "(" + description + ")" + ' matched in "' + self.capability + '"\n'
            setPreComment(ghidra_addr, comment)  # type: ignore [name-defined] # noqa: F821
        elif self.capability not in comment:
            comment = (
                comment + "capa: " + sub_type + "(" + description + ")" + ' matched in "' + self.capability + '"\n'
            )
            setPreComment(ghidra_addr, comment)  # type: ignore [name-defined] # noqa: F821
        else:
            return

    def label_matches(self):
        """label findings at function scopes and comment on subscope matches"""
        capa_namespace = create_namespace(self.namespace)
        symbol_table = currentProgram().getSymbolTable()  # type: ignore [name-defined] # noqa: F821

        # handle function main scope of matched rule
        # these will typically contain further matches within
        if self.scope == "function":
            for addr in self.matches.keys():
                ghidra_addr = toAddr(hex(addr))  # type: ignore [name-defined] # noqa: F821

                # classify new function label under capa-generated namespace
                sym = symbol_table.getPrimarySymbol(ghidra_addr)
                if sym is not None:
                    if sym.getSymbolType() == SymbolType.FUNCTION:
                        create_label(ghidra_addr, sym.getName(), capa_namespace)
                        self.set_plate_comment(ghidra_addr)

                    # parse the corresponding nodes, and pre-comment subscope matched features
                    # under the encompassing function(s)
                    for sub_match in self.matches.get(addr):
                        for loc, node in sub_match.items():
                            sub_ghidra_addr = toAddr(hex(loc))  # type: ignore [name-defined] # noqa: F821
                            if sub_ghidra_addr == ghidra_addr:
                                # skip duplicates
                                continue

                            # precomment subscope matches under the function
                            if node != {}:
                                for sub_type, description in parse_node(node):
                                    self.set_pre_comment(sub_ghidra_addr, sub_type, description)
        else:
            # resolve the encompassing function for the capa namespace
            # of non-function scoped main matches
            for addr in self.matches.keys():
                ghidra_addr = toAddr(hex(addr))  # type: ignore [name-defined] # noqa: F821

                # basic block / insn scoped main matches
                # Ex. See "Create Process on Windows" Rule
                func = getFunctionContaining(ghidra_addr)  # type: ignore [name-defined] # noqa: F821
                if func is not None:
                    func_addr = func.getEntryPoint()
                    create_label(func_addr, func.getName(), capa_namespace)
                    self.set_plate_comment(func_addr)

                # create subscope match precomments
                for sub_match in self.matches.get(addr):
                    for loc, node in sub_match.items():
                        sub_ghidra_addr = toAddr(hex(loc))  # type: ignore [name-defined] # noqa: F821

                        if node != {}:
                            if func is not None:
                                # basic block/ insn scope under resolved function
                                for sub_type, description in parse_node(node):
                                    self.set_pre_comment(sub_ghidra_addr, sub_type, description)
                            else:
                                # this would be a global/file scoped main match
                                # try to resolve the encompassing function via the subscope match, instead
                                # Ex. "run as service" rule
                                sub_func = getFunctionContaining(sub_ghidra_addr)  # type: ignore [name-defined] # noqa: F821
                                if sub_func is not None:
                                    sub_func_addr = sub_func.getEntryPoint()
                                    # place function in capa namespace & create the subscope match label in Ghidra's global namespace
                                    create_label(sub_func_addr, sub_func.getName(), capa_namespace)
                                    self.set_plate_comment(sub_func_addr)
                                    for sub_type, description in parse_node(node):
                                        self.set_pre_comment(sub_ghidra_addr, sub_type, description)
                                else:
                                    # addr is in some other file section like .data
                                    # represent this location with a label symbol under the capa namespace
                                    # Ex. See "Reference Base64 String" rule
                                    for sub_type, description in parse_node(node):
                                        # in many cases, these will be ghidra-labeled data, so just add the existing
                                        # label symbol to the capa namespace
                                        for sym in symbol_table.getSymbols(sub_ghidra_addr):
                                            if sym.getSymbolType() == SymbolType.LABEL:
                                                sym.setNamespace(capa_namespace)
                                        self.set_pre_comment(sub_ghidra_addr, sub_type, description)


def get_capabilities():
    rules_dir: str = ""
    try:
        selected_dir = askDirectory("Choose capa rules directory", "Ok")  # type: ignore [name-defined] # noqa: F821
        if selected_dir:
            rules_dir = selected_dir.getPath()
    except RuntimeError:
        # RuntimeError thrown when user selects "Cancel"
        pass

    if not rules_dir:
        logger.info("You must choose a capa rules directory before running capa.")
        return ""  # return empty str to avoid handling both int and str types

    rules_path: pathlib.Path = pathlib.Path(rules_dir)
    logger.info("running capa using rules from %s", str(rules_path))

    rules = capa.rules.get_rules([rules_path])
    meta = capa.ghidra.helpers.collect_metadata([rules_path])
    extractor = capa.features.extractors.ghidra.extractor.GhidraFeatureExtractor()

    capabilities, counts = capa.capabilities.common.find_capabilities(rules, extractor, True)

    if capa.capabilities.common.has_file_limitation(rules, capabilities, is_standalone=False):
        popup("capa explorer encountered warnings during analysis. Please check the console output for more information.")  # type: ignore [name-defined] # noqa: F821
        logger.info("capa encountered warnings during analysis")

    return capa.render.json.render(meta, rules, capabilities)


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
        rule_matches: Dict[Any, List[Any]] = {}
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
            namespace = "capa" + Namespace.DELIMITER + namespace_str + fmt_rule
        else:
            # lib rules via the official rules repo will not contain data
            # for the "namespaces" key, so format using rule itself
            # Ex. 'contain loop' -> capa::lib::contain-loop
            namespace = "capa" + Namespace.DELIMITER + "lib" + fmt_rule

        yield CapaMatchData(namespace, scope, rule, rule_matches, attack, mbc)


def main():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    if isRunningHeadless():  # type: ignore [name-defined] # noqa: F821
        logger.error("unsupported Ghidra execution mode")
        return capa.main.E_UNSUPPORTED_GHIDRA_EXECUTION_MODE

    if not capa.ghidra.helpers.is_supported_ghidra_version():
        logger.error("unsupported Ghidra version")
        return capa.main.E_UNSUPPORTED_GHIDRA_VERSION

    if not capa.ghidra.helpers.is_supported_file_type():
        logger.error("unsupported file type")
        return capa.main.E_INVALID_FILE_TYPE

    if not capa.ghidra.helpers.is_supported_arch_type():
        logger.error("unsupported file architecture")
        return capa.main.E_INVALID_FILE_ARCH

    # capa_data will always contain {'meta':..., 'rules':...}
    # if the 'rules' key contains no values, then there were no matches
    capa_data = json.loads(get_capabilities())
    if capa_data.get("rules") is None:
        logger.info("capa explorer found no matches")
        popup("capa explorer found no matches.")  # type: ignore [name-defined] # noqa: F821
        return capa.main.E_EMPTY_REPORT

    for item in parse_json(capa_data):
        item.bookmark_functions()
        item.label_matches()
    logger.info("capa explorer analysis complete")
    popup("capa explorer analysis complete.\nPlease see results in the Bookmarks Window and Namespaces section of the Symbol Tree Window.")  # type: ignore [name-defined] # noqa: F821
    return 0


if __name__ == "__main__":
    if sys.version_info < (3, 8):
        from capa.exceptions import UnsupportedRuntimeError

        raise UnsupportedRuntimeError("This version of capa can only be used with Python 3.8+")
    exit_code = main()
    if exit_code != 0:
        popup("capa explorer encountered errors during analysis. Please check the console output for more information.")  # type: ignore [name-defined] # noqa: F821
    sys.exit(exit_code)
