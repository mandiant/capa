# Integrate capa results with Ghidra UI
# @author Colton Gabertan (gabertan.colton@gmail.com)
# @category Python 3.capa

# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
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

    # create SymbolType.LABEL at addr
    # prioritize capa-generated namespace (duplicate match @ new addr), else put under global Ghidra one (new match)
    cmd = AddLabelCmd(ghidra_addr, name, True, SourceType.USER_DEFINED)
    cmd.applyTo(currentProgram())  # type: ignore [name-defined] # noqa: F821

    # assign new match overlay label to capa-generated namespace
    try:
        cmd.getSymbol().setNamespace(capa_namespace)
        return
    except RuntimeError:  # DuplicateNameError
        # duplicate features within same scope/ namespace
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

    def recurse_node(self, node_data):
        """pull match descriptions by recursing node dicts

        Note: all final returned data should be type str or None
        """

        if node_data is None or node_data == {}:
            # mismatched key or empty node dict, skip
            # ex. {'type':'subscope', 'scope':'basic block'}
            return ""

        if isinstance(node_data, int):
            # Number operands, usually parameters or immediates
            # {'type':'number', 'number':80}
            # hex() will cast this int to a str type
            return hex(node_data)

        if isinstance(node_data, str):
            # expect the "description" key's string value
            # {'description':'PEB->OSMajorVersion'}
            return node_data

        if "description" in node_data:
            return node_data.get("description")
        else:
            # if no "description" key, the "type" key's value is the
            # expected key.
            # ex. {'type':'api', 'api':'RegisterServiceCtrlHandler'}
            return self.recurse_node(node_data.get(node_data.get("type")))

    def tag_functions(self):
        """create function tags & bookmarks for MITRE ATT&CK & MBC mappings"""

        for key in self.matches.keys():
            addr = toAddr(hex(key))  # type: ignore [name-defined] # noqa: F821
            func = getFunctionContaining(addr)  # type: ignore [name-defined] # noqa: F821

            # bookmark & tag MITRE ATT&CK tactics & MBC @ function scope
            if func is not None:
                func.addTag(self.capability)

                for item in self.attack:
                    attack_txt = item.get("tactic") + Namespace.DELIMITER + item.get("id")
                    add_bookmark(addr, attack_txt, "CapaExplorer::MITRE ATT&CK")

                for item in self.mbc:
                    mbc_txt = item.get("objective") + Namespace.DELIMITER + item.get("id")
                    add_bookmark(addr, mbc_txt, "CapaExplorer::MBC")

    def label_matches(self):
        """bookmark & label findings at all scopes"""
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

                    # parse the corresponding nodes, and label subscope matched features
                    # under the encompassing function(s)
                    for sub_match in self.matches.get(addr):
                        for loc, node in sub_match.items():
                            sub_ghidra_addr = toAddr(hex(loc))  # type: ignore [name-defined] # noqa: F821
                            if sub_ghidra_addr == ghidra_addr:
                                # skip duplicates
                                continue

                            # classify matched extracted features under Ghidra Global scope
                            if node != {}:
                                label_name = self.recurse_node(node).replace(" ", "-")
                                if label_name != "":
                                    label_name = "capa_LAB_" + label_name + "_" + sub_ghidra_addr.toString().upper()
                                    createLabel(sub_ghidra_addr, label_name, False, SourceType.USER_DEFINED)  # type: ignore [name-defined] # noqa: F821
        else:
            # resolve the encompassing function for the capa namespace
            for addr in self.matches.keys():
                ghidra_addr = toAddr(hex(addr))  # type: ignore [name-defined] # noqa: F821

                # basic block / insn scoped matches
                # Ex. See "Create Process on Windows" Rule
                func = getFunctionContaining(ghidra_addr)  # type: ignore [name-defined] # noqa: F821
                if func is not None:
                    create_label(func.getEntryPoint(), func.getName(), capa_namespace)

                # create subscope labels in Ghidra's global scope
                for sub_match in self.matches.get(addr):
                    for loc, node in sub_match.items():
                        sub_ghidra_addr = toAddr(hex(loc))  # type: ignore [name-defined] # noqa: F821

                        if node != {}:
                            label_name = self.recurse_node(node).replace(" ", "-")
                            if label_name != "":
                                if func is not None:
                                    label_name = "capa_LAB_" + label_name + "_" + sub_ghidra_addr.toString().upper()
                                    createLabel(sub_ghidra_addr, label_name, False, SourceType.USER_DEFINED)  # type: ignore [name-defined] # noqa: F821
                                else:
                                    # this would be a global/file scoped main match
                                    # try to resolve the encompassing function via the subscope match, instead
                                    sub_func = getFunctionContaining(sub_ghidra_addr)  # type: ignore [name-defined] # noqa: F821
                                    if sub_func is not None:
                                        label_name = "capa_LAB_" + label_name + "_" + sub_ghidra_addr.toString().upper()
                                        # place function in capa namespace & create the subscope match label in Ghidra's global namespace
                                        create_label(sub_func.getEntryPoint(), sub_func.getName(), capa_namespace)
                                        createLabel(sub_ghidra_addr, label_name, False, SourceType.USER_DEFINED)  # type: ignore [name-defined] # noqa: F821
                                    else:
                                        # addr is in some other file section like .data
                                        # represent this location with a label symbol under the capa namespace
                                        # Ex. See "Reference Base64 String" rule
                                        create_label(sub_ghidra_addr, label_name, capa_namespace)


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

    rules = capa.main.get_rules([rules_path])
    meta = capa.ghidra.helpers.collect_metadata([rules_path])
    extractor = capa.features.extractors.ghidra.extractor.GhidraFeatureExtractor()

    capabilities, counts = capa.main.find_capabilities(rules, extractor, True)

    if capa.main.has_file_limitation(rules, capabilities, is_standalone=False):
        popup("Capa Explorer encountered warnings during analysis. Please check the console output for more information.")  # type: ignore [name-defined] # noqa: F821
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
        # avoid passing NoneTypes
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
    # found
    capa_data = json.loads(get_capabilities())
    if capa_data.get("rules") is None:
        logger.info("capa explorer found no matches")
        popup("capa explorer found no matches.")  # type: ignore [name-defined] # noqa: F821
        return capa.main.E_EMPTY_REPORT

    for item in parse_json(capa_data):
        item.tag_functions()
        item.label_matches()
    logger.info("capa explorer analysis complete")
    popup("capa explorer analysis complete.\nPlease see results in the Bookmarks and Namespaces section of the Symbol Tree Window.")  # type: ignore [name-defined] # noqa: F821
    return 0


if __name__ == "__main__":
    if sys.version_info < (3, 8):
        from capa.exceptions import UnsupportedRuntimeError

        raise UnsupportedRuntimeError("This version of capa can only be used with Python 3.8+")
    exit_code = main()
    if exit_code != 0:
        popup("capa explorer encountered errors during analysis. Please check the console output for more information.")  # type: ignore [name-defined] # noqa: F821
    sys.exit(exit_code)
