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
from contextlib import suppress

from ghidra.app.cmd.label import CreateNamespacesCmd
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


class CapaMatchData:
    def __init__(
        self, namespace, scope, capability, locations, node, attack: List[Dict[Any, Any]], mbc: List[Dict[Any, Any]]
    ):
        self.namespace = namespace
        self.scope = scope
        self.capability = capability
        self.locations = locations
        self.node = node
        self.attack = attack
        self.mbc = mbc

    def recurse_node(self, node_dict):
        """pull match descriptions by recursing node dicts"""

        if not node_dict:
            # mismatched key, skip
            # ex. {'type':'subscope', 'scope':'basic block'}
            return ""

        if isinstance(node_dict, int):
            # Number operands, usually parameters or immediates
            # {'type':'number', 'number':80}
            # hex() will cast this int to a str type
            return hex(node_dict)

        if isinstance(node_dict, str):
            # expect the "description" key's string value
            # {'description':'PEB->OSMajorVersion'}
            return node_dict

        if "description" in node_dict:
            return node_dict.get("description")
        else:
            # if no "description" key, the "type" key's value is the
            # expected key.
            # ex. {'type':'api', 'api':'RegisterServiceCtrlHandler'}
            return self.recurse_node(node_dict.get(node_dict.get("type")))

    def create_namespace(self):
        """create new ghidra namespace for each capa namespace"""

        cmd = CreateNamespacesCmd(self.namespace, SourceType.USER_DEFINED)
        cmd.applyTo(currentProgram())  # type: ignore [name-defined] # noqa: F821
        return cmd.getNamespace()

    def tag_functions(self):
        """create function tags for capabilities"""

        # self.locations[0] will always be the largest
        # scoped offset yielded i.e. closest to an entrypoint
        addr = toAddr(hex(self.locations[0]))  # type: ignore [name-defined] # noqa: F821
        func = getFunctionContaining(addr)  # type: ignore [name-defined] # noqa: F821

        # bookmark Mitre ATT&CK tactics & MBC @ function scope
        if func:
            func.addTag(self.capability)
            for item in self.attack:
                attack_txt = item.get("tactic") + Namespace.DELIMITER + item.get("id")
                add_bookmark(addr, attack_txt, "CapaExplorer::Mitre ATT&CK")

            for item in self.mbc:
                mbc_txt = item.get("objective") + Namespace.DELIMITER + item.get("id")
                add_bookmark(addr, mbc_txt, "CapaExplorer::MBC")

    def bookmark_locations(self):
        """bookmark & label findings at all scopes"""
        symbol_table = currentProgram().getSymbolTable()  # type: ignore [name-defined] # noqa: F821
        name_space = self.create_namespace()

        for addr in self.locations:
            label_name = self.capability.replace(" ", "-")
            ghidra_addr = toAddr(hex(addr))  # type: ignore [name-defined] # noqa: F821

            add_bookmark(ghidra_addr, label_name)

            # avoid renaming user-defined functions
            # to namespace/rule names, since they
            # may contain matches for many rules at this scope
            is_function = False
            for sym in symbol_table.getSymbols(ghidra_addr):
                if sym.getSymbolType() == SymbolType.FUNCTION:
                    is_function = True
                    label_name = sym.getName()
                    # label to classify function under capa-generated namespace
                    createLabel(ghidra_addr, label_name, name_space, True, SourceType.USER_DEFINED)  # type: ignore [name-defined] # noqa: F821

            if is_function:
                # skip re-labelling a function
                continue

            # greedily create labels at basic block & insn scopes
            node_to_parse = self.node[self.locations.index(addr)]
            if node_to_parse:
                label_name = self.recurse_node(node_to_parse)

                if not label_name:
                    continue

                label_name = label_name.replace(" ", "-")
                createLabel(ghidra_addr, label_name, name_space, True, SourceType.USER_DEFINED)  # type: ignore [name-defined] # noqa: F821
                continue

            # handle first address of match
            createLabel(ghidra_addr, label_name, name_space, True, SourceType.USER_DEFINED)  # type: ignore [name-defined] # noqa: F821


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

    rules = capa_data["rules"]
    for rule in capa_data.get("rules", {}).keys():
        # loosely coupled location & node data lists
        this_locs = []
        this_node: List[Dict] = []

        # dict data of currently matched rule
        this_capability = rules[rule]
        meta = this_capability["meta"]

        # get Mitre ATT&CK and MBC
        # avoid passing NoneTypes
        this_attack = meta.get("attack")
        if not this_attack:
            this_attack = []
        this_mbc = meta.get("mbc")
        if not this_mbc:
            this_mbc = []

        # scope match for the rule
        this_scope = meta["scopes"].get("static")
        with suppress(KeyError):
            # always grab first location of match
            this_locs.append(this_capability["matches"][0][0]["value"])
            # align node data
            this_node.append({})

        if "namespace" in meta:
            # split into list to help define child namespaces
            # this requires the correct delimiter used by Ghidra
            # Ex. 'communication/named-pipe/create' -> capa::communication::named-pipe::create
            namespace_str = Namespace.DELIMITER.join(meta["namespace"].split("/"))
            this_namespace = "capa" + Namespace.DELIMITER + namespace_str
            # lib rules via the official rules repo will not contain data
            # for the "namespaces" key, so format using rule itself
        else:
            lib_str = "capa" + Namespace.DELIMITER + "lib" + Namespace.DELIMITER
            this_namespace = lib_str + rule.replace(" ", "-")

        # recurse to find all locations
        # grab second dict, containing additional matches
        # and node data
        matches = this_capability["matches"][0][1]
        for m in get_locations(matches):
            this_locs.append(m[0])
            this_node.append(m[1])

        yield CapaMatchData(this_namespace, this_scope, rule, this_locs, this_node, this_attack, this_mbc)


def main():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    if isRunningHeadless():  # type: ignore [name-defined] # noqa: F821
        logger.error("unsupported ghidra execution mode")
        return capa.main.E_UNSUPPORTED_GHIDRA_EXECUTION_MODE

    if not capa.ghidra.helpers.is_supported_ghidra_version():
        logger.error("unsupported ghidra version")
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
    if not capa_data.get("rules"):
        logger.info("capa explorer found no matches")
        popup("capa explorer found no matches.")  # type: ignore [name-defined] # noqa: F821
        return capa.main.E_EMPTY_REPORT

    for item in parse_json(capa_data):
        item.tag_functions()
        item.bookmark_locations()
    logger.info("capa explorer analysis complete")
    popup("""capa explorer analysis complete.\nPlease see results in the Bookmarks and Namespaces section of the Symbol Tree Window.""")  # type: ignore [name-defined] # noqa: F821
    return 0


if __name__ == "__main__":
    if sys.version_info < (3, 8):
        from capa.exceptions import UnsupportedRuntimeError

        raise UnsupportedRuntimeError("This version of capa can only be used with Python 3.8+")
    exit_code = main()
    if exit_code != 0:
        popup("Capa Explorer encountered errors during analysis. Please check the console output for more information.")  # type: ignore [name-defined] # noqa: F821
    sys.exit(exit_code)
