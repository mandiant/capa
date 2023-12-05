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
from typing import Dict, List
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

# Ghidra helpers

def add_bookmark(addr, txt, category="CapaExplorer"):
    """create bookmark at addr"""
    currentProgram().getBookmarkManager().setBookmark(addr, "Info", category, txt)  # type: ignore [name-defined] # noqa: F821


class CapaMatchData:
    def __init__(self, namespace, scope, capability, locations, node, attack={}):
        self.namespace = namespace
        self.scope = scope
        self.capability = capability
        self.locations = locations
        self.node = node
        self.attack = attack

    def recurse_node(self, node_dict):
        """pull match descriptions by recursing node dicts"""

        if not node_dict:
            # KeyError
            # ex. {'type':'subscope', 'scope':'basic block'}
            return ""

        if isinstance(node_dict, int):
            node_dict = hex(node_dict)

        if isinstance(node_dict, str):
            return node_dict

        if "description" in node_dict:
            return node_dict.get("description")
        else:
            return self.recurse_node(node_dict.get(node_dict.get("type")))

    def create_namespace(self):
        """create new ghidra namespace for each capa namespace"""

        # handle rules w/o namespace -> capa lib rule
        if self.namespace == "capa":
            lib_str = Namespace.DELIMITER + "lib" + Namespace.DELIMITER
            self.namespace = self.namespace + lib_str + self.capability.replace(" ", "-")
        cmd = CreateNamespacesCmd(self.namespace, SourceType.USER_DEFINED)
        cmd.applyTo(currentProgram())  # type: ignore [name-defined] # noqa: F821

        return cmd.getNamespace()

#    def add_bookmark(self, addr, txt, category="CapaExplorer"):
#        """create bookmark at addr"""
#        currentProgram().getBookmarkManager().setBookmark(addr, "Info", category, txt)  # type: ignore [name-defined] # noqa: F821

    def tag_functions(self):
        """create function tags for capabilities"""

        # self.locations[0] will always be the largest
        # scoped offset yielded i.e. closest to an entrypoint
        addr = toAddr(hex(self.locations[0]))  # type: ignore [name-defined] # noqa: F821
        func = getFunctionContaining(addr)  # type: ignore [name-defined] # noqa: F821

        # bookmark Mitre ATT&CK tactics @ function scope
        if func:
            func.addTag(self.capability)
            for item in self.attack:
                attack_txt = item.get("tactic") + Namespace.DELIMITER + item.get("id")
                add_bookmark(addr, attack_txt, "CapaExplorer::Mitre ATT&CK")

    def bookmark_locations(self):
        """bookmark & label findings at all scopes"""
        symbol_table = currentProgram().getSymbolTable()  # type: ignore [name-defined] # noqa: F821
        name_space = self.create_namespace()

        for addr in self.locations:
            txt = self.capability.replace(" ", "-")
            a = toAddr(hex(addr))  # type: ignore [name-defined] # noqa: F821

            add_bookmark(a, txt)

            # avoid re-naming functions
            # to namespace/rule names
            to_cont = False
            for sym in symbol_table.getSymbols(a):
                if sym.getSymbolType() == SymbolType.FUNCTION:
                    to_cont = True
                    txt = sym.getName()
                    # label to classify function under capa-generated namespace
                    createLabel(a, txt, name_space, True, SourceType.USER_DEFINED)  # type: ignore [name-defined] # noqa: F821

            if to_cont:
                continue

            # greedily create labels at basic block & insn scopes
            node_to_parse = self.node[self.locations.index(addr)]
            if node_to_parse:
                txt = self.recurse_node(node_to_parse)

                if not txt:
                    continue

                txt = txt.replace(" ", "-")
                createLabel(a, txt, name_space, True, SourceType.USER_DEFINED)  # type: ignore [name-defined] # noqa: F821
                continue

            # handle first address of match
            createLabel(a, txt, name_space, True, SourceType.USER_DEFINED)  # type: ignore [name-defined] # noqa: F821


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
        return capa.main.E_MISSING_RULES

    rules_path: pathlib.Path = pathlib.Path(rules_dir)
    logger.info("running capa using rules from %s", str(rules_path))

    rules = capa.main.get_rules([rules_path])
    meta = capa.ghidra.helpers.collect_metadata([rules_path])
    extractor = capa.features.extractors.ghidra.extractor.GhidraFeatureExtractor()

    capabilities, counts = capa.main.find_capabilities(rules, extractor, True)

    if capa.main.has_file_limitation(rules, capabilities, is_standalone=False):
        logger.info("capa encountered warnings during analysis")

    return capa.render.json.render(meta, rules, capabilities)


def get_locations(match_dict):
    """recursively collect match addresses and associated nodes"""
    if "locations" in match_dict:
        for loc in match_dict.get("locations", {}):
            if "type" in loc:
                # either an rva (absolute)
                # or an offset into a file (file)
                if loc.get("type", "") in ("absolute", "file"):
                    yield loc.get("value"), match_dict.get("node")

    if match_dict["children"]:
        for child in match_dict.get("children", {}):
            yield from get_locations(child)


def parse_json(capa_data):
    """Parse json produced by capa"""
    ghidra_data = []

    rules = capa_data["rules"]
    for rule in rules.keys():
        # loosely coupled location & node data lists
        this_locs = []
        this_node: List[Dict] = []

        # dict data of currently matched rule
        this_capability = rules[rule]
        meta = this_capability["meta"]

        # return MITRE ATT&CK or None
        this_attack = meta.get("attack")

        # scope match for the rule
        this_scope = meta["scopes"].get("static")
        with suppress(KeyError):
            # always grab first location of match
            this_locs.append(this_capability["matches"][0][0]["value"])
            # align node data
            this_node.append({})

        if "namespace" in meta:
            # split into list to help define child namespaces
            # in ghidra
            namespace_str = Namespace.DELIMITER.join(meta["namespace"].split("/"))
            this_namespace = "capa" + Namespace.DELIMITER + namespace_str
        else:
            this_namespace = "capa"

        # recurse to find all locations
        # grab second dict, containing additional matches
        # and node data
        matches = this_capability["matches"][0][1]
        for m in get_locations(matches):
            this_locs.append(m[0])
            this_node.append(m[1])

        ghidra_data.append(CapaMatchData(this_namespace, this_scope, rule, this_locs, this_node, this_attack))

    return ghidra_data


def main():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    if not capa.ghidra.helpers.is_supported_ghidra_version():
        return capa.main.E_UNSUPPORTED_GHIDRA_VERSION

    if not capa.ghidra.helpers.is_supported_file_type():
        return capa.main.E_INVALID_FILE_TYPE

    if not capa.ghidra.helpers.is_supported_arch_type():
        return capa.main.E_INVALID_FILE_ARCH

    if not isRunningHeadless():  # type: ignore [name-defined] # noqa: F821
        capa_data = json.loads(get_capabilities())
        for item in parse_json(capa_data):
            item.tag_functions()
            item.bookmark_locations()
    return 0


if __name__ == "__main__":
    if sys.version_info < (3, 8):
        from capa.exceptions import UnsupportedRuntimeError

        raise UnsupportedRuntimeError("This version of capa can only be used with Python 3.8+")
    sys.exit(main())
