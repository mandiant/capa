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

import capa
import capa.main
import capa.rules
import capa.render.json
import capa.ghidra.helpers
import capa.features.extractors.ghidra.extractor

logger = logging.getLogger("capa_ghidra")

class CAPADATA:
    def __init__(self, namespace, scope, capability, match, label_list, attack=None):
        self.namesapce = namespace
        self.scope = scope 
        self.capability = capability 
        self.match = match 
        self.label_list = label_list 
        self.attack = attack


def get_capabilities():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

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
    

def get_locations(match):
    """recursively collect data from matches"""

    if "locations" in match.keys():
        if len(match['locations']) != 0:
            for loc in match['locations']:
                yield loc['value']

    if len(match['children']) != 0:
        for child in match['children']:
            return get_locations(child)
    else:
        return []


def parse_json(capa_data):
    # for key in capa_data['rules'].keys() -> key == rule name
    #   key['meta']['namespace'] -> capa namespace to add to ghidra namespace
    #       key['matches'][0][0]['value'] -> first offset
    #       key['matches'][0][1] // recursively hop down ['children'] key, collect locations & node data
    # capa_data[]
    ghidra_data = []

    rules = capa_data['rules']
    for rule in rules.keys():

        # dict data of currently matched rule
        this_capability = rules[rule]
        meta = this_capability['meta']

        # scope match for the rule
        this_scope = meta['scope']
        this_locs = []
        this_locs.append(this_capability['matches'][0][0]['value'])

        if 'namespace' in meta.keys():
            # split into list to help define child namespaces
            # in ghidra
            this_namespace = meta['namespace'].split('/')
        else:
            this_namespace = [""]

        # recurse to find all locations
        matches = this_capability['matches'][0][1]
        try:
            if len(matches['locations']) == 0:
                for match in matches['children']:
                    for loc in get_locations(match):
                        this_locs.append(loc) 
            else:
                for loc in matches['locations']:
                    this_locs.append(loc['value'])  
        except KeyError:
            pass


def main():
    if not capa.ghidra.helpers.is_supported_ghidra_version():
        return capa.main.E_UNSUPPORTED_GHIDRA_VERSION

    if not capa.ghidra.helpers.is_supported_file_type():
        return capa.main.E_INVALID_FILE_TYPE

    if not capa.ghidra.helpers.is_supported_arch_type():
        return capa.main.E_INVALID_FILE_ARCH

    if isRunningHeadless():  # type: ignore [name-defined] # noqa: F821
        return
    else:
        capa_data = json.loads(get_capabilities())
        return parse_json(capa_data)


if __name__ == "__main__":
    if sys.version_info < (3, 8):
        from capa.exceptions import UnsupportedRuntimeError

        raise UnsupportedRuntimeError("This version of capa can only be used with Python 3.8+")
    sys.exit(main())
