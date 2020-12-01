#!/usr/bin/env python3

import json

import capa.main
import capa.rules
import capa.engine
import capa.features
from capa.engine import *

# edit this to set the path for file to analyze and rule directory
SAMPLE_PATH = "path/to/file"
RULES_PATH = "/tmp/capa/rules/"

# load rules from disk
rules = capa.main.get_rules(RULES_PATH, disable_progress=True)
rules = capa.rules.RuleSet(rules)

# extract features and find capabilities
extractor = capa.main.get_extractor(SAMPLE_PATH, "auto", disable_progress=True)
capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)

# collect metadata (used only to make rendering more complete)
meta = capa.main.collect_metadata("", SAMPLE_PATH, RULES_PATH, "auto", extractor)
meta["analysis"].update(counts)

# render results
# ...as json
capa_json = json.loads(capa.render.render_json(meta, rules, capabilities))
# ...as human readable text table
capa_texttable = capa.render.render_default(meta, rules, capabilities)
