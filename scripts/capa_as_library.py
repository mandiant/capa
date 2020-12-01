#!/usr/bin/env python3

import json
import capa.main
import capa.rules
import capa.engine
import capa.features
from capa.engine import *

sample_path = "path/to/file"

capa.main.RULES_PATH_DEFAULT_STRING = "/tmp/capa/rules/"
rules = capa.main.get_rules(capa.main.RULES_PATH_DEFAULT_STRING, disable_progress=True)
rules = capa.rules.RuleSet(rules)

extractor = capa.main.get_extractor(sample_path, "auto", disable_progress=True)
meta = capa.main.collect_metadata("", sample_path,capa.main.RULES_PATH_DEFAULT_STRING, "auto", extractor)
capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)
meta["analysis"].update(counts)

capa_json = json.loads(capa.render.render_json(meta, rules, capabilities))
capa_texttable = capa.render.render_default(meta, rules, capabilities)
