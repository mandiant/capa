"""
Create a cache of the given rules.
This is only really intended to be used by CI to pre-cache rulesets 
that will be distributed within PyInstaller binaries.

Usage:

   $ python scripts/cache-ruleset.py rules/ /path/to/cache/directory

Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
import os
import sys
import time
import logging
import argparse

import capa.main
import capa.rules
import capa.engine
import capa.helpers
import capa.rules.cache
import capa.features.insn

logger = logging.getLogger("cache-ruleset")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Cache ruleset.")
    capa.main.install_common_args(parser)
    parser.add_argument("rules", type=str, action="append", help="Path to rules")
    parser.add_argument("cache", type=str, help="Path to cache directory")
    args = parser.parse_args(args=argv)
    capa.main.handle_common_args(args)

    if args.debug:
        logging.getLogger("capa").setLevel(logging.DEBUG)
    else:
        logging.getLogger("capa").setLevel(logging.ERROR)

    try:
        os.makedirs(args.cache, exist_ok=True)
        rules = capa.main.get_rules(args.rules, cache_dir=args.cache)
        logger.info("successfully loaded %s rules", len(rules))
    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        logger.error("%s", str(e))
        return -1

    content = capa.rules.cache.get_ruleset_content(rules)
    id = capa.rules.cache.compute_cache_identifier(content)
    path = capa.rules.cache.get_cache_path(args.cache, id)

    assert os.path.exists(path)
    logger.info("cached to: %s", path)


if __name__ == "__main__":
    sys.exit(main())
