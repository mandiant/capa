# Copyright 2023 Google LLC
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

"""
Create a cache of the given rules.
This is only really intended to be used by CI to pre-cache rulesets
that will be distributed within PyInstaller binaries.

Usage:

   $ python scripts/cache-ruleset.py rules/ /path/to/cache/directory
"""

import sys
import logging
import argparse
from pathlib import Path

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
    parser.add_argument("rules", type=str, help="Path to rules directory")
    parser.add_argument("cache", type=str, help="Path to cache directory")
    args = parser.parse_args(args=argv)

    # don't use capa.main.handle_common_args
    # because it expects a different format for the --rules argument

    if args.quiet:
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    try:
        cache_dir = Path(args.cache)
        cache_dir.mkdir(parents=True, exist_ok=True)
        rules = capa.rules.get_rules([Path(args.rules)], cache_dir)
        logger.info("successfully loaded %s rules", len(rules))
    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        logger.error("%s", str(e))
        return -1

    content = capa.rules.cache.get_ruleset_content(rules)
    id = capa.rules.cache.compute_cache_identifier(content)
    path = capa.rules.cache.get_cache_path(cache_dir, id)

    assert path.exists()
    logger.info("cached to: %s", path)


if __name__ == "__main__":
    sys.exit(main())
