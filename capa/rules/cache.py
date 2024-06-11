# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import os
import sys
import zlib
import pickle
import hashlib
import logging
from typing import List, Optional
from pathlib import Path
from dataclasses import dataclass

import capa.rules
import capa.helpers
import capa.version

logger = logging.getLogger(__name__)


# TypeAlias. note: using `foo: TypeAlias = bar` is Python 3.10+
CacheIdentifier = str


def compute_cache_identifier(rule_content: List[bytes]) -> CacheIdentifier:
    hash = hashlib.sha256()

    # note that this changes with each release,
    # so cache identifiers will never collide across releases.
    version = capa.version.__version__

    hash.update(version.encode("utf-8"))
    hash.update(b"\x00")

    rule_hashes = sorted([hashlib.sha256(buf).hexdigest() for buf in rule_content])
    for rule_hash in rule_hashes:
        hash.update(rule_hash.encode("ascii"))
        hash.update(b"\x00")

    return hash.hexdigest()


def get_default_cache_directory() -> Path:
    # ref: https://github.com/mandiant/capa/issues/1212#issuecomment-1361259813
    #
    # Linux:   $XDG_CACHE_HOME/capa/
    # Windows: %LOCALAPPDATA%\flare\capa\cache
    # MacOS:   ~/Library/Caches/capa

    # ref: https://stackoverflow.com/a/8220141/87207
    if sys.platform == "linux" or sys.platform == "linux2":
        directory = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache" / "capa"))
    elif sys.platform == "darwin":
        directory = Path.home() / "Library" / "Caches" / "capa"
    elif sys.platform == "win32":
        directory = Path(os.environ["LOCALAPPDATA"]) / "flare" / "capa" / "cache"
    else:
        raise NotImplementedError(f"unsupported platform: {sys.platform}")

    directory.mkdir(parents=True, exist_ok=True)

    return directory


def get_cache_path(cache_dir: Path, id: CacheIdentifier) -> Path:
    filename = "capa-" + id[:8] + ".cache"
    return cache_dir / filename


MAGIC = b"capa"
VERSION = b"\x00\x00\x00\x01"


@dataclass
class RuleCache:
    id: CacheIdentifier
    ruleset: capa.rules.RuleSet

    def dump(self):
        return MAGIC + VERSION + self.id.encode("ascii") + zlib.compress(pickle.dumps(self))

    @staticmethod
    def load(data):
        assert data.startswith(MAGIC + VERSION)

        id = data[0x8:0x48].decode("ascii")
        cache = pickle.loads(zlib.decompress(data[0x48:]))

        assert isinstance(cache, RuleCache)
        assert cache.id == id

        return cache


def get_ruleset_content(ruleset: capa.rules.RuleSet) -> List[bytes]:
    rule_contents = []
    for rule in ruleset.rules.values():
        if rule.is_subscope_rule():
            continue
        rule_contents.append(rule.definition.encode("utf-8"))
    return rule_contents


def compute_ruleset_cache_identifier(ruleset: capa.rules.RuleSet) -> CacheIdentifier:
    rule_contents = get_ruleset_content(ruleset)
    return compute_cache_identifier(rule_contents)


def cache_ruleset(cache_dir: Path, ruleset: capa.rules.RuleSet):
    """
    cache the given ruleset to disk, using the given cache directory.
    this can subsequently be reloaded via `load_cached_ruleset`,
    assuming the capa version and rule content does not change.

    callers should use this function to avoid the performance overhead
    of validating rules on each run.
    """
    id = compute_ruleset_cache_identifier(ruleset)
    path = get_cache_path(cache_dir, id)
    if path.exists():
        logger.debug("rule set already cached to %s", path)
        return

    cache = RuleCache(id, ruleset)
    path.write_bytes(cache.dump())

    logger.debug("rule set cached to %s", path)
    return


def load_cached_ruleset(cache_dir: Path, rule_contents: List[bytes]) -> Optional[capa.rules.RuleSet]:
    """
    load a cached ruleset from disk, using the given cache directory.
    the raw rule contents are required here to prove that the rules haven't changed
    and to avoid stale cache entries.

    callers should use this function to avoid the performance overhead
    of validating rules on each run.
    """
    id = compute_cache_identifier(rule_contents)
    path = get_cache_path(cache_dir, id)
    if not path.exists():
        logger.debug("rule set cache does not exist: %s", path)
        return None

    logger.debug("loading rule set from cache: %s", path)
    buf = path.read_bytes()

    try:
        cache = RuleCache.load(buf)
    except AssertionError:
        logger.debug("rule set cache is invalid: %s", path)
        # delete the cache that seems to be invalid.
        path.unlink()
        return None
    else:
        return cache.ruleset


def generate_rule_cache(rules_dir: Path, cache_dir: Path) -> bool:
    if not rules_dir.is_dir():
        logger.error("rules directory %s does not exist", rules_dir)
        return False

    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        rules = capa.rules.get_rules([rules_dir], cache_dir)
    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        logger.error("%s", str(e))
        return False

    content = capa.rules.cache.get_ruleset_content(rules)
    id = capa.rules.cache.compute_cache_identifier(content)
    path = capa.rules.cache.get_cache_path(cache_dir, id)

    assert path.exists()
    logger.info("rules cache saved to: %s", path)

    return True
