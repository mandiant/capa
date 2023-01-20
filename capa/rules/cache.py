import sys
import pickle
import hashlib
import logging
import os.path
from typing import List, Optional
from dataclasses import dataclass

import capa.rules

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

    rule_hashes = list(sorted([hashlib.sha256(rule).hexdigest() for rule in rule_content]))
    for rule_hash in rule_hashes:
        hash.update(rule_hash.encode("ascii"))
        hash.update(b"\x00")

    return hash.hexdigest()


def get_default_cache_directory() -> str:
    # ref: https://github.com/mandiant/capa/issues/1212#issuecomment-1361259813
    #
    # Linux:   $XDG_CACHE_HOME/capa/
    # Windows: %LOCALAPPDATA%\flare\capa\cache
    # MacOS:   ~/Library/Caches/capa

    # ref: https://stackoverflow.com/a/8220141/87207
    if sys.platform == "linux" or sys.platform == "linux2":
        directory = os.environ.get("XDG_CACHE_HOME", os.path.join(os.environ["HOME"], ".cache", "capa"))
    elif sys.platform == "darwin":
        directory = os.path.join(os.environ["HOME"], "Library", "Caches", "capa")
    elif sys.platform == "win32":
        directory = os.path.join(os.environ["LOCALAPPDATA"], "flare", "capa", "cache")
    else:
        raise NotImplementedError(f"unsupported platform: {sys.platform}")

    os.makedirs(directory, exist_ok=True)

    return directory


def get_default_cache_path(id: CacheIdentifier) -> str:
    filename = "capa-" + id[:8] + ".cache"
    return os.path.join(get_default_cache_directory(), filename)


MAGIC = b"capa"
VERSION = b"\x00\x00\x00\x01"


@dataclass
class RuleCache:
    id: CacheIdentifier
    ruleset: capa.rules.RuleSet

    def dump(self):
        return MAGIC + VERSION + self.id.encode("ascii") + pickle.dumps(self)

    @staticmethod
    def load(data):
        assert data.startswith(MAGIC + VERSION)

        id = data[0x8:0x48].decode("ascii")
        cache = pickle.loads(data[0x48:])

        assert isinstance(cache, RuleCache)
        assert cache.id == id

        return cache


def cache_ruleset(ruleset: capa.rules.RuleSet):
    rule_contents = []
    for rule in ruleset.rules.values():
        if rule.is_subscope_rule():
            continue
        with open(rule.meta["capa/path"], "rb") as f:
            rule_contents.append(f.read())

    id = compute_cache_identifier(rule_contents)
    path = get_default_cache_path(id)
    if os.path.exists(path):
        logger.debug("rule set already cached to %s", path)
        return

    cache = RuleCache(id, ruleset)
    with open(path, "wb") as f:
        f.write(cache.dump())

    logger.debug("rule set cached to %s", path)
    return


def load_cached_ruleset(rule_contents: List[bytes]) -> Optional[capa.rules.RuleSet]:
    id = compute_cache_identifier(rule_contents)
    path = get_default_cache_path(id)
    if not os.path.exists(path):
        logger.debug("rule set cache does not exist: %s", path)
        return None

    logger.debug("loading rule set from cache: %s", path)
    with open(path, "rb") as f:
        buf = f.read()
        cache = RuleCache.load(buf)
        return cache.ruleset
