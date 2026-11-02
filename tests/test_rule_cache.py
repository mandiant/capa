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


import os
import textwrap
import contextlib
from types import SimpleNamespace
from pathlib import Path

import pytest

import capa.main
import capa.rules
import capa.helpers
import capa.rules.cache

R1 = capa.rules.Rule.from_yaml(
    textwrap.dedent("""
    rule:
        meta:
            name: test rule
            authors:
                - user@domain.com
            scopes:
                static: function
                dynamic: process
            examples:
                - foo1234
                - bar5678
        features:
            - and:
                - number: 1
                - number: 2
    """)
)

R2 = capa.rules.Rule.from_yaml(
    textwrap.dedent("""
    rule:
        meta:
            name: test rule 2
            authors:
                - user@domain.com
            scopes:
                static: function
                dynamic: process
            examples:
                - foo1234
                - bar5678
        features:
            - and:
                - number: 3
                - number: 4
    """)
)


def test_ruleset_cache_ids():
    rs = capa.rules.RuleSet([R1])
    content = capa.rules.cache.get_ruleset_content(rs)

    rs2 = capa.rules.RuleSet([R1, R2])
    content2 = capa.rules.cache.get_ruleset_content(rs2)

    id = capa.rules.cache.compute_cache_identifier(content)
    id2 = capa.rules.cache.compute_cache_identifier(content2)
    assert id != id2


def test_ruleset_cache_save_load():
    rs = capa.rules.RuleSet([R1])
    content = capa.rules.cache.get_ruleset_content(rs)

    id = capa.rules.cache.compute_cache_identifier(content)
    assert id is not None

    cache_dir = capa.rules.cache.get_default_cache_directory()

    path = capa.rules.cache.get_cache_path(cache_dir, id)
    with contextlib.suppress(OSError):
        path.unlink()

    capa.rules.cache.cache_ruleset(cache_dir, rs)
    assert path.exists()

    assert capa.rules.cache.load_cached_ruleset(cache_dir, content) is not None


def test_ruleset_cache_invalid():
    rs = capa.rules.RuleSet([R1])
    content = capa.rules.cache.get_ruleset_content(rs)
    id = capa.rules.cache.compute_cache_identifier(content)
    cache_dir = capa.rules.cache.get_default_cache_directory()
    path = capa.rules.cache.get_cache_path(cache_dir, id)
    with contextlib.suppress(OSError):
        path.unlink()

    capa.rules.cache.cache_ruleset(cache_dir, rs)
    assert path.exists()

    buf = path.read_bytes()

    # corrupt the magic header
    buf = b"x" + buf[1:]

    # write the modified contents back to the file
    path.write_bytes(buf)

    # check if the file still exists
    assert path.exists()
    assert capa.rules.cache.load_cached_ruleset(cache_dir, content) is None
    # the invalid cache should be deleted
    assert not path.exists()


def test_rule_cache_dev_environment():
    # generate rules cache
    rs = capa.rules.RuleSet([R2])
    content = capa.rules.cache.get_ruleset_content(rs)
    id = capa.rules.cache.compute_cache_identifier(content)
    cache_dir = capa.rules.cache.get_default_cache_directory()
    cache_path = capa.rules.cache.get_cache_path(cache_dir, id)

    # clear existing cache files
    for f in cache_dir.glob("*.cache"):
        f.unlink()

    capa.rules.cache.cache_ruleset(cache_dir, rs)
    assert cache_path.exists()

    assert capa.helpers.is_cache_newer_than_rule_code(cache_dir) is True

    capa_root = Path(__file__).resolve().parent.parent
    cachepy = capa_root / "capa" / "rules" / "cache.py"  # alternative: capa_root / "capa" / "rules" / "__init__.py"

    # set cache's last modified time prior to code file's modified time
    os.utime(cache_path, (cache_path.stat().st_atime, cachepy.stat().st_mtime - 600000))

    # debug
    def ts_to_str(ts):
        from datetime import datetime

        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    for g in ((capa_root / "capa" / "rules").glob("*.py"), cache_dir.glob("*.cache")):
        for p in g:
            print(p, "\t", ts_to_str(p.stat().st_mtime))  # noqa: T201

    assert capa.helpers.is_dev_environment() is True
    assert capa.helpers.is_cache_newer_than_rule_code(cache_dir) is False


@pytest.mark.parametrize("relocate_checkout", [False, True])
@pytest.mark.parametrize("subscope", [False, True])
def test_cached_rule_locations_follow_current_files(tmp_path, monkeypatch, relocate_checkout, subscope):
    checkout = tmp_path / "checkout-a"
    source = checkout / "nursery" / "rule.yml"
    source.parent.mkdir(parents=True)
    features = "- and:\n  - basic block:\n    - number: 1\n  - number: 2" if subscope else "- number: 1"
    definition = textwrap.dedent(
        """\
        rule:
          meta:
            name: cache location test
            scopes:
              static: function
              dynamic: unsupported
          features:
        """
    ) + textwrap.indent(features, "    ") + "\n"
    source.write_text(definition, encoding="utf-8")
    cache = tmp_path / "cache"
    cache.mkdir()
    initial = capa.rules.get_rules([checkout], cache_dir=cache)
    assert initial.rules["cache location test"].meta["capa/nursery"] is True

    target_checkout = tmp_path / "checkout-b" if relocate_checkout else checkout
    target = target_checkout / "anti-analysis" / "rule.yml"
    target.parent.mkdir(parents=True)
    if relocate_checkout:
        target.write_bytes(source.read_bytes())
    else:
        source.rename(target)

    def unexpected_parse(*args, **kwargs):
        pytest.fail("the content-identical ruleset should be loaded from cache")

    monkeypatch.setattr(capa.rules.Rule, "from_yaml", unexpected_parse)
    loaded = capa.rules.get_rules([target_checkout], cache_dir=cache)
    assert loaded.rules["cache location test"].meta["capa/path"] == target.as_posix()
    assert loaded.rules["cache location test"].meta["capa/nursery"] is False


@pytest.mark.parametrize("development", [False, True])
@pytest.mark.parametrize("enabled", [False, True])
def test_cli_respects_explicit_cache_setting(tmp_path, monkeypatch, development, enabled):
    monkeypatch.setattr(capa.helpers, "is_running_standalone", lambda: False)
    monkeypatch.setattr(capa.helpers, "is_dev_environment", lambda: development)
    monkeypatch.setattr(capa.helpers, "is_cache_newer_than_rule_code", lambda directory: True)
    monkeypatch.setattr(capa.rules.cache, "get_default_cache_directory", lambda: tmp_path)
    requested = []

    def get_rules(paths, **kwargs):
        requested.append(kwargs["enable_cache"])
        return SimpleNamespace(rules={})

    monkeypatch.setattr(capa.rules, "get_rules", get_rules)
    args = SimpleNamespace(rules=[], is_default_rules=False, enable_cache=enabled)
    capa.main.get_rules_from_cli(args)
    assert requested == [enabled]
