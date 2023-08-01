# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import textwrap
import contextlib

import capa.rules
import capa.rules.cache

R1 = capa.rules.Rule.from_yaml(
    textwrap.dedent(
        """
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
    """
    )
)

R2 = capa.rules.Rule.from_yaml(
    textwrap.dedent(
        """
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
    """
    )
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
