# Copyright 2020 Google LLC
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


import textwrap

import capa.rules

EXPECTED = textwrap.dedent(
    """\
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


def test_rule_reformat_top_level_elements():
    rule = textwrap.dedent(
        """
        rule:
          features:
            - and:
              - number: 1
              - number: 2
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
        """
    )

    assert capa.rules.Rule.from_yaml(rule).to_yaml() == EXPECTED


def test_rule_reformat_indentation():
    rule = textwrap.dedent(
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

    assert capa.rules.Rule.from_yaml(rule).to_yaml() == EXPECTED


def test_rule_reformat_order():
    rule = textwrap.dedent(
        """
        rule:
          meta:
            authors:
              - user@domain.com
            examples:
              - foo1234
              - bar5678
            scopes:
              static: function
              dynamic: process
            name: test rule
          features:
            - and:
              - number: 1
              - number: 2
        """
    )

    assert capa.rules.Rule.from_yaml(rule).to_yaml() == EXPECTED


def test_rule_reformat_meta_update():
    # test updating the rule content after parsing

    src = textwrap.dedent(
        """
        rule:
          meta:
            authors:
              - user@domain.com
            examples:
              - foo1234
              - bar5678
            scopes:
              static: function
              dynamic: process
            name: AAAA
          features:
            - and:
              - number: 1
              - number: 2
        """
    )

    rule = capa.rules.Rule.from_yaml(src)
    rule.name = "test rule"
    assert rule.to_yaml() == EXPECTED


def test_rule_reformat_string_description():
    # the `description` should be aligned with the preceding feature name.
    # see #263
    src = textwrap.dedent(
        """
        rule:
          meta:
            name: test rule
            authors:
              - user@domain.com
            scopes:
              static: function
              dynamic: process
          features:
            - and:
              - string: foo
                description: bar
        """
    ).lstrip()

    rule = capa.rules.Rule.from_yaml(src)
    assert rule.to_yaml() == src
