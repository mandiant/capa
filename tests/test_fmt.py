import textwrap

import capa.rules

EXPECTED = textwrap.dedent('''\
   rule:
     meta:
       name: test rule
       author: user@domain.com
       scope: function
       examples:
         - foo1234
         - bar5678
     features:
       - and:
         - number: 1
         - number: 2
''')


def test_rule_reformat_top_level_elements():
    rule = textwrap.dedent('''\
        rule:
          features:
            - and:
              - number: 1
              - number: 2
          meta:
            name: test rule
            author: user@domain.com
            scope: function
            examples:
              - foo1234
              - bar5678''')

    assert capa.rules.Rule.from_yaml(rule).to_yaml() == EXPECTED


def test_rule_reformat_indentation():
    rule = textwrap.dedent('''\
        rule:
         meta:
            name: test rule
            author: user@domain.com
            scope: function
            examples:
            - foo1234
            - bar5678
         features:
                - and:
                             - number: 1
                             - number: 2''')

    assert capa.rules.Rule.from_yaml(rule).to_yaml() == EXPECTED


def test_rule_reformat_order():
    rule = textwrap.dedent('''\
         rule:
           meta:
             author: user@domain.com
             examples:
               - foo1234
               - bar5678
             scope: function
             name: test rule
           features:
             - and:
               - number: 1
               - number: 2''')

    assert capa.rules.Rule.from_yaml(rule).to_yaml() == EXPECTED


def test_rule_reformat_meta_update():
    rule = textwrap.dedent('''\
         rule:
           meta:
             author: user@domain.com
             examples:
               - foo1234
               - bar5678
             scope: function
             name: AAAA
           features:
             - and:
               - number: 1
               - number: 2''')

    rule = capa.rules.Rule.from_yaml(rule)
    rule.name = "test rule"
    assert rule.to_yaml() == EXPECTED

