import textwrap

import pytest

import capa.rules
from capa.engine import Element
from capa.features.insn import Number, Offset


def test_rule_ctor():
    r = capa.rules.Rule('test rule', capa.rules.FUNCTION_SCOPE, Element(1), {})
    assert r.evaluate(set([0])) == False
    assert r.evaluate(set([1])) == True


def test_rule_yaml():
    rule = textwrap.dedent('''
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
                    - element: 1
                    - element: 2
    ''')
    r = capa.rules.Rule.from_yaml(rule)
    assert r.evaluate(set([0])) == False
    assert r.evaluate(set([0, 1])) == False
    assert r.evaluate(set([0, 1, 2])) == True
    assert r.evaluate(set([0, 1, 2, 3])) == True


def test_rule_yaml_complex():
    rule = textwrap.dedent('''
        rule:
            meta:
                name: test rule
            features:
                - or:
                    - and:
                        - element: 1
                        - element: 2
                    - or:
                        - element: 3
                        - 2 or more:
                            - element: 4
                            - element: 5
                            - element: 6
    ''')
    r = capa.rules.Rule.from_yaml(rule)
    assert r.evaluate(set([5, 6, 7, 8])) == True
    assert r.evaluate(set([6, 7, 8])) == False


def test_rule_yaml_not():
    rule = textwrap.dedent('''
            rule:
                meta:
                    name: test rule
                features:
                    - and:
                        - element: 1
                        - not:
                            - element: 2
        ''')
    r = capa.rules.Rule.from_yaml(rule)
    assert r.evaluate(set([1])) == True
    assert r.evaluate(set([1, 2])) == False


def test_rule_yaml_count():
    rule = textwrap.dedent('''
        rule:
            meta:
                name: test rule
            features:
                - count(element(100)): 1
    ''')
    r = capa.rules.Rule.from_yaml(rule)
    assert r.evaluate({Element(100): {}}) == False
    assert r.evaluate({Element(100): {1}}) == True
    assert r.evaluate({Element(100): {1, 2}}) == False


def test_rule_yaml_count_range():
    rule = textwrap.dedent('''
        rule:
            meta:
                name: test rule
            features:
                - count(element(100)): (1, 2)
    ''')
    r = capa.rules.Rule.from_yaml(rule)
    assert r.evaluate({Element(100): {}}) == False
    assert r.evaluate({Element(100): {1}}) == True
    assert r.evaluate({Element(100): {1, 2}}) == True
    assert r.evaluate({Element(100): {1, 2, 3}}) == False


def test_invalid_rule_feature():
    with pytest.raises(capa.rules.InvalidRule):
        capa.rules.Rule.from_yaml(textwrap.dedent('''
            rule:
                meta:
                    name: test rule
                features:
                    - foo: true
        '''))

    with pytest.raises(capa.rules.InvalidRule):
        capa.rules.Rule.from_yaml(textwrap.dedent('''
            rule:
                meta:
                    name: test rule
                    scope: file
                features:
                    - characteristic(nzxor): true
        '''))

    with pytest.raises(capa.rules.InvalidRule):
        capa.rules.Rule.from_yaml(textwrap.dedent('''
            rule:
                meta:
                    name: test rule
                    scope: function
                features:
                    - characteristic(embedded pe): true
        '''))

    with pytest.raises(capa.rules.InvalidRule):
        capa.rules.Rule.from_yaml(textwrap.dedent('''
            rule:
                meta:
                    name: test rule
                    scope: basic block
                features:
                    - characteristic(embedded pe): true
        '''))


def test_lib_rules():
    rules = capa.rules.RuleSet([
        capa.rules.Rule.from_yaml(textwrap.dedent('''
            rule:
                meta:
                    name: a lib rule
                    lib: true
                features:
                    - api: CreateFileA
        ''')),
        capa.rules.Rule.from_yaml(textwrap.dedent('''
                rule:
                    meta:
                        name: a standard rule
                        lib: false
                    features:
                        - api: CreateFileW
            ''')),
    ])
    assert len(rules.function_rules) == 1


def test_subscope_rules():
    rules = capa.rules.RuleSet([
        capa.rules.Rule.from_yaml(textwrap.dedent('''
            rule:
                meta:
                    name: test rule
                    scope: file
                features:
                    - and:
                        - characteristic(embedded pe): true
                        - function:
                            - and:
                                - characteristic(nzxor): true
                                - characteristic(switch): true
        '''))
    ])
    # the file rule scope will have one rules:
    #  - `test rule`
    assert len(rules.file_rules) == 1

    # the function rule scope have one rule:
    #  - the rule on which `test rule` depends
    assert len(rules.function_rules) == 1


def test_duplicate_rules():
    with pytest.raises(capa.rules.InvalidRule):
        rules = capa.rules.RuleSet([
            capa.rules.Rule.from_yaml(textwrap.dedent('''
                rule:
                    meta:
                        name: rule-name
                    features:
                        - api: CreateFileA
            ''')),
            capa.rules.Rule.from_yaml(textwrap.dedent('''
                    rule:
                        meta:
                            name: rule-name
                        features:
                            - api: CreateFileW
                ''')),
        ])


def test_missing_dependency():
    with pytest.raises(capa.rules.InvalidRule):
        rules = capa.rules.RuleSet([
            capa.rules.Rule.from_yaml(textwrap.dedent('''
                    rule:
                        meta:
                            name: dependent rule
                        features:
                            - match: missing rule
                ''')),
        ])


def test_invalid_rules():
    with pytest.raises(capa.rules.InvalidRule):
        r = capa.rules.Rule.from_yaml(textwrap.dedent('''
                rule:
                    meta:
                        name: test rule
                    features:
                        - characteristic(number(1)): True
            '''))

    with pytest.raises(capa.rules.InvalidRule):
        r = capa.rules.Rule.from_yaml(textwrap.dedent('''
                rule:
                    meta:
                        name: test rule
                    features:
                        - characteristic(count(element(100))): True
            '''))


def test_number_symbol():
    rule = textwrap.dedent('''
        rule:
            meta:
                name: test rule
            features:
                - and:
                    - number: 1
                    - number: -1
                    - number: 2 = symbol name
                    - number: 3  =  symbol name
                    - number: 4  =  symbol name = another name
                    - number: 0x100 = symbol name
                    - number: 0x11 = (FLAG_A | FLAG_B)
    ''')
    r = capa.rules.Rule.from_yaml(rule)
    children = list(r.statement.get_children())
    assert (Number(1) in children) == True
    assert (Number(-1) in children) == True
    assert (Number(2, 'symbol name') in children) == True
    assert (Number(3, 'symbol name') in children) == True
    assert (Number(4, 'symbol name = another name') in children) == True
    assert (Number(0x100, 'symbol name') in children) == True


def test_count_number_symbol():
    rule = textwrap.dedent('''
        rule:
            meta:
                name: test rule
            features:
                - or:
                    - count(number(2 = symbol name)): 1
                    - count(number(0x100 = symbol name)): 2 or more
                    - count(number(0x11 = (FLAG_A | FLAG_B))): 2 or more
    ''')
    r = capa.rules.Rule.from_yaml(rule)
    assert r.evaluate({Number(2): {}}) == False
    assert r.evaluate({Number(2): {1}}) == True
    assert r.evaluate({Number(2): {1, 2}}) == False
    assert r.evaluate({Number(0x100, 'symbol name'): {1}}) == False
    assert r.evaluate({Number(0x100, 'symbol name'): {1, 2, 3}}) == True


def test_invalid_number():
    with pytest.raises(capa.rules.InvalidRule):
        r = capa.rules.Rule.from_yaml(textwrap.dedent('''
                    rule:
                        meta:
                            name: test rule
                        features:
                            - number: "this is a string"
                '''))

    with pytest.raises(capa.rules.InvalidRule):
        r = capa.rules.Rule.from_yaml(textwrap.dedent('''
                    rule:
                        meta:
                            name: test rule
                        features:
                            - number: 2=
                '''))

    with pytest.raises(capa.rules.InvalidRule):
        r = capa.rules.Rule.from_yaml(textwrap.dedent('''
                    rule:
                        meta:
                            name: test rule
                        features:
                            - number: symbol name = 2
                '''))


def test_offset_symbol():
    rule = textwrap.dedent('''
        rule:
            meta:
                name: test rule
            features:
                - and:
                    - offset: 1
                    # what about negative offsets?
                    - offset: 2 = symbol name
                    - offset: 3  =  symbol name
                    - offset: 4  =  symbol name = another name
                    - offset: 0x100 = symbol name
    ''')
    r = capa.rules.Rule.from_yaml(rule)
    children = list(r.statement.get_children())
    assert (Offset(1) in children) == True
    assert (Offset(2, 'symbol name') in children) == True
    assert (Offset(3, 'symbol name') in children) == True
    assert (Offset(4, 'symbol name = another name') in children) == True
    assert (Offset(0x100, 'symbol name') in children) == True


def test_count_offset_symbol():
    rule = textwrap.dedent('''
        rule:
            meta:
                name: test rule
            features:
                - or:
                    - count(offset(2 = symbol name)): 1
                    - count(offset(0x100 = symbol name)): 2 or more
                    - count(offset(0x11 = (FLAG_A | FLAG_B))): 2 or more
    ''')
    r = capa.rules.Rule.from_yaml(rule)
    assert r.evaluate({Offset(2): {}}) == False
    assert r.evaluate({Offset(2): {1}}) == True
    assert r.evaluate({Offset(2): {1, 2}}) == False
    assert r.evaluate({Offset(0x100, 'symbol name'): {1}}) == False
    assert r.evaluate({Offset(0x100, 'symbol name'): {1, 2, 3}}) == True


def test_invalid_offset():
    with pytest.raises(capa.rules.InvalidRule):
        r = capa.rules.Rule.from_yaml(textwrap.dedent('''
                    rule:
                        meta:
                            name: test rule
                        features:
                            - offset: "this is a string"
                '''))

    with pytest.raises(capa.rules.InvalidRule):
        r = capa.rules.Rule.from_yaml(textwrap.dedent('''
                    rule:
                        meta:
                            name: test rule
                        features:
                            - offset: 2=
                '''))

    with pytest.raises(capa.rules.InvalidRule):
        r = capa.rules.Rule.from_yaml(textwrap.dedent('''
                    rule:
                        meta:
                            name: test rule
                        features:
                            - offset: symbol name = 2
                '''))


def test_filter_rules():
    rules = capa.rules.RuleSet([
        capa.rules.Rule.from_yaml(textwrap.dedent('''
                rule:
                    meta:
                        name: rule 1
                        author: joe
                    features:
                        - api: CreateFile
        ''')),
        capa.rules.Rule.from_yaml(textwrap.dedent('''
                rule:
                    meta:
                        name: rule 2
                    features:
                        - string: joe
        ''')),
    ])
    rules = rules.filter_rules_by_meta('joe')
    assert len(rules) == 1
    assert ('rule 1' in rules.rules)


def test_filter_rules_dependencies():
    rules = capa.rules.RuleSet([
        capa.rules.Rule.from_yaml(textwrap.dedent('''
                rule:
                    meta:
                        name: rule 1
                    features:
                        - match: rule 2
        ''')),
        capa.rules.Rule.from_yaml(textwrap.dedent('''
                rule:
                    meta:
                        name: rule 2
                    features:
                        - match: rule 3
        ''')),
        capa.rules.Rule.from_yaml(textwrap.dedent('''
                rule:
                    meta:
                        name: rule 3
                    features:
                        - api: CreateFile
        ''')),
    ])
    rules = rules.filter_rules_by_meta('rule 1')
    assert(len(rules.rules) == 3)
    assert('rule 1' in rules.rules)
    assert('rule 2' in rules.rules)
    assert('rule 3' in rules.rules)


def test_filter_rules_missing_dependency():
    with pytest.raises(capa.rules.InvalidRule):
        capa.rules.RuleSet([
            capa.rules.Rule.from_yaml(textwrap.dedent('''
                    rule:
                        meta:
                            name: rule 1
                            author: joe
                        features:
                            - match: rule 2
            ''')),
        ])
