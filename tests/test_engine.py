import textwrap

import capa.rules
import capa.engine
from capa.engine import *
import capa.features


def test_element():
    assert Element(1).evaluate(set([0])) == False
    assert Element(1).evaluate(set([1])) == True
    assert Element(1).evaluate(set([None])) == False
    assert Element(1).evaluate(set([''])) == False
    assert Element(1).evaluate(set([False])) == False


def test_and():
    assert And(Element(1)).evaluate(set([0])) == False
    assert And(Element(1)).evaluate(set([1])) == True
    assert And(Element(1), Element(2)).evaluate(set([0])) == False
    assert And(Element(1), Element(2)).evaluate(set([1])) == False
    assert And(Element(1), Element(2)).evaluate(set([2])) == False
    assert And(Element(1), Element(2)).evaluate(set([1, 2])) == True


def test_or():
    assert Or(Element(1)).evaluate(set([0])) == False
    assert Or(Element(1)).evaluate(set([1])) == True
    assert Or(Element(1), Element(2)).evaluate(set([0])) == False
    assert Or(Element(1), Element(2)).evaluate(set([1])) == True
    assert Or(Element(1), Element(2)).evaluate(set([2])) == True
    assert Or(Element(1), Element(2)).evaluate(set([1, 2])) == True


def test_not():
    assert Not(Element(1)).evaluate(set([0])) == True
    assert Not(Element(1)).evaluate(set([1])) == False


def test_some():
    assert Some(0, Element(1)).evaluate(set([0])) == True
    assert Some(1, Element(1)).evaluate(set([0])) == False

    assert Some(2, Element(1), Element(2), Element(3)).evaluate(set([0])) == False
    assert Some(2, Element(1), Element(2), Element(3)).evaluate(set([0, 1])) == False
    assert Some(2, Element(1), Element(2), Element(3)).evaluate(set([0, 1, 2])) == True
    assert Some(2, Element(1), Element(2), Element(3)).evaluate(set([0, 1, 2, 3])) == True
    assert Some(2, Element(1), Element(2), Element(3)).evaluate(set([0, 1, 2, 3, 4])) == True


def test_complex():
    assert True == Or(
        And(Element(1), Element(2)),
        Or(Element(3),
           Some(2, Element(4), Element(5), Element(6)))
    ).evaluate(set([5, 6, 7, 8]))

    assert False == Or(
        And(Element(1), Element(2)),
        Or(Element(3),
           Some(2, Element(4), Element(5)))
    ).evaluate(set([5, 6, 7, 8]))


def test_range():
    # unbounded range, but no matching feature
    assert Range(Element(1)).evaluate({Element(2): {}}) == False

    # unbounded range with matching feature should always match
    assert Range(Element(1)).evaluate({Element(1): {}}) == True
    assert Range(Element(1)).evaluate({Element(1): {0}}) == True

    # unbounded max
    assert Range(Element(1), min=1).evaluate({Element(1): {0}}) == True
    assert Range(Element(1), min=2).evaluate({Element(1): {0}}) == False
    assert Range(Element(1), min=2).evaluate({Element(1): {0, 1}}) == True

    # unbounded min
    assert Range(Element(1), max=0).evaluate({Element(1): {0}}) == False
    assert Range(Element(1), max=1).evaluate({Element(1): {0}}) == True
    assert Range(Element(1), max=2).evaluate({Element(1): {0}}) == True
    assert Range(Element(1), max=2).evaluate({Element(1): {0, 1}}) == True
    assert Range(Element(1), max=2).evaluate({Element(1): {0, 1, 3}}) == False

    # we can do an exact match by setting min==max
    assert Range(Element(1), min=1, max=1).evaluate({Element(1): {}}) == False
    assert Range(Element(1), min=1, max=1).evaluate({Element(1): {1}}) == True
    assert Range(Element(1), min=1, max=1).evaluate({Element(1): {1, 2}}) == False

    # bounded range
    assert Range(Element(1), min=1, max=3).evaluate({Element(1): {}}) == False
    assert Range(Element(1), min=1, max=3).evaluate({Element(1): {1}}) == True
    assert Range(Element(1), min=1, max=3).evaluate({Element(1): {1, 2}}) == True
    assert Range(Element(1), min=1, max=3).evaluate({Element(1): {1, 2, 3}}) == True
    assert Range(Element(1), min=1, max=3).evaluate({Element(1): {1, 2, 3, 4}}) == False


def test_match_adds_matched_rule_feature():
    '''show that using `match` adds a feature for matched rules.'''
    rule = textwrap.dedent('''
        rule:
            meta:
                name: test rule
            features:
                - number: 100
    ''')
    r = capa.rules.Rule.from_yaml(rule)
    features, matches = capa.engine.match([r], {capa.features.insn.Number(100): {1}}, 0x0)
    assert capa.features.MatchedRule('test rule') in features


def test_match_matched_rules():
    '''show that using `match` adds a feature for matched rules.'''
    rules = [
        capa.rules.Rule.from_yaml(textwrap.dedent('''
            rule:
                meta:
                    name: test rule1
                features:
                    - number: 100
        ''')),
         capa.rules.Rule.from_yaml(textwrap.dedent('''
            rule:
                meta:
                    name: test rule2
                features:
                    - match: test rule1
        ''')),
    ]
    features, matches = capa.engine.match(capa.engine.topologically_order_rules(rules),
                                            {capa.features.insn.Number(100): {1}}, 0x0)
    assert capa.features.MatchedRule('test rule1') in features
    assert capa.features.MatchedRule('test rule2') in features

    # the ordering of the rules must not matter,
    # the engine should match rules in an appropriate order.
    features, matches = capa.engine.match(capa.engine.topologically_order_rules(reversed(rules)),
                                            {capa.features.insn.Number(100): {1}}, 0x0)
    assert capa.features.MatchedRule('test rule1') in features
    assert capa.features.MatchedRule('test rule2') in features


def test_regex():
    rules = [
        capa.rules.Rule.from_yaml(textwrap.dedent('''
             rule:
                 meta:
                     name: test rule
                 features:
                     - and:
                         - string: /.*bbbb.*/
         ''')),
        capa.rules.Rule.from_yaml(textwrap.dedent('''
             rule:
                 meta:
                     name: rule with implied wildcards
                 features:
                     - and:
                         - string: /bbbb/
        ''')),
        capa.rules.Rule.from_yaml(textwrap.dedent('''
             rule:
                 meta:
                     name: rule with anchor
                 features:
                     - and:
                         - string: /^bbbb/
        ''')),
    ]
    features, matches = capa.engine.match(capa.engine.topologically_order_rules(rules),
                                            {capa.features.insn.Number(100): {1}}, 0x0)
    assert capa.features.MatchedRule('test rule') not in features

    features, matches = capa.engine.match(capa.engine.topologically_order_rules(rules),
                                            {capa.features.String('aaaa'): {1}}, 0x0)
    assert capa.features.MatchedRule('test rule') not in features

    features, matches = capa.engine.match(capa.engine.topologically_order_rules(rules),
                                          {capa.features.String('aBBBBa'): {1}}, 0x0)
    assert capa.features.MatchedRule('test rule') not in features

    features, matches = capa.engine.match(capa.engine.topologically_order_rules(rules),
                                            {capa.features.String('abbbba'): {1}}, 0x0)
    assert capa.features.MatchedRule('test rule') in features
    assert capa.features.MatchedRule('rule with implied wildcards') in features
    assert capa.features.MatchedRule('rule with anchor') not in features


def test_regex_ignorecase():
    rules = [
        capa.rules.Rule.from_yaml(textwrap.dedent('''
             rule:
                 meta:
                     name: test rule
                 features:
                     - and:
                         - string: /.*bbbb.*/i
         ''')),
    ]
    features, matches = capa.engine.match(capa.engine.topologically_order_rules(rules),
                                          {capa.features.String('aBBBBa'): {1}}, 0x0)
    assert capa.features.MatchedRule('test rule') in features


def test_regex_complex():
    rules = [
        capa.rules.Rule.from_yaml(textwrap.dedent(r'''
             rule:
                 meta:
                     name: test rule
                 features:
                     - or:
                         - string: /.*HARDWARE\\Key\\key with spaces\\.*/i
         ''')),
    ]
    features, matches = capa.engine.match(capa.engine.topologically_order_rules(rules),
                                            {capa.features.String(r'Hardware\Key\key with spaces\some value'): {1}}, 0x0)
    assert capa.features.MatchedRule('test rule') in features
