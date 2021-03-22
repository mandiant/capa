# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import re
import uuid
import codecs
import logging
import binascii
import functools

try:
    from functools import lru_cache
except ImportError:
    from backports.functools_lru_cache import lru_cache

import six
import yaml
import ruamel.yaml

import capa.engine
import capa.features
import capa.features.file
import capa.features.insn
import capa.features.basicblock
from capa.engine import *
from capa.features import MAX_BYTES_FEATURE_SIZE

logger = logging.getLogger(__name__)

# these are the standard metadata fields, in the preferred order.
# when reformatted, any custom keys will come after these.
META_KEYS = (
    "name",
    "namespace",
    "rule-category",
    "maec/analysis-conclusion",
    "maec/analysis-conclusion-ov",
    "maec/malware-category",
    "maec/malware-category-ov",
    "author",
    "description",
    "lib",
    "scope",
    "att&ck",
    "mbc",
    "references",
    "examples",
)
# these are meta fields that are internal to capa,
# and added during rule reading/construction.
# they may help use manipulate or index rules,
# but should not be exposed to clients.
HIDDEN_META_KEYS = ("capa/nursery", "capa/path")


FILE_SCOPE = "file"
FUNCTION_SCOPE = "function"
BASIC_BLOCK_SCOPE = "basic block"


SUPPORTED_FEATURES = {
    FILE_SCOPE: {
        capa.features.MatchedRule,
        capa.features.file.Export,
        capa.features.file.Import,
        capa.features.file.Section,
        capa.features.Characteristic("embedded pe"),
        capa.features.String,
    },
    FUNCTION_SCOPE: {
        # plus basic block scope features, see below
        capa.features.basicblock.BasicBlock,
        capa.features.Characteristic("calls from"),
        capa.features.Characteristic("calls to"),
        capa.features.Characteristic("loop"),
        capa.features.Characteristic("recursive call"),
    },
    BASIC_BLOCK_SCOPE: {
        capa.features.MatchedRule,
        capa.features.insn.API,
        capa.features.insn.Number,
        capa.features.String,
        capa.features.Bytes,
        capa.features.insn.Offset,
        capa.features.insn.Mnemonic,
        capa.features.Characteristic("nzxor"),
        capa.features.Characteristic("peb access"),
        capa.features.Characteristic("fs access"),
        capa.features.Characteristic("gs access"),
        capa.features.Characteristic("cross section flow"),
        capa.features.Characteristic("tight loop"),
        capa.features.Characteristic("stack string"),
        capa.features.Characteristic("indirect call"),
    },
}

# all basic block scope features are also function scope features
SUPPORTED_FEATURES[FUNCTION_SCOPE].update(SUPPORTED_FEATURES[BASIC_BLOCK_SCOPE])


class InvalidRule(ValueError):
    def __init__(self, msg):
        super(InvalidRule, self).__init__()
        self.msg = msg

    def __str__(self):
        return "invalid rule: %s" % (self.msg)

    def __repr__(self):
        return str(self)


class InvalidRuleWithPath(InvalidRule):
    def __init__(self, path, msg):
        super(InvalidRuleWithPath, self).__init__(msg)
        self.path = path
        self.msg = msg
        self.__cause__ = None

    def __str__(self):
        return "invalid rule: %s: %s" % (self.path, self.msg)


class InvalidRuleSet(ValueError):
    def __init__(self, msg):
        super(InvalidRuleSet, self).__init__()
        self.msg = msg

    def __str__(self):
        return "invalid rule set: %s" % (self.msg)

    def __repr__(self):
        return str(self)


def ensure_feature_valid_for_scope(scope, feature):
    if isinstance(feature, capa.features.Characteristic):
        if capa.features.Characteristic(feature.value) not in SUPPORTED_FEATURES[scope]:
            raise InvalidRule("feature %s not support for scope %s" % (feature, scope))
    elif not isinstance(feature, tuple(filter(lambda t: isinstance(t, type), SUPPORTED_FEATURES[scope]))):
        raise InvalidRule("feature %s not support for scope %s" % (feature, scope))


def parse_int(s):
    if s.startswith("0x"):
        return int(s, 0x10)
    else:
        return int(s, 10)


def parse_range(s):
    """
    parse a string "(0, 1)" into a range (min, max).
    min and/or max may by None to indicate an unbound range.
    """
    # we want to use `{` characters, but this is a dict in yaml.
    if not s.startswith("("):
        raise InvalidRule("invalid range: %s" % (s))

    if not s.endswith(")"):
        raise InvalidRule("invalid range: %s" % (s))

    s = s[len("(") : -len(")")]
    min, _, max = s.partition(",")
    min = min.strip()
    max = max.strip()

    if min:
        min = parse_int(min.strip())
        if min < 0:
            raise InvalidRule("range min less than zero")
    else:
        min = None

    if max:
        max = parse_int(max.strip())
        if max < 0:
            raise InvalidRule("range max less than zero")
    else:
        max = None

    if min is not None and max is not None:
        if max < min:
            raise InvalidRule("range max less than min")

    return min, max


def parse_feature(key):
    # keep this in sync with supported features
    if key == "api":
        return capa.features.insn.API
    elif key == "string":
        return capa.features.StringFactory
    elif key == "bytes":
        return capa.features.Bytes
    elif key == "number":
        return capa.features.insn.Number
    elif key.startswith("number/"):
        arch = key.partition("/")[2]
        # the other handlers here return constructors for features,
        # and we want to as well,
        # however, we need to preconfigure one of the arguments (`arch`).
        # so, instead we return a partially-applied function that
        #  provides `arch` to the feature constructor.
        # it forwards any other arguments provided to the closure along to the constructor.
        return functools.partial(capa.features.insn.Number, arch=arch)
    elif key == "offset":
        return capa.features.insn.Offset
    elif key.startswith("offset/"):
        arch = key.partition("/")[2]
        return functools.partial(capa.features.insn.Offset, arch=arch)
    elif key == "mnemonic":
        return capa.features.insn.Mnemonic
    elif key == "basic blocks":
        return capa.features.basicblock.BasicBlock
    elif key == "characteristic":
        return capa.features.Characteristic
    elif key == "export":
        return capa.features.file.Export
    elif key == "import":
        return capa.features.file.Import
    elif key == "section":
        return capa.features.file.Section
    elif key == "match":
        return capa.features.MatchedRule
    else:
        raise InvalidRule("unexpected statement: %s" % key)


# this is the separator between a feature value and its description
# when using the inline description syntax, like:
#
#     number: 42 = ENUM_FAVORITE_NUMBER
DESCRIPTION_SEPARATOR = " = "


def parse_description(s, value_type, description=None):
    """
    s can be an int or a string
    """
    if value_type != "string" and isinstance(s, six.string_types) and DESCRIPTION_SEPARATOR in s:
        if description:
            raise InvalidRule(
                'unexpected value: "%s", only one description allowed (inline description with `%s`)'
                % (s, DESCRIPTION_SEPARATOR)
            )
        value, _, description = s.partition(DESCRIPTION_SEPARATOR)
        if description == "":
            raise InvalidRule('unexpected value: "%s", description cannot be empty' % s)
    else:
        value = s

    if isinstance(value, six.string_types):
        if value_type == "bytes":
            try:
                value = codecs.decode(value.replace(" ", ""), "hex")
            # TODO: Remove TypeError when Python2 is not used anymore
            except (TypeError, binascii.Error):
                raise InvalidRule('unexpected bytes value: "%s", must be a valid hex sequence' % value)

            if len(value) > MAX_BYTES_FEATURE_SIZE:
                raise InvalidRule(
                    "unexpected bytes value: byte sequences must be no larger than %s bytes" % MAX_BYTES_FEATURE_SIZE
                )
        elif value_type in ("number", "offset") or value_type.startswith(("number/", "offset/")):
            try:
                value = parse_int(value)
            except ValueError:
                raise InvalidRule('unexpected value: "%s", must begin with numerical value' % value)

    return value, description


def pop_statement_description_entry(d):
    """
    extracts the description for statements and removes the description entry from the document
    a statement can only have one description

    example:
    the features definition
      - or:
        - description: statement description
        - number: 1
          description: feature description

    becomes
      <statement>: [
        { "description": "statement description" },  <-- extracted here
        { "number": 1, "description": "feature description" }
      ]
    """
    if not isinstance(d, list):
        return None

    # identify child of form '{ "description": <description> }'
    descriptions = list(filter(lambda c: isinstance(c, dict) and len(c) == 1 and "description" in c, d))
    if len(descriptions) > 1:
        raise InvalidRule("statements can only have one description")

    if not descriptions:
        return None

    description = descriptions[0]
    d.remove(description)

    return description["description"]


def build_statements(d, scope):
    if len(d.keys()) > 2:
        raise InvalidRule("too many statements")

    key = list(d.keys())[0]
    description = pop_statement_description_entry(d[key])
    if key == "and":
        return And([build_statements(dd, scope) for dd in d[key]], description=description)
    elif key == "or":
        return Or([build_statements(dd, scope) for dd in d[key]], description=description)
    elif key == "not":
        if len(d[key]) != 1:
            raise InvalidRule("not statement must have exactly one child statement")
        return Not(build_statements(d[key][0], scope), description=description)
    elif key.endswith(" or more"):
        count = int(key[: -len("or more")])
        return Some(count, [build_statements(dd, scope) for dd in d[key]], description=description)
    elif key == "optional":
        # `optional` is an alias for `0 or more`
        # which is useful for documenting behaviors,
        # like with `write file`, we might say that `WriteFile` is optionally found alongside `CreateFileA`.
        return Some(0, [build_statements(dd, scope) for dd in d[key]], description=description)

    elif key == "function":
        if scope != FILE_SCOPE:
            raise InvalidRule("function subscope supported only for file scope")

        if len(d[key]) != 1:
            raise InvalidRule("subscope must have exactly one child statement")

        return Subscope(FUNCTION_SCOPE, build_statements(d[key][0], FUNCTION_SCOPE))

    elif key == "basic block":
        if scope != FUNCTION_SCOPE:
            raise InvalidRule("basic block subscope supported only for function scope")

        if len(d[key]) != 1:
            raise InvalidRule("subscope must have exactly one child statement")

        return Subscope(BASIC_BLOCK_SCOPE, build_statements(d[key][0], BASIC_BLOCK_SCOPE))

    elif key.startswith("count(") and key.endswith(")"):
        # e.g.:
        #
        #     count(basic block)
        #     count(mnemonic(mov))
        #     count(characteristic(nzxor))

        term = key[len("count(") : -len(")")]

        # when looking for the existence of such a feature, our rule might look like:
        #     - mnemonic: mov
        #
        # but here we deal with the form: `mnemonic(mov)`.
        term, _, arg = term.partition("(")
        Feature = parse_feature(term)

        if arg:
            arg = arg[: -len(")")]
            # can't rely on yaml parsing ints embedded within strings
            # like:
            #
            #     count(offset(0xC))
            #     count(number(0x11223344))
            #     count(number(0x100 = description))
            if term != "string":
                value, description = parse_description(arg, term)
                feature = Feature(value, description=description)
            else:
                # arg is string (which doesn't support inline descriptions), like:
                #
                #     count(string(error))
                # TODO: what about embedded newlines?
                feature = Feature(arg)
        else:
            feature = Feature()
        ensure_feature_valid_for_scope(scope, feature)

        count = d[key]
        if isinstance(count, int):
            return Range(feature, min=count, max=count, description=description)
        elif count.endswith(" or more"):
            min = parse_int(count[: -len(" or more")])
            max = None
            return Range(feature, min=min, max=max, description=description)
        elif count.endswith(" or fewer"):
            min = None
            max = parse_int(count[: -len(" or fewer")])
            return Range(feature, min=min, max=max, description=description)
        elif count.startswith("("):
            min, max = parse_range(count)
            return Range(feature, min=min, max=max, description=description)
        else:
            raise InvalidRule("unexpected range: %s" % (count))
    elif key == "string" and not isinstance(d[key], six.string_types):
        raise InvalidRule("ambiguous string value %s, must be defined as explicit string" % d[key])
    else:
        Feature = parse_feature(key)
        value, description = parse_description(d[key], key, d.get("description"))
        try:
            feature = Feature(value, description=description)
        except ValueError as e:
            raise InvalidRule(str(e))
        ensure_feature_valid_for_scope(scope, feature)
        return feature


def first(s):
    return s[0]


def second(s):
    return s[1]


class Rule(object):
    def __init__(self, name, scope, statement, meta, definition=""):
        super(Rule, self).__init__()
        self.name = name
        self.scope = scope
        self.statement = statement
        self.meta = meta
        self.definition = definition

    def __str__(self):
        return "Rule(name=%s)" % (self.name)

    def __repr__(self):
        return "Rule(scope=%s, name=%s)" % (self.scope, self.name)

    def get_dependencies(self, namespaces):
        """
        fetch the names of rules this rule relies upon.
        these are only the direct dependencies; a user must
         compute the transitive dependency graph themself, if they want it.

        Args:
          namespaces(Dict[str, List[Rule]]): mapping from namespace name to rules in it.
            see `index_rules_by_namespace`.

        Returns:
          List[str]: names of rules upon which this rule depends.
        """
        deps = set([])

        def rec(statement):
            if isinstance(statement, capa.features.MatchedRule):
                # we're not sure at this point if the `statement.value` is
                #  really a rule name or a namespace name (we use `MatchedRule` for both cases).
                # we'll give precedence to namespaces, and then assume if that does work,
                #  that it must be a rule name.
                #
                # we don't expect any collisions between namespaces and rule names, but its possible.
                # most likely would be collision between top level namespace (e.g. `host-interaction`) and rule name.
                # but, namespaces tend to use `-` while rule names use ` `. so, unlikely, but possible.
                if statement.value in namespaces:
                    # matches a namespace, so take precedence and don't even check rule names.
                    deps.update(map(lambda r: r.name, namespaces[statement.value]))
                else:
                    # not a namespace, assume its a rule name.
                    deps.add(statement.value)

            elif isinstance(statement, Statement):
                for child in statement.get_children():
                    rec(child)

            # else: might be a Feature, etc.
            # which we don't care about here.

        rec(self.statement)
        return deps

    def _extract_subscope_rules_rec(self, statement):
        if isinstance(statement, Statement):
            # for each child that is a subscope,
            for subscope in filter(
                lambda statement: isinstance(statement, capa.engine.Subscope), statement.get_children()
            ):

                # create a new rule from it.
                # the name is a randomly generated, hopefully unique value.
                # ideally, this won't every be rendered to a user.
                name = self.name + "/" + uuid.uuid4().hex
                new_rule = Rule(
                    name,
                    subscope.scope,
                    subscope.child,
                    {
                        "name": name,
                        "scope": subscope.scope,
                        # these derived rules are never meant to be inspected separately,
                        # they are dependencies for the parent rule,
                        # so mark it as such.
                        "lib": True,
                        # metadata that indicates this is derived from a subscope statement
                        "capa/subscope-rule": True,
                        # metadata that links the child rule the parent rule
                        "capa/parent": self.name,
                    },
                )

                # update the existing statement to `match` the new rule
                new_node = capa.features.MatchedRule(name)
                statement.replace_child(subscope, new_node)

                # and yield the new rule to our caller
                yield new_rule

            # now recurse to other nodes in the logic tree.
            # note: we cannot recurse into the subscope sub-tree,
            #  because its been replaced by a `match` statement.
            for child in statement.get_children():
                for new_rule in self._extract_subscope_rules_rec(child):
                    yield new_rule

    def extract_subscope_rules(self):
        """
        scan through the statements of this rule,
        replacing subscope statements with `match` references to a newly created rule,
        which are yielded from this routine.

        note: this mutates the current rule.

        example::

            for derived_rule in rule.extract_subscope_rules():
                assert derived_rule.meta['capa/parent'] == rule.name
        """

        # recurse through statements
        # when encounter Subscope statement
        #   create new transient rule
        #   copy logic into the new rule
        #   replace old node with reference to new rule
        #   yield new rule

        for new_rule in self._extract_subscope_rules_rec(self.statement):
            yield new_rule

    def evaluate(self, features):
        return self.statement.evaluate(features)

    @classmethod
    def from_dict(cls, d, definition):
        name = d["rule"]["meta"]["name"]
        # if scope is not specified, default to function scope.
        # this is probably the mode that rule authors will start with.
        scope = d["rule"]["meta"].get("scope", FUNCTION_SCOPE)
        statements = d["rule"]["features"]

        # the rule must start with a single logic node.
        # doing anything else is too implicit and difficult to remove (AND vs OR ???).
        if len(statements) != 1:
            raise InvalidRule("rule must begin with a single top level statement")

        if isinstance(statements[0], capa.engine.Subscope):
            raise InvalidRule("top level statement may not be a subscope")

        if scope not in SUPPORTED_FEATURES.keys():
            raise InvalidRule("{:s} is not a supported scope".format(scope))

        return cls(name, scope, build_statements(statements[0], scope), d["rule"]["meta"], definition)

    @staticmethod
    @lru_cache()
    def _get_yaml_loader():
        try:
            # prefer to use CLoader to be fast, see #306
            # on Linux, make sure you install libyaml-dev or similar
            # on Windows, get WHLs from pyyaml.org/pypi
            loader = yaml.CLoader
            logger.debug("using libyaml CLoader.")
        except:
            loader = yaml.Loader
            logger.debug("unable to import libyaml CLoader, falling back to Python yaml parser.")
            logger.debug("this will be slower to load rules.")

        return loader

    @staticmethod
    def _get_ruamel_yaml_parser():
        # use ruamel to enable nice formatting

        # we use the ruamel.yaml parser because it supports roundtripping of documents with comments.
        y = ruamel.yaml.YAML(typ="rt")

        # use block mode, not inline json-like mode
        y.default_flow_style = False

        # leave quotes unchanged
        y.preserve_quotes = True

        # indent lists by two spaces below their parent
        #
        #     features:
        #       - or:
        #         - mnemonic: aesdec
        #         - mnemonic: vaesdec
        y.indent(sequence=2, offset=2)

        # avoid word wrapping
        y.width = 4096

        return y

    @classmethod
    def from_yaml(cls, s, use_ruamel=False):
        if use_ruamel:
            # ruamel enables nice formatting and doc roundtripping with comments
            doc = cls._get_ruamel_yaml_parser().load(s)
        else:
            # use pyyaml because it can be much faster than ruamel (pure python)
            doc = yaml.load(s, Loader=cls._get_yaml_loader())
        return cls.from_dict(doc, s)

    @classmethod
    def from_yaml_file(cls, path, use_ruamel=False):
        with open(path, "rb") as f:
            try:
                return cls.from_yaml(f.read().decode("utf-8"), use_ruamel=use_ruamel)
            except InvalidRule as e:
                raise InvalidRuleWithPath(path, str(e))

    def to_yaml(self):
        # reformat the yaml document with a common style.
        # this includes:
        #  - ordering the meta elements
        #  - indenting the nested items with two spaces
        #
        # updates to the rule will be synced for meta fields,
        # but not for rule logic.
        # programmatic generation of rules is not yet supported.

        # use ruamel because it supports round tripping.
        # pyyaml will lose the existing ordering of rule statements.
        definition = self._get_ruamel_yaml_parser().load(self.definition)

        # we want to apply any updates that have been made to `meta`.
        # so we would like to assigned it like this:
        #
        #     definition["rule"]["meta"] = self.meta
        #
        # however, `self.meta` is not ordered, its just a dict, so subsequent formatting doesn't work.
        # so, we'll manually copy the keys over, re-using the existing ordereddict/CommentedMap
        meta = definition["rule"]["meta"]
        for k in meta.keys():
            if k not in self.meta:
                del meta[k]
        for k, v in self.meta.items():
            meta[k] = v

        # the name and scope of the rule instance overrides anything in meta.
        meta["name"] = self.name
        meta["scope"] = self.scope

        def move_to_end(m, k):
            # ruamel.yaml uses an ordereddict-like structure to track maps (CommentedMap).
            # here we refresh the insertion order of the given key.
            # this will move it to the end of the sequence.
            v = m[k]
            del m[k]
            m[k] = v

        move_to_end(definition["rule"], "meta")
        move_to_end(definition["rule"], "features")

        for key in META_KEYS:
            if key in meta:
                move_to_end(meta, key)

        for key in sorted(meta.keys()):
            if key in META_KEYS:
                continue
            move_to_end(meta, key)

        # save off the existing hidden meta values,
        # emit the document,
        # and re-add the hidden meta.
        hidden_meta = {}
        for key in HIDDEN_META_KEYS:
            value = meta.get(key)
            if value:
                hidden_meta[key] = value

        for key in hidden_meta.keys():
            del meta[key]

        ostream = six.BytesIO()
        self._get_ruamel_yaml_parser().dump(definition, ostream)

        for key, value in hidden_meta.items():
            if value is None:
                continue
            meta[key] = value

        doc = ostream.getvalue().decode("utf-8").rstrip("\n") + "\n"
        # when we have something like:
        #
        #     and:
        #       - string: foo
        #         description: bar
        #
        # we want the `description` horizontally aligned with the start of the `string` (like above).
        # however, ruamel will give us (which I don't think is even valid yaml):
        #
        #     and:
        #       - string: foo
        #      description: bar
        #
        # tweaking `ruamel.indent()` doesn't quite give us the control we want.
        # so, add the two extra spaces that we've determined we need through experimentation.
        # see #263
        # only do this for the features section, so the meta description doesn't get reformatted
        # assumes features section always exists
        features_offset = doc.find("features")
        doc = doc[:features_offset] + doc[features_offset:].replace("  description:", "    description:")

        # for negative hex numbers, yaml dump outputs:
        # - offset: !!int '0x-30'
        # we prefer:
        # - offset: -0x30
        # the below regex makes these adjustments and while ugly, we don't have to explore the ruamel.yaml insides
        doc = re.sub(r"!!int '0x-([0-9a-fA-F]+)'", r"-0x\1", doc)

        # normalize CRLF to LF
        doc = doc.replace("\r\n", "\n")
        return doc


def get_rules_with_scope(rules, scope):
    """
    from the given collection of rules, select those with the given scope.

    args:
      rules (List[capa.rules.Rule]):
      scope (str): one of the capa.rules.*_SCOPE constants.

    returns:
      List[capa.rules.Rule]:
    """
    return list(rule for rule in rules if rule.scope == scope)


def get_rules_and_dependencies(rules, rule_name):
    """
    from the given collection of rules, select a rule and its dependencies (transitively).

    args:
      rules (List[Rule]):
      rule_name (str):

    yields:
      Rule:
    """
    # we evaluate `rules` multiple times, so if its a generator, realize it into a list.
    rules = list(rules)
    namespaces = index_rules_by_namespace(rules)
    rules = {rule.name: rule for rule in rules}
    wanted = set([rule_name])

    def rec(rule):
        wanted.add(rule.name)
        for dep in rule.get_dependencies(namespaces):
            rec(rules[dep])

    rec(rules[rule_name])

    for rule in rules.values():
        if rule.name in wanted:
            yield rule


def ensure_rules_are_unique(rules):
    seen = set([])
    for rule in rules:
        if rule.name in seen:
            raise InvalidRule("duplicate rule name: " + rule.name)
        seen.add(rule.name)


def ensure_rule_dependencies_are_met(rules):
    """
    raise an exception if a rule dependency does not exist.

    raises:
      InvalidRule: if a dependency is not met.
    """
    # we evaluate `rules` multiple times, so if its a generator, realize it into a list.
    rules = list(rules)
    namespaces = index_rules_by_namespace(rules)
    rules = {rule.name: rule for rule in rules}
    for rule in rules.values():
        for dep in rule.get_dependencies(namespaces):
            if dep not in rules:
                raise InvalidRule('rule "%s" depends on missing rule "%s"' % (rule.name, dep))


def index_rules_by_namespace(rules):
    """
    compute the rules that fit into each namespace found within the given rules.

    for example, given:

      - c2/shell :: create reverse shell
      - c2/file-transfer :: download and write a file

    return the index:

      c2/shell: [create reverse shell]
      c2/file-transfer: [download and write a file]
      c2: [create reverse shell, download and write a file]

    Args:
      rules (List[Rule]):

    Returns: Dict[str, List[Rule]]
    """
    namespaces = collections.defaultdict(list)

    for rule in rules:
        namespace = rule.meta.get("namespace")
        if not namespace:
            continue

        while namespace:
            namespaces[namespace].append(rule)
            namespace, _, _ = namespace.rpartition("/")

    return dict(namespaces)


class RuleSet(object):
    """
    a ruleset is initialized with a collection of rules, which it verifies and sorts into scopes.
    each set of scoped rules is sorted topologically, which enables rules to match on past rule matches.

    example:

        ruleset = RuleSet([
          Rule(...),
          Rule(...),
          ...
        ])
        capa.engine.match(ruleset.file_rules, ...)
    """

    def __init__(self, rules):
        super(RuleSet, self).__init__()

        ensure_rules_are_unique(rules)

        rules = self._extract_subscope_rules(rules)

        ensure_rule_dependencies_are_met(rules)

        if len(rules) == 0:
            raise InvalidRuleSet("no rules selected")

        self.file_rules = self._get_rules_for_scope(rules, FILE_SCOPE)
        self.function_rules = self._get_rules_for_scope(rules, FUNCTION_SCOPE)
        self.basic_block_rules = self._get_rules_for_scope(rules, BASIC_BLOCK_SCOPE)
        self.rules = {rule.name: rule for rule in rules}

    def __len__(self):
        return len(self.rules)

    def __getitem__(self, rulename):
        return self.rules[rulename]

    @staticmethod
    def _get_rules_for_scope(rules, scope):
        """
        given a collection of rules, collect the rules that are needed at the given scope.
        these rules are ordered topologically.

        don't include auto-generated "subscope" rules.
        we want to include general "lib" rules here - even if they are not dependencies of other rules, see #398
        """
        scope_rules = set([])

        # we need to process all rules, not just rules with the given scope.
        # this is because rules with a higher scope, e.g. file scope, may have subscope rules
        #  at lower scope, e.g. function scope.
        # so, we find all dependencies of all rules, and later will filter them down.
        for rule in rules:
            if rule.meta.get("capa/subscope-rule", False):
                continue

            scope_rules.update(get_rules_and_dependencies(rules, rule.name))
        return get_rules_with_scope(capa.engine.topologically_order_rules(scope_rules), scope)

    @staticmethod
    def _extract_subscope_rules(rules):
        """
        process the given sequence of rules.
        for each one, extract any embedded subscope rules into their own rule.
        process these recursively.
        then return a list of the refactored rules.

        note: this operation mutates the rules passed in - they may now have `match` statements
         for the extracted subscope rules.
        """
        done = []

        # use a queue of rules, because we'll be modifying the list (appending new items) as we go.
        while rules:
            rule = rules.pop(0)
            for subscope_rule in rule.extract_subscope_rules():
                rules.append(subscope_rule)
            done.append(rule)

        return done

    def filter_rules_by_meta(self, tag):
        """
        return new rule set with rules filtered based on all meta field values, adds all dependency rules
        apply tag-based rule filter assuming that all required rules are loaded
        can be used to specify selected rules vs. providing a rules child directory where capa cannot resolve
        dependencies from unknown paths
        TODO handle circular dependencies?
        TODO support -t=metafield <k>
        """
        rules = self.rules.values()
        rules_filtered = set([])
        for rule in rules:
            for k, v in rule.meta.items():
                if isinstance(v, six.string_types) and tag in v:
                    logger.debug('using rule "%s" and dependencies, found tag in meta.%s: %s', rule.name, k, v)
                    rules_filtered.update(set(capa.rules.get_rules_and_dependencies(rules, rule.name)))
                    break
        return RuleSet(list(rules_filtered))
