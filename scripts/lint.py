"""
Check the given capa rules for style issues.

Usage:

   $ python scripts/lint.py rules/

Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
import gc
import os
import re
import sys
import json
import time
import string
import difflib
import hashlib
import inspect
import logging
import pathlib
import argparse
import itertools
import posixpath
import contextlib
from typing import Set, Dict, List
from pathlib import Path
from dataclasses import field, dataclass

import tqdm
import termcolor
import ruamel.yaml
import tqdm.contrib.logging

import capa.main
import capa.rules
import capa.engine
import capa.helpers
import capa.features.insn
import capa.features.common
from capa.rules import Rule, RuleSet
from capa.features.common import Feature

logger = logging.getLogger("lint")


def red(s):
    return termcolor.colored(s, "red")


def orange(s):
    return termcolor.colored(s, "yellow")


def green(s):
    return termcolor.colored(s, "green")


@dataclass
class Context:
    """
    attributes:
      samples: mapping from content hash (MD5, SHA, etc.) to file path.
      rules: rules to inspect
      is_thorough: should inspect long-running lints
      capabilities_by_sample: cache of results, indexed by file path.
    """

    samples: Dict[str, Path]
    rules: RuleSet
    is_thorough: bool
    capabilities_by_sample: Dict[Path, Set[str]] = field(default_factory=dict)


class Lint:
    WARN = orange("WARN")
    FAIL = red("FAIL")

    name = "lint"
    level = FAIL
    recommendation = ""

    def check_rule(self, ctx: Context, rule: Rule):
        return False


class NameCasing(Lint):
    name = "rule name casing"
    recommendation = "Rename rule using to start with lower case letters"

    def check_rule(self, ctx: Context, rule: Rule):
        return rule.name[0] in string.ascii_uppercase and rule.name[1] not in string.ascii_uppercase


class FilenameDoesntMatchRuleName(Lint):
    name = "filename doesn't match the rule name"
    recommendation = "Rename rule file to match the rule name"
    recommendation_template = 'Rename rule file to match the rule name, expected: "{:s}", found: "{:s}"'

    def check_rule(self, ctx: Context, rule: Rule):
        expected = rule.name
        expected = expected.lower()
        expected = expected.replace(" ", "-")
        expected = expected.replace("(", "")
        expected = expected.replace(")", "")
        expected = expected.replace("+", "")
        expected = expected.replace("/", "")
        expected = expected.replace(".", "")
        expected = expected + ".yml"

        found = os.path.basename(rule.meta["capa/path"])

        self.recommendation = self.recommendation_template.format(expected, found)

        return expected != found


class MissingNamespace(Lint):
    name = "missing rule namespace"
    recommendation = "Add meta.namespace so that the rule is emitted correctly"

    def check_rule(self, ctx: Context, rule: Rule):
        return (
            "namespace" not in rule.meta
            and not is_nursery_rule(rule)
            and "maec/malware-category" not in rule.meta
            and "lib" not in rule.meta
        )


class NamespaceDoesntMatchRulePath(Lint):
    name = "file path doesn't match rule namespace"
    recommendation = "Move rule to appropriate directory or update the namespace"

    def check_rule(self, ctx: Context, rule: Rule):
        # let the other lints catch namespace issues
        if "namespace" not in rule.meta:
            return False
        if is_nursery_rule(rule):
            return False
        if "maec/malware-category" in rule.meta:
            return False
        if "lib" in rule.meta:
            return False

        return rule.meta["namespace"] not in get_normpath(rule.meta["capa/path"])


class MissingScope(Lint):
    name = "missing scope"
    recommendation = "Add meta.scope so that the scope is explicit (defaults to `function`)"

    def check_rule(self, ctx: Context, rule: Rule):
        return "scope" not in rule.meta


class InvalidScope(Lint):
    name = "invalid scope"
    recommendation = "Use only file, function, basic block, or instruction rule scopes"

    def check_rule(self, ctx: Context, rule: Rule):
        return rule.meta.get("scope") not in ("file", "function", "basic block", "instruction")


class MissingAuthor(Lint):
    name = "missing author"
    recommendation = "Add meta.author so that users know who to contact with questions"

    def check_rule(self, ctx: Context, rule: Rule):
        return "author" not in rule.meta


class MissingExamples(Lint):
    name = "missing examples"
    recommendation = "Add meta.examples so that the rule can be tested and verified"

    def check_rule(self, ctx: Context, rule: Rule):
        return (
            "examples" not in rule.meta
            or not isinstance(rule.meta["examples"], list)
            or len(rule.meta["examples"]) == 0
            or rule.meta["examples"] == [None]
        )


class MissingExampleOffset(Lint):
    name = "missing example offset"
    recommendation = "Add offset of example function"

    def check_rule(self, ctx: Context, rule: Rule):
        if rule.meta.get("scope") in ("function", "basic block"):
            examples = rule.meta.get("examples")
            if isinstance(examples, list):
                for example in examples:
                    if example and ":" not in example:
                        logger.debug("example: %s", example)
                        return True


class ExampleFileDNE(Lint):
    name = "referenced example doesn't exist"
    recommendation = "Add the referenced example to samples directory ($capa-root/tests/data or supplied via --samples)"

    def check_rule(self, ctx: Context, rule: Rule):
        if not rule.meta.get("examples"):
            # let the MissingExamples lint catch this case, don't double report.
            return False

        found = False
        for example in rule.meta.get("examples", []):
            if example:
                example_id = example.partition(":")[0]
                if example_id in ctx.samples:
                    found = True
                    break

        return not found


class InvalidAttckOrMbcTechnique(Lint):
    name = "att&ck/mbc entry is malformed or does not exist"
    recommendation = """
    The att&ck and mbc fields must respect the following format:
    <Tactic/Objective>::<Technique/Behavior> [<ID>]
    OR
    <Tactic/Objective>::<Technique/Behavior>::<Subtechnique/Method> [<ID.SubID>]
    """

    def __init__(self):
        super(InvalidAttckOrMbcTechnique, self).__init__()

        try:
            with open(f"{os.path.dirname(__file__)}/linter-data.json", "rb") as fd:
                self.data = json.load(fd)
            self.enabled_frameworks = self.data.keys()
        except BaseException:
            # If linter-data.json is not present, or if an error happen
            # we log an error and lint nothing.
            logger.warning(
                "Could not load 'scripts/linter-data.json'. The att&ck and mbc information will not be linted."
            )
            self.enabled_frameworks = []

        # This regex matches the format defined in the recommendation attribute
        self.reg = re.compile(r"^([\w\s-]+)::(.+) \[([A-Za-z0-9.]+)\]$")

    def _entry_check(self, framework, category, entry, eid):
        if category not in self.data[framework].keys():
            self.recommendation = f'Unknown category: "{category}"'
            return True
        if eid not in self.data[framework][category].keys():
            self.recommendation = f"Unknown entry ID: {eid}"
            return True
        if self.data[framework][category][eid] != entry:
            self.recommendation = (
                f'{eid} should be associated to entry "{self.data[framework][category][eid]}" instead of "{entry}"'
            )
            return True
        return False

    def check_rule(self, ctx: Context, rule: Rule):
        for framework in self.enabled_frameworks:
            if framework in rule.meta.keys():
                for r in rule.meta[framework]:
                    m = self.reg.match(r)
                    if m is None:
                        return True

                    args = m.group(1, 2, 3)
                    if self._entry_check(framework, *args):
                        return True
        return False


DEFAULT_SIGNATURES = capa.main.get_default_signatures()


def get_sample_capabilities(ctx: Context, path: Path) -> Set[str]:
    nice_path = os.path.abspath(str(path))
    if path in ctx.capabilities_by_sample:
        logger.debug("found cached results: %s: %d capabilities", nice_path, len(ctx.capabilities_by_sample[path]))
        return ctx.capabilities_by_sample[path]

    if nice_path.endswith(capa.helpers.EXTENSIONS_SHELLCODE_32):
        format_ = "sc32"
    elif nice_path.endswith(capa.helpers.EXTENSIONS_SHELLCODE_64):
        format_ = "sc64"
    else:
        format_ = "auto"

    logger.debug("analyzing sample: %s", nice_path)
    extractor = capa.main.get_extractor(
        nice_path, format_, capa.main.BACKEND_VIV, DEFAULT_SIGNATURES, False, disable_progress=True
    )

    capabilities, _ = capa.main.find_capabilities(ctx.rules, extractor, disable_progress=True)
    # mypy doesn't seem to be happy with the MatchResults type alias & set(...keys())?
    # so we ignore a few types here.
    capabilities = set(capabilities.keys())  # type: ignore
    assert isinstance(capabilities, set)

    logger.debug("computed results: %s: %d capabilities", nice_path, len(capabilities))
    ctx.capabilities_by_sample[path] = capabilities

    # when i (wb) run the linter in thorough mode locally,
    # the OS occasionally kills the process due to memory usage.
    # so, be extra aggressive in keeping memory usage down.
    #
    # tbh, im not sure this actually does anything, but maybe it helps?
    gc.collect()

    return capabilities


class DoesntMatchExample(Lint):
    name = "doesn't match on referenced example"
    recommendation = "Fix the rule logic or provide a different example"

    def check_rule(self, ctx: Context, rule: Rule):
        if not ctx.is_thorough:
            return False

        examples = rule.meta.get("examples", [])
        if not examples:
            return False

        for example in examples:
            example_id = example.partition(":")[0]
            try:
                path = ctx.samples[example_id]
            except KeyError:
                # lint ExampleFileDNE will catch this.
                # don't double report.
                continue

            try:
                capabilities = get_sample_capabilities(ctx, path)
            except Exception as e:
                logger.error("failed to extract capabilities: %s %s %s", rule.name, str(path), e, exc_info=True)
                return True

            if rule.name not in capabilities:
                return True


class StatementWithSingleChildStatement(Lint):
    name = "rule contains one or more statements with a single child statement"
    recommendation = "remove the superfluous parent statement"
    recommendation_template = "remove the superfluous parent statement: {:s}"
    violation = False

    def check_rule(self, ctx: Context, rule: Rule):
        self.violation = False

        def rec(statement, is_root=False):
            if isinstance(statement, (capa.engine.And, capa.engine.Or)):
                children = list(statement.get_children())
                if not is_root and len(children) == 1 and isinstance(children[0], capa.engine.Statement):
                    self.recommendation = self.recommendation_template.format(str(statement))
                    self.violation = True
                for child in children:
                    rec(child)

        rec(rule.statement, is_root=True)

        return self.violation


class OrStatementWithAlwaysTrueChild(Lint):
    name = "rule contains an `or` statement that's always True because of an `optional` or other child statement that's always True"
    recommendation = "clarify the rule logic, e.g. by moving the always True child statement"
    recommendation_template = "clarify the rule logic, e.g. by moving the always True child statement: {:s}"
    violation = False

    def check_rule(self, ctx: Context, rule: Rule):
        self.violation = False

        def rec(statement):
            if isinstance(statement, capa.engine.Or):
                children = list(statement.get_children())
                for child in children:
                    # `Some` implements `optional` which is an alias for `0 or more`
                    if isinstance(child, capa.engine.Some) and child.count == 0:
                        self.recommendation = self.recommendation_template.format(str(child))
                        self.violation = True
                    rec(child)

        rec(rule.statement)

        return self.violation


class NotNotUnderAnd(Lint):
    name = "rule contains a `not` statement that's not found under an `and` statement"
    recommendation = "clarify the rule logic and ensure `not` is always found under `and`"
    violation = False

    def check_rule(self, ctx: Context, rule: Rule):
        self.violation = False

        def rec(statement):
            if isinstance(statement, capa.engine.Statement):
                if not isinstance(statement, capa.engine.And):
                    for child in statement.get_children():
                        if isinstance(child, capa.engine.Not):
                            self.violation = True

                for child in statement.get_children():
                    rec(child)

        rec(rule.statement)

        return self.violation


class OptionalNotUnderAnd(Lint):
    name = "rule contains an `optional` or `0 or more` statement that's not found under an `and` statement"
    recommendation = "clarify the rule logic and ensure `optional` and `0 or more` is always found under `and`"
    violation = False

    def check_rule(self, ctx: Context, rule: Rule):
        self.violation = False

        def rec(statement):
            if isinstance(statement, capa.engine.Statement):
                if not isinstance(statement, capa.engine.And):
                    for child in statement.get_children():
                        if isinstance(child, capa.engine.Some) and child.count == 0:
                            self.violation = True

                for child in statement.get_children():
                    rec(child)

        rec(rule.statement)

        return self.violation


class UnusualMetaField(Lint):
    name = "unusual meta field"
    recommendation = "Remove the meta field"
    recommendation_template = 'Remove the meta field: "{:s}"'

    def check_rule(self, ctx: Context, rule: Rule):
        for key in rule.meta.keys():
            if key in capa.rules.META_KEYS:
                continue
            if key in capa.rules.HIDDEN_META_KEYS:
                continue
            self.recommendation = self.recommendation_template.format(key)
            return True

        return False


class LibRuleNotInLibDirectory(Lint):
    name = "lib rule not found in lib directory"
    recommendation = "Move the rule to the `lib` subdirectory of the rules path"

    def check_rule(self, ctx: Context, rule: Rule):
        if is_nursery_rule(rule):
            return False

        if "lib" not in rule.meta:
            return False

        return "lib/" not in get_normpath(rule.meta["capa/path"])


class LibRuleHasNamespace(Lint):
    name = "lib rule has a namespace"
    recommendation = "Remove the namespace from the rule"

    def check_rule(self, ctx: Context, rule: Rule):
        if "lib" not in rule.meta:
            return False

        return "namespace" in rule.meta


class FeatureStringTooShort(Lint):
    name = "feature string too short"
    recommendation = 'capa only extracts strings with length >= 4; will not match on "{:s}"'

    def check_features(self, ctx: Context, features: List[Feature]):
        for feature in features:
            if isinstance(feature, (capa.features.common.String, capa.features.common.Substring)):
                assert isinstance(feature.value, str)
                if len(feature.value) < 4:
                    self.recommendation = self.recommendation.format(feature.value)
                    return True
        return False


class FeatureNegativeNumber(Lint):
    name = "feature value is negative"
    recommendation = "specify the number's two's complement representation"
    recommendation_template = (
        "capa treats number features as unsigned values; you may specify the number's two's complement "
        'representation; will not match on "{:d}"'
    )

    def check_features(self, ctx: Context, features: List[Feature]):
        for feature in features:
            if isinstance(feature, (capa.features.insn.Number,)):
                assert isinstance(feature.value, int)
                if feature.value < 0:
                    self.recommendation = self.recommendation_template.format(feature.value)
                    return True
        return False


class FeatureNtdllNtoskrnlApi(Lint):
    name = "feature api may overlap with ntdll and ntoskrnl"
    level = Lint.WARN
    recommendation_template = (
        "check if {:s} is exported by both ntdll and ntoskrnl; if true, consider removing {:s} "
        "module requirement to improve detection"
    )

    def check_features(self, ctx: Context, features: List[Feature]):
        for feature in features:
            if isinstance(feature, capa.features.insn.API):
                assert isinstance(feature.value, str)
                modname, _, impname = feature.value.rpartition(".")

                if modname == "ntdll":
                    if impname in (
                        "LdrGetProcedureAddress",
                        "LdrLoadDll",
                        "NtCreateThread",
                        "NtCreatUserProcess",
                        "NtLoadDriver",
                        "NtQueryDirectoryObject",
                        "NtResumeThread",
                        "NtSuspendThread",
                        "NtTerminateProcess",
                        "NtWriteVirtualMemory",
                        "RtlGetNativeSystemInformation",
                        "NtCreateThreadEx",
                        "NtCreateUserProcess",
                        "NtOpenDirectoryObject",
                        "NtQueueApcThread",
                        "ZwResumeThread",
                        "ZwSuspendThread",
                        "ZwWriteVirtualMemory",
                        "NtCreateProcess",
                        "ZwCreateThread",
                        "NtCreateProcessEx",
                        "ZwCreateThreadEx",
                        "ZwCreateProcess",
                        "ZwCreateUserProcess",
                        "RtlCreateUserProcess",
                    ):
                        # ntoskrnl.exe does not export these routines
                        continue

                if modname == "ntoskrnl":
                    if impname in (
                        "PsGetVersion",
                        "PsLookupProcessByProcessId",
                        "KeStackAttachProcess",
                        "ObfDereferenceObject",
                        "KeUnstackDetachProcess",
                    ):
                        # ntdll.dll does not export these routines
                        continue

                if modname in ("ntdll", "ntoskrnl"):
                    self.recommendation = self.recommendation_template.format(impname, modname)
                    return True
        return False


class FormatLineFeedEOL(Lint):
    name = "line(s) end with CRLF (\\r\\n)"
    recommendation = "convert line endings to LF (\\n) for example using dos2unix"

    def check_rule(self, ctx: Context, rule: Rule):
        if len(rule.definition.split("\r\n")) > 0:
            return False
        return True


class FormatSingleEmptyLineEOF(Lint):
    name = "EOF format"
    recommendation = "end file with a single empty line"

    def check_rule(self, ctx: Context, rule: Rule):
        if rule.definition.endswith("\n") and not rule.definition.endswith("\n\n"):
            return False
        return True


class FormatIncorrect(Lint):
    name = "rule format incorrect"
    recommendation_template = "use scripts/capafmt.py or adjust as follows\n{:s}"

    def check_rule(self, ctx: Context, rule: Rule):
        actual = rule.definition
        expected = capa.rules.Rule.from_yaml(rule.definition, use_ruamel=True).to_yaml()

        if actual != expected:
            diff = difflib.ndiff(actual.splitlines(1), expected.splitlines(True))
            recommendation_template = self.recommendation_template
            if "\r\n" in actual:
                recommendation_template = (
                    self.recommendation_template + "\nplease make sure that the file uses LF (\\n) line endings only"
                )
            self.recommendation = recommendation_template.format("".join(diff))
            return True

        return False


class FormatStringQuotesIncorrect(Lint):
    name = "rule string quotes incorrect"

    def check_rule(self, ctx: Context, rule: Rule):
        events = capa.rules.Rule._get_ruamel_yaml_parser().parse(rule.definition)
        for key in events:
            if isinstance(key, ruamel.yaml.ScalarEvent) and key.value == "string":
                value = next(events)  # assume value is next event
                if not isinstance(value, ruamel.yaml.ScalarEvent):
                    # ignore non-scalar
                    continue
                if value.value.startswith("/") and value.value.endswith(("/", "/i")):
                    # ignore regex for now
                    continue
                if value.style is None:
                    # no quotes
                    self.recommendation = 'add double quotes to "%s"' % value.value
                    return True
                if value.style == "'":
                    # single quote
                    self.recommendation = 'change single quotes to double quotes for "%s"' % value.value
                    return True

            elif isinstance(key, ruamel.yaml.ScalarEvent) and key.value == "substring":
                value = next(events)  # assume value is next event
                if not isinstance(value, ruamel.yaml.ScalarEvent):
                    # ignore non-scalar
                    continue
                if value.style is None:
                    # no quotes
                    self.recommendation = 'add double quotes to "%s"' % value.value
                    return True
                if value.style == "'":
                    # single quote
                    self.recommendation = 'change single quotes to double quotes for "%s"' % value.value
                    return True

            else:
                continue

        return False


def run_lints(lints, ctx: Context, rule: Rule):
    for lint in lints:
        if lint.check_rule(ctx, rule):
            yield lint


def run_feature_lints(lints, ctx: Context, features: List[Feature]):
    for lint in lints:
        if lint.check_features(ctx, features):
            yield lint


NAME_LINTS = (
    NameCasing(),
    FilenameDoesntMatchRuleName(),
)


def lint_name(ctx: Context, rule: Rule):
    return run_lints(NAME_LINTS, ctx, rule)


SCOPE_LINTS = (
    MissingScope(),
    InvalidScope(),
)


def lint_scope(ctx: Context, rule: Rule):
    return run_lints(SCOPE_LINTS, ctx, rule)


META_LINTS = (
    MissingNamespace(),
    NamespaceDoesntMatchRulePath(),
    MissingAuthor(),
    MissingExamples(),
    MissingExampleOffset(),
    ExampleFileDNE(),
    UnusualMetaField(),
    LibRuleNotInLibDirectory(),
    LibRuleHasNamespace(),
    InvalidAttckOrMbcTechnique(),
)


def lint_meta(ctx: Context, rule: Rule):
    return run_lints(META_LINTS, ctx, rule)


FEATURE_LINTS = (FeatureStringTooShort(), FeatureNegativeNumber(), FeatureNtdllNtoskrnlApi())


def lint_features(ctx: Context, rule: Rule):
    features = get_features(ctx, rule)
    return run_feature_lints(FEATURE_LINTS, ctx, features)


FORMAT_LINTS = (
    FormatLineFeedEOL(),
    FormatSingleEmptyLineEOF(),
    FormatStringQuotesIncorrect(),
    FormatIncorrect(),
)


def lint_format(ctx: Context, rule: Rule):
    return run_lints(FORMAT_LINTS, ctx, rule)


def get_normpath(path):
    return posixpath.normpath(path).replace(os.sep, "/")


def get_features(ctx: Context, rule: Rule):
    # get features from rule and all dependencies including subscopes and matched rules
    features = []
    namespaces = ctx.rules.rules_by_namespace
    deps = [ctx.rules.rules[dep] for dep in rule.get_dependencies(namespaces)]
    for r in [rule] + deps:
        features.extend(get_rule_features(r))
    return features


def get_rule_features(rule):
    features = []

    def rec(statement):
        if isinstance(statement, capa.engine.Statement):
            for child in statement.get_children():
                rec(child)
        else:
            features.append(statement)

    rec(rule.statement)
    return features


LOGIC_LINTS = (
    DoesntMatchExample(),
    StatementWithSingleChildStatement(),
    OrStatementWithAlwaysTrueChild(),
    NotNotUnderAnd(),
    OptionalNotUnderAnd(),
)


def lint_logic(ctx: Context, rule: Rule):
    return run_lints(LOGIC_LINTS, ctx, rule)


def is_nursery_rule(rule):
    """
    The nursery is a spot for rules that have not yet been fully polished.
    For example, they may not have references to public example of a technique.
    Yet, we still want to capture and report on their matches.
    """
    return rule.meta.get("capa/nursery")


def lint_rule(ctx: Context, rule: Rule):
    logger.debug(rule.name)

    violations = list(
        itertools.chain(
            lint_name(ctx, rule),
            lint_scope(ctx, rule),
            lint_meta(ctx, rule),
            lint_logic(ctx, rule),
            lint_features(ctx, rule),
            lint_format(ctx, rule),
        )
    )

    if len(violations) > 0:
        # don't show nursery rules with a single violation: needs examples.
        # this is by far the most common reason to be in the nursery,
        # and ends up just producing a lot of noise.
        if not (is_nursery_rule(rule) and len(violations) == 1 and violations[0].name == "missing examples"):
            category = rule.meta.get("rule-category")

            print("")
            print(
                "%s%s %s"
                % (
                    "    (nursery) " if is_nursery_rule(rule) else "",
                    rule.name,
                    ("(%s)" % category) if category else "",
                )
            )

            for violation in violations:
                print(
                    "%s  %s: %s: %s"
                    % (
                        "    " if is_nursery_rule(rule) else "",
                        Lint.WARN if is_nursery_rule(rule) else violation.level,
                        violation.name,
                        violation.recommendation,
                    )
                )

            print("")

    if is_nursery_rule(rule):
        has_examples = not any(map(lambda v: v.level == Lint.FAIL and v.name == "missing examples", violations))
        lints_failed = len(
            tuple(
                filter(
                    lambda v: v.level == Lint.FAIL
                    and not (v.name == "missing examples" or v.name == "referenced example doesn't exist"),
                    violations,
                )
            )
        )
        lints_warned = len(
            tuple(
                filter(
                    lambda v: v.level == Lint.WARN
                    or (v.level == Lint.FAIL and v.name == "referenced example doesn't exist"),
                    violations,
                )
            )
        )

        if (not lints_failed) and (not lints_warned) and has_examples:
            print("")
            print("%s%s" % ("    (nursery) ", rule.name))
            print("%s  %s: %s: %s" % ("    ", Lint.WARN, green("no lint failures"), "Graduate the rule"))
            print("")
    else:
        lints_failed = len(tuple(filter(lambda v: v.level == Lint.FAIL, violations)))
        lints_warned = len(tuple(filter(lambda v: v.level == Lint.WARN, violations)))

    return (lints_failed, lints_warned)


def width(s, count):
    if len(s) > count:
        return s[: count - 3] + "..."
    else:
        return s.ljust(count)


@contextlib.contextmanager
def redirecting_print_to_tqdm():
    """
    tqdm (progress bar) expects to have fairly tight control over console output.
    so calls to `print()` will break the progress bar and make things look bad.
    so, this context manager temporarily replaces the `print` implementation
    with one that is compatible with tqdm.

    via: https://stackoverflow.com/a/42424890/87207
    """
    old_print = print

    def new_print(*args, **kwargs):

        # If tqdm.tqdm.write raises error, use builtin print
        try:
            tqdm.tqdm.write(*args, **kwargs)
        except:
            old_print(*args, **kwargs)

    try:
        # Globaly replace print with new_print
        inspect.builtins.print = new_print
        yield
    finally:
        inspect.builtins.print = old_print


def lint(ctx: Context):
    """
    Returns: Dict[string, Tuple(int, int)]
      - # lints failed
      - # lints warned
    """
    ret = {}

    with tqdm.contrib.logging.tqdm_logging_redirect(ctx.rules.rules.items(), unit="rule") as pbar:
        with redirecting_print_to_tqdm():
            for name, rule in pbar:
                if rule.meta.get("capa/subscope-rule", False):
                    continue

                pbar.set_description(width("linting rule: %s" % (name), 48))
                ret[name] = lint_rule(ctx, rule)

    return ret


def collect_samples(path) -> Dict[str, Path]:
    """
    recurse through the given path, collecting all file paths, indexed by their content sha256, md5, and filename.
    """
    samples = {}
    for root, dirs, files in os.walk(path):
        for name in files:
            if name.endswith(".viv"):
                continue
            if name.endswith(".idb"):
                continue
            if name.endswith(".i64"):
                continue
            if name.endswith(".frz"):
                continue
            if name.endswith(".fnames"):
                continue

            path = pathlib.Path(os.path.join(root, name))

            try:
                with path.open("rb") as f:
                    buf = f.read()
            except IOError:
                continue

            sha256 = hashlib.sha256()
            sha256.update(buf)

            md5 = hashlib.md5()
            md5.update(buf)

            samples[sha256.hexdigest().lower()] = path
            samples[sha256.hexdigest().upper()] = path
            samples[md5.hexdigest().lower()] = path
            samples[md5.hexdigest().upper()] = path
            samples[name] = path

    return samples


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    samples_path = os.path.join(os.path.dirname(__file__), "..", "tests", "data")

    parser = argparse.ArgumentParser(description="Lint capa rules.")
    capa.main.install_common_args(parser, wanted={"tag"})
    parser.add_argument("rules", type=str, action="append", help="Path to rules")
    parser.add_argument("--samples", type=str, default=samples_path, help="Path to samples")
    parser.add_argument(
        "--thorough",
        action="store_true",
        help="Enable thorough linting - takes more time, but does a better job",
    )
    args = parser.parse_args(args=argv)
    capa.main.handle_common_args(args)

    if args.debug:
        logging.getLogger("capa").setLevel(logging.DEBUG)
        logging.getLogger("viv_utils").setLevel(logging.DEBUG)
    else:
        logging.getLogger("capa").setLevel(logging.ERROR)
        logging.getLogger("viv_utils").setLevel(logging.ERROR)

    time0 = time.time()

    try:
        rules = capa.main.get_rules(args.rules, disable_progress=True)
        rules = capa.rules.RuleSet(rules)
        logger.info("successfully loaded %s rules", len(rules))
        if args.tag:
            rules = rules.filter_rules_by_meta(args.tag)
            logger.debug("selected %s rules", len(rules))
            for i, r in enumerate(rules.rules, 1):
                logger.debug(" %d. %s", i, r)
    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        logger.error("%s", str(e))
        return -1

    logger.info("collecting potentially referenced samples")
    if not os.path.exists(args.samples):
        logger.error("samples path %s does not exist", args.samples)
        return -1

    samples = collect_samples(args.samples)

    ctx = Context(samples=samples, rules=rules, is_thorough=args.thorough)

    results_by_name = lint(ctx)
    failed_rules = []
    warned_rules = []
    for name, (fail_count, warn_count) in results_by_name.items():
        if fail_count > 0:
            failed_rules.append(name)

        if warn_count > 0:
            warned_rules.append(name)

    min, sec = divmod(time.time() - time0, 60)
    logger.debug("lints ran for ~ %02d:%02dm", min, sec)

    if warned_rules:
        print(orange("rules with WARN:"))
        for warned_rule in sorted(warned_rules):
            print("  - " + warned_rule)
        print()

    if failed_rules:
        print(red("rules with FAIL:"))
        for failed_rule in sorted(failed_rules):
            print("  - " + failed_rule)
        return 1
    else:
        logger.info(green("no lints failed, nice!"))
        return 0


if __name__ == "__main__":
    sys.exit(main())
