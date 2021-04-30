"""
Check the given capa rules for style issues.

Usage:

   $ python scripts/lint.py rules/

Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
import os
import sys
import time
import string
import difflib
import hashlib
import logging
import os.path
import argparse
import itertools
import posixpath

import ruamel.yaml

import capa.main
import capa.rules
import capa.engine
import capa.features
import capa.features.insn

logger = logging.getLogger("lint")


class Lint(object):
    WARN = "WARN"
    FAIL = "FAIL"

    name = "lint"
    level = FAIL
    recommendation = ""

    def check_rule(self, ctx, rule):
        return False


class NameCasing(Lint):
    name = "rule name casing"
    recommendation = "Rename rule using to start with lower case letters"

    def check_rule(self, ctx, rule):
        return rule.name[0] in string.ascii_uppercase and rule.name[1] not in string.ascii_uppercase


class FilenameDoesntMatchRuleName(Lint):
    name = "filename doesn't match the rule name"
    recommendation = "Rename rule file to match the rule name"
    recommendation_template = 'Rename rule file to match the rule name, expected: "{:s}", found: "{:s}"'

    def check_rule(self, ctx, rule):
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

    def check_rule(self, ctx, rule):
        return (
            "namespace" not in rule.meta
            and not is_nursery_rule(rule)
            and "maec/malware-category" not in rule.meta
            and "lib" not in rule.meta
        )


class NamespaceDoesntMatchRulePath(Lint):
    name = "file path doesn't match rule namespace"
    recommendation = "Move rule to appropriate directory or update the namespace"

    def check_rule(self, ctx, rule):
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

    def check_rule(self, ctx, rule):
        return "scope" not in rule.meta


class InvalidScope(Lint):
    name = "invalid scope"
    recommendation = "Use only file, function, or basic block rule scopes"

    def check_rule(self, ctx, rule):
        return rule.meta.get("scope") not in ("file", "function", "basic block")


class MissingAuthor(Lint):
    name = "missing author"
    recommendation = "Add meta.author so that users know who to contact with questions"

    def check_rule(self, ctx, rule):
        return "author" not in rule.meta


class MissingExamples(Lint):
    name = "missing examples"
    recommendation = "Add meta.examples so that the rule can be tested and verified"

    def check_rule(self, ctx, rule):
        return (
            "examples" not in rule.meta
            or not isinstance(rule.meta["examples"], list)
            or len(rule.meta["examples"]) == 0
            or rule.meta["examples"] == [None]
        )


class MissingExampleOffset(Lint):
    name = "missing example offset"
    recommendation = "Add offset of example function"

    def check_rule(self, ctx, rule):
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

    def check_rule(self, ctx, rule):
        if not rule.meta.get("examples"):
            # let the MissingExamples lint catch this case, don't double report.
            return False

        found = False
        for example in rule.meta.get("examples", []):
            if example:
                example_id = example.partition(":")[0]
                if example_id in ctx["samples"]:
                    found = True
                    break

        return not found


DEFAULT_SIGNATURES = capa.main.get_default_signatures()


class DoesntMatchExample(Lint):
    name = "doesn't match on referenced example"
    recommendation = "Fix the rule logic or provide a different example"

    def check_rule(self, ctx, rule):
        if not ctx["is_thorough"]:
            return False

        examples = rule.meta.get("examples", [])
        if not examples:
            return False

        for example in examples:
            example_id = example.partition(":")[0]
            try:
                path = ctx["samples"][example_id]
            except KeyError:
                # lint ExampleFileDNE will catch this.
                # don't double report.
                continue

            try:
                extractor = capa.main.get_extractor(
                    path, "auto", capa.main.BACKEND_VIV, sigpaths=DEFAULT_SIGNATURES, disable_progress=True
                )
                capabilities, meta = capa.main.find_capabilities(ctx["rules"], extractor, disable_progress=True)
            except Exception as e:
                logger.error("failed to extract capabilities: %s %s %s", rule.name, path, e)
                return True

            if rule.name not in capabilities:
                return True


class UnusualMetaField(Lint):
    name = "unusual meta field"
    recommendation = "Remove the meta field"
    recommendation_template = 'Remove the meta field: "{:s}"'

    def check_rule(self, ctx, rule):
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

    def check_rule(self, ctx, rule):
        if is_nursery_rule(rule):
            return False

        if "lib" not in rule.meta:
            return False

        return "lib/" not in get_normpath(rule.meta["capa/path"])


class LibRuleHasNamespace(Lint):
    name = "lib rule has a namespace"
    recommendation = "Remove the namespace from the rule"

    def check_rule(self, ctx, rule):
        if "lib" not in rule.meta:
            return False

        return "namespace" in rule.meta


class FeatureStringTooShort(Lint):
    name = "feature string too short"
    recommendation = 'capa only extracts strings with length >= 4; will not match on "{:s}"'

    def check_features(self, ctx, features):
        for feature in features:
            if isinstance(feature, capa.features.String):
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

    def check_features(self, ctx, features):
        for feature in features:
            if isinstance(feature, (capa.features.insn.Number,)):
                if feature.value < 0:
                    self.recommendation = self.recommendation_template.format(feature.value)
                    return True
        return False


class FeatureNtdllNtoskrnlApi(Lint):
    name = "feature api may overlap with ntdll and ntoskrnl"
    level = Lint.WARN
    recommendation = (
        "check if {:s} is exported by both ntdll and ntoskrnl; if true, consider removing {:s} "
        "module requirement to improve detection"
    )

    def check_features(self, ctx, features):
        for feature in features:
            if isinstance(feature, capa.features.insn.API):
                modname, _, impname = feature.value.rpartition(".")
                if modname in ("ntdll", "ntoskrnl"):
                    self.recommendation = self.recommendation.format(impname, modname)
                    return True
        return False


class FormatLineFeedEOL(Lint):
    name = "line(s) end with CRLF (\\r\\n)"
    recommendation = "convert line endings to LF (\\n) for example using dos2unix"

    def check_rule(self, ctx, rule):
        if len(rule.definition.split("\r\n")) > 0:
            return False
        return True


class FormatSingleEmptyLineEOF(Lint):
    name = "EOF format"
    recommendation = "end file with a single empty line"

    def check_rule(self, ctx, rule):
        if rule.definition.endswith("\n") and not rule.definition.endswith("\n\n"):
            return False
        return True


class FormatIncorrect(Lint):
    name = "rule format incorrect"
    recommendation_template = "use scripts/capafmt.py or adjust as follows\n{:s}"

    def check_rule(self, ctx, rule):
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

    def check_rule(self, ctx, rule):
        events = capa.rules.Rule._get_ruamel_yaml_parser().parse(rule.definition)
        for key in events:
            if not (isinstance(key, ruamel.yaml.ScalarEvent) and key.value == "string"):
                continue
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
        return False


def run_lints(lints, ctx, rule):
    for lint in lints:
        if lint.check_rule(ctx, rule):
            yield lint


def run_feature_lints(lints, ctx, features):
    for lint in lints:
        if lint.check_features(ctx, features):
            yield lint


NAME_LINTS = (
    NameCasing(),
    FilenameDoesntMatchRuleName(),
)


def lint_name(ctx, rule):
    return run_lints(NAME_LINTS, ctx, rule)


SCOPE_LINTS = (
    MissingScope(),
    InvalidScope(),
)


def lint_scope(ctx, rule):
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
)


def lint_meta(ctx, rule):
    return run_lints(META_LINTS, ctx, rule)


FEATURE_LINTS = (FeatureStringTooShort(), FeatureNegativeNumber(), FeatureNtdllNtoskrnlApi())


def lint_features(ctx, rule):
    features = get_features(ctx, rule)
    return run_feature_lints(FEATURE_LINTS, ctx, features)


FORMAT_LINTS = (
    FormatLineFeedEOL(),
    FormatSingleEmptyLineEOF(),
    FormatStringQuotesIncorrect(),
    FormatIncorrect(),
)


def lint_format(ctx, rule):
    return run_lints(FORMAT_LINTS, ctx, rule)


def get_normpath(path):
    return posixpath.normpath(path).replace(os.sep, "/")


def get_features(ctx, rule):
    # get features from rule and all dependencies including subscopes and matched rules
    features = []
    namespaces = capa.rules.index_rules_by_namespace([rule])
    deps = [ctx["rules"].rules[dep] for dep in rule.get_dependencies(namespaces)]
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


LOGIC_LINTS = (DoesntMatchExample(),)


def lint_logic(ctx, rule):
    return run_lints(LOGIC_LINTS, ctx, rule)


def is_nursery_rule(rule):
    """
    The nursery is a spot for rules that have not yet been fully polished.
    For example, they may not have references to public example of a technique.
    Yet, we still want to capture and report on their matches.
    """
    return rule.meta.get("capa/nursery")


def lint_rule(ctx, rule):
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

    lints_failed = any(map(lambda v: v.level == Lint.FAIL, violations))

    if not lints_failed and is_nursery_rule(rule):
        print("")
        print("%s%s" % ("    (nursery) ", rule.name))
        print("%s  %s: %s: %s" % ("    ", Lint.WARN, "no lint failures", "Graduate the rule"))
        print("")

    return lints_failed and not is_nursery_rule(rule)


def lint(ctx, rules):
    """
    Args:
      samples (Dict[string, string]): map from sample id to path.
        for each sample, record sample id of sha256, md5, and filename.
        see `collect_samples(path)`.
      rules (List[Rule]): the rules to lint.
    """
    did_suggest_fix = False
    for rule in rules.rules.values():
        if rule.meta.get("capa/subscope-rule", False):
            continue

        did_suggest_fix = lint_rule(ctx, rule) or did_suggest_fix

    return did_suggest_fix


def collect_samples(path):
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

            path = os.path.join(root, name)

            try:
                with open(path, "rb") as f:
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
    parser.add_argument("rules", type=str, help="Path to rules")
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

    ctx = {
        "samples": samples,
        "rules": rules,
        "is_thorough": args.thorough,
    }

    did_violate = lint(ctx, rules)

    min, sec = divmod(time.time() - time0, 60)
    logger.debug("lints ran for ~ %02d:%02dm", min, sec)

    if not did_violate:
        logger.info("no lints failed, nice!")
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
