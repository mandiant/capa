#!/usr/bin/env python2
"""
identify capabilities in programs.

Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
"""
import os
import sys
import hashlib
import logging
import os.path
import argparse
import datetime
import textwrap
import collections

import tqdm
import colorama

import capa.rules
import capa.engine
import capa.render
import capa.version
import capa.features
import capa.features.freeze
import capa.features.extractors
from capa.helpers import oint, get_file_taste

RULES_PATH_DEFAULT_STRING = "(embedded rules)"
SUPPORTED_FILE_MAGIC = set(["MZ"])


logger = logging.getLogger("capa")


def set_vivisect_log_level(level):
    logging.getLogger("vivisect").setLevel(level)
    logging.getLogger("vtrace").setLevel(level)
    logging.getLogger("envi").setLevel(level)


def find_function_capabilities(ruleset, extractor, f):
    # contains features from:
    #  - insns
    #  - function
    function_features = collections.defaultdict(set)
    bb_matches = collections.defaultdict(list)

    for feature, va in extractor.extract_function_features(f):
        function_features[feature].add(va)

    for bb in extractor.get_basic_blocks(f):
        # contains features from:
        #  - insns
        #  - basic blocks
        bb_features = collections.defaultdict(set)

        for feature, va in extractor.extract_basic_block_features(f, bb):
            bb_features[feature].add(va)
            function_features[feature].add(va)

        for insn in extractor.get_instructions(f, bb):
            for feature, va in extractor.extract_insn_features(f, bb, insn):
                bb_features[feature].add(va)
                function_features[feature].add(va)

        _, matches = capa.engine.match(ruleset.basic_block_rules, bb_features, oint(bb))

        for rule_name, res in matches.items():
            bb_matches[rule_name].extend(res)
            for va, _ in res:
                function_features[capa.features.MatchedRule(rule_name)].add(va)

    _, function_matches = capa.engine.match(ruleset.function_rules, function_features, oint(f))
    return function_matches, bb_matches, len(function_features)


def find_file_capabilities(ruleset, extractor, function_features):
    file_features = collections.defaultdict(set)

    for feature, va in extractor.extract_file_features():
        # not all file features may have virtual addresses.
        # if not, then at least ensure the feature shows up in the index.
        # the set of addresses will still be empty.
        if va:
            file_features[feature].add(va)
        else:
            if feature not in file_features:
                file_features[feature] = set()

    logger.debug("analyzed file and extracted %d features", len(file_features))

    file_features.update(function_features)

    _, matches = capa.engine.match(ruleset.file_rules, file_features, 0x0)
    return matches, len(file_features)


def find_capabilities(ruleset, extractor, disable_progress=None):
    all_function_matches = collections.defaultdict(list)
    all_bb_matches = collections.defaultdict(list)

    meta = {"feature_counts": {"file": 0, "functions": {},}}

    for f in tqdm.tqdm(extractor.get_functions(), disable=disable_progress, unit=" functions"):
        function_matches, bb_matches, feature_count = find_function_capabilities(ruleset, extractor, f)
        meta["feature_counts"]["functions"][f.__int__()] = feature_count
        logger.debug("analyzed function 0x%x and extracted %d features", f.__int__(), feature_count)

        for rule_name, res in function_matches.items():
            all_function_matches[rule_name].extend(res)
        for rule_name, res in bb_matches.items():
            all_bb_matches[rule_name].extend(res)

    # mapping from matched rule feature to set of addresses at which it matched.
    # schema: Dic[MatchedRule: Set[int]
    function_features = {
        capa.features.MatchedRule(rule_name): set(map(lambda p: p[0], results))
        for rule_name, results in all_function_matches.items()
    }

    all_file_matches, feature_count = find_file_capabilities(ruleset, extractor, function_features)
    meta["feature_counts"]["file"] = feature_count

    matches = {}
    matches.update(all_bb_matches)
    matches.update(all_function_matches)
    matches.update(all_file_matches)

    return matches, meta


def has_rule_with_namespace(rules, capabilities, rule_cat):
    for rule_name in capabilities.keys():
        if rules.rules[rule_name].meta.get("namespace", "").startswith(rule_cat):
            return True
    return False


def has_file_limitation(rules, capabilities, is_standalone=True):
    file_limitations = {
        # capa will likely detect installer specific functionality.
        # this is probably not what the user wants.
        "executable/installer": [
            " This sample appears to be an installer.",
            " ",
            " capa cannot handle installers well. This means the results may be misleading or incomplete."
            " You should try to understand the install mechanism and analyze created files with capa.",
        ],
        # capa won't detect much in .NET samples.
        # it might match some file-level things.
        # for consistency, bail on things that we don't support.
        "runtime/dotnet": [
            " This sample appears to be a .NET module.",
            " ",
            " .NET is a cross-platform framework for running managed applications.",
            " capa cannot handle non-native files. This means that the results may be misleading or incomplete.",
            " You may have to analyze the file manually, using a tool like the .NET decompiler dnSpy.",
        ],
        # capa will detect dozens of capabilities for AutoIt samples,
        # but these are due to the AutoIt runtime, not the payload script.
        # so, don't confuse the user with FP matches - bail instead
        "compiler/autoit": [
            " This sample appears to be compiled with AutoIt.",
            " ",
            " AutoIt is a freeware BASIC-like scripting language designed for automating the Windows GUI.",
            " capa cannot handle AutoIt scripts. This means that the results will be misleading or incomplete.",
            " You may have to analyze the file manually, using a tool like the AutoIt decompiler MyAut2Exe.",
        ],
        # capa won't detect much in packed samples
        "anti-analysis/packer/": [
            " This sample appears to be packed.",
            " ",
            " Packed samples have often been obfuscated to hide their logic.",
            " capa cannot handle obfuscation well. This means the results may be misleading or incomplete.",
            " If possible, you should try to unpack this input file before analyzing it with capa.",
        ],
    }

    for category, dialogue in file_limitations.items():
        if not has_rule_with_namespace(rules, capabilities, category):
            continue
        logger.warning("-" * 80)
        for line in dialogue:
            logger.warning(line)
        if is_standalone:
            logger.warning(" ")
            logger.warning(" Use -v or -vv if you really want to see the capabilities identified by capa.")
        logger.warning("-" * 80)
        return True
    return False


def is_supported_file_type(sample):
    """
    Return if this is a supported file based on magic header values
    """
    with open(sample, "rb") as f:
        magic = f.read(2)
    if magic in SUPPORTED_FILE_MAGIC:
        return True
    else:
        return False


SHELLCODE_BASE = 0x690000


def get_shellcode_vw(sample, arch="auto"):
    """
    Return shellcode workspace using explicit arch or via auto detect
    """
    import viv_utils

    with open(sample, "rb") as f:
        sample_bytes = f.read()
    if arch == "auto":
        # choose arch with most functions, idea by Jay G.
        vw_cands = []
        for arch in ["i386", "amd64"]:
            vw_cands.append(viv_utils.getShellcodeWorkspace(sample_bytes, arch, base=SHELLCODE_BASE))
        if not vw_cands:
            raise ValueError("could not generate vivisect workspace")
        vw = max(vw_cands, key=lambda vw: len(vw.getFunctions()))
    else:
        vw = viv_utils.getShellcodeWorkspace(sample_bytes, arch, base=SHELLCODE_BASE)
    return vw


def get_meta_str(vw):
    """
    Return workspace meta information string
    """
    meta = []
    for k in ["Format", "Platform", "Architecture"]:
        if k in vw.metadata:
            meta.append("%s: %s" % (k.lower(), vw.metadata[k]))
    return "%s, number of functions: %d" % (", ".join(meta), len(vw.getFunctions()))


class UnsupportedFormatError(ValueError):
    pass


def get_workspace(path, format):
    import viv_utils

    logger.debug("generating vivisect workspace for: %s", path)
    if format == "auto":
        if not is_supported_file_type(path):
            raise UnsupportedFormatError()
        vw = viv_utils.getWorkspace(path)
    elif format == "pe":
        vw = viv_utils.getWorkspace(path)
    elif format == "sc32":
        vw = get_shellcode_vw(path, arch="i386")
    elif format == "sc64":
        vw = get_shellcode_vw(path, arch="amd64")
    logger.debug("%s", get_meta_str(vw))
    return vw


def get_extractor_py2(path, format):
    import capa.features.extractors.viv

    vw = get_workspace(path, format)
    return capa.features.extractors.viv.VivisectFeatureExtractor(vw, path)


class UnsupportedRuntimeError(RuntimeError):
    pass


def get_extractor_py3(path, format):
    raise UnsupportedRuntimeError()


def get_extractor(path, format):
    """
    raises:
      UnsupportedFormatError:
    """
    if sys.version_info >= (3, 0):
        return get_extractor_py3(path, format)
    else:
        return get_extractor_py2(path, format)


def is_nursery_rule_path(path):
    """
    The nursery is a spot for rules that have not yet been fully polished.
    For example, they may not have references to public example of a technique.
    Yet, we still want to capture and report on their matches.
    The nursery is currently a subdirectory of the rules directory with that name.

    When nursery rules are loaded, their metadata section should be updated with:
      `nursery=True`.
    """
    return "nursery" in path


def get_rules(rule_path):
    if not os.path.exists(rule_path):
        raise IOError("rule path %s does not exist or cannot be accessed" % rule_path)

    rule_paths = []
    if os.path.isfile(rule_path):
        rule_paths.append(rule_path)
    elif os.path.isdir(rule_path):
        logger.debug("reading rules from directory %s", rule_path)
        for root, dirs, files in os.walk(rule_path):
            if ".github" in root:
                # the .github directory contains CI config in capa-rules
                # this includes some .yml files
                # these are not rules
                continue

            for file in files:
                if not file.endswith(".yml"):
                    if not (file.endswith(".md") or file.endswith(".git")):
                        # expect to see readme.md, format.md, and maybe a .git directory
                        # other things maybe are rules, but are mis-named.
                        logger.warning("skipping non-.yml file: %s", file)
                    continue

                rule_path = os.path.join(root, file)
                rule_paths.append(rule_path)

    rules = []
    for rule_path in rule_paths:
        try:
            rule = capa.rules.Rule.from_yaml_file(rule_path)
        except capa.rules.InvalidRule:
            raise
        else:
            rule.meta["capa/path"] = rule_path
            if is_nursery_rule_path(rule_path):
                rule.meta["capa/nursery"] = True

            rules.append(rule)
            logger.debug("loaded rule: '%s' with scope: %s", rule.name, rule.scope)

    return rules


def collect_metadata(argv, sample_path, rules_path, format, extractor):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(sample_path, "rb") as f:
        buf = f.read()

    md5.update(buf)
    sha1.update(buf)
    sha256.update(buf)

    if rules_path != RULES_PATH_DEFAULT_STRING:
        rules_path = os.path.abspath(os.path.normpath(rules_path))

    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "version": capa.version.__version__,
        "argv": argv,
        "sample": {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
            "path": os.path.normpath(sample_path),
        },
        "analysis": {
            "format": format,
            "extractor": extractor.__class__.__name__,
            "rules": rules_path,
            "base_address": extractor.get_base_address(),
        },
    }


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    formats = [
        ("auto", "(default) detect file type automatically"),
        ("pe", "Windows PE file"),
        ("sc32", "32-bit shellcode"),
        ("sc64", "64-bit shellcode"),
        ("freeze", "features previously frozen by capa"),
    ]
    format_help = ", ".join(["%s: %s" % (f[0], f[1]) for f in formats])

    epilog = textwrap.dedent(
        """
        By default, capa uses a default set of embedded rules.
        You can see the rule set here:
          https://github.com/fireeye/capa-rules

        To provide your own rule set, use the `-r` flag:
          capa  --rules /path/to/rules  suspicious.exe
          capa  -r      /path/to/rules  suspicious.exe

        examples:
          identify capabilities in a binary
            capa suspicous.exe

          identify capabilities in 32-bit shellcode, see `-f` for all supported formats
            capa -f sc32 shellcode.bin

          report match locations
            capa -v suspicous.exe

          report all feature match details
            capa -vv suspicious.exe

          filter rules by meta fields, e.g. rule name or namespace
            capa -t "create TCP socket" suspicious.exe
         """
    )

    parser = argparse.ArgumentParser(
        description=__doc__, epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("sample", type=str, help="path to sample to analyze")
    parser.add_argument("--version", action="version", version="%(prog)s {:s}".format(capa.version.__version__))
    parser.add_argument(
        "-r",
        "--rules",
        type=str,
        default=RULES_PATH_DEFAULT_STRING,
        help="path to rule file or directory, use embedded rules by default",
    )
    parser.add_argument(
        "-f", "--format", choices=[f[0] for f in formats], default="auto", help="select sample format, %s" % format_help
    )
    parser.add_argument("-t", "--tag", type=str, help="filter on rule meta field values")
    parser.add_argument("-j", "--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="enable verbose result document (no effect with --json)"
    )
    parser.add_argument(
        "-vv", "--vverbose", action="store_true", help="enable very verbose result document (no effect with --json)"
    )
    parser.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
    parser.add_argument("-q", "--quiet", action="store_true", help="disable all output but errors")
    parser.add_argument(
        "--color",
        type=str,
        choices=("auto", "always", "never"),
        default="auto",
        help="enable ANSI color codes in results, default: only during interactive session",
    )
    args = parser.parse_args(args=argv)

    if args.quiet:
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger().setLevel(logging.WARNING)
    elif args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    # disable vivisect-related logging, it's verbose and not relevant for capa users
    set_vivisect_log_level(logging.CRITICAL)

    try:
        taste = get_file_taste(args.sample)
    except IOError as e:
        logger.error("%s", str(e))
        return -1

    # py2 doesn't know about cp65001, which is a variant of utf-8 on windows
    # tqdm bails when trying to render the progress bar in this setup.
    # because cp65001 is utf-8, we just map that codepage to the utf-8 codec.
    # see #380 and: https://stackoverflow.com/a/3259271/87207
    import codecs

    codecs.register(lambda name: codecs.lookup("utf-8") if name == "cp65001" else None)

    if args.rules == RULES_PATH_DEFAULT_STRING:
        logger.debug("-" * 80)
        logger.debug(" Using default embedded rules.")
        logger.debug(" To provide your own rules, use the form `capa.exe -r ./path/to/rules/  /path/to/mal.exe`.")
        logger.debug(" You can see the current default rule set here:")
        logger.debug("     https://github.com/fireeye/capa-rules")
        logger.debug("-" * 80)

        if hasattr(sys, "frozen") and hasattr(sys, "_MEIPASS"):
            logger.debug("detected running under PyInstaller")
            rules_path = os.path.join(sys._MEIPASS, "rules")
            logger.debug("default rule path (PyInstaller method): %s", rules_path)
        else:
            logger.debug("detected running from source")
            rules_path = os.path.join(os.path.dirname(__file__), "..", "rules")
            logger.debug("default rule path (source method): %s", rules_path)

        if not os.path.exists(rules_path):
            # when a users installs capa via pip,
            # this pulls down just the source code - not the default rules.
            # i'm not sure the default rules should even be written to the library directory,
            # so in this case, we require the user to use -r to specify the rule directory.
            logger.error("default embedded rules not found! (maybe you installed capa as a library?)")
            logger.error("provide your own rule set via the `-r` option.")
            return -1
    else:
        rules_path = args.rules
        logger.debug("using rules path: %s", rules_path)

    try:
        rules = get_rules(rules_path)
        rules = capa.rules.RuleSet(rules)
        logger.debug("successfully loaded %s rules", len(rules))
        if args.tag:
            rules = rules.filter_rules_by_meta(args.tag)
            logger.debug("selected %s rules", len(rules))
            for i, r in enumerate(rules.rules, 1):
                # TODO don't display subscope rules?
                logger.debug(" %d. %s", i, r)
    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        logger.error("%s", str(e))
        return -1

    if (args.format == "freeze") or (args.format == "auto" and capa.features.freeze.is_freeze(taste)):
        format = "freeze"
        with open(args.sample, "rb") as f:
            extractor = capa.features.freeze.load(f.read())
    else:
        format = args.format
        try:
            extractor = get_extractor(args.sample, args.format)
        except UnsupportedFormatError:
            logger.error("-" * 80)
            logger.error(" Input file does not appear to be a PE file.")
            logger.error(" ")
            logger.error(
                " capa currently only supports analyzing PE files (or shellcode, when using --format sc32|sc64)."
            )
            logger.error(" If you don't know the input file type, you can try using the `file` utility to guess it.")
            logger.error("-" * 80)
            return -1
        except UnsupportedRuntimeError:
            logger.error("-" * 80)
            logger.error(" Unsupported runtime or Python interpreter.")
            logger.error(" ")
            logger.error(" capa supports running under Python 2.7 using Vivisect for binary analysis.")
            logger.error(" It can also run within IDA Pro, using either Python 2.7 or 3.5+.")
            logger.error(" ")
            logger.error(" If you're seeing this message on the command line, please ensure you're running Python 2.7.")
            logger.error("-" * 80)
            return -1

    meta = collect_metadata(argv, args.sample, args.rules, format, extractor)

    capabilities, counts = find_capabilities(rules, extractor)
    meta["analysis"].update(counts)

    if has_file_limitation(rules, capabilities):
        # bail if capa encountered file limitation e.g. a packed binary
        # do show the output in verbose mode, though.
        if not (args.verbose or args.vverbose or args.json):
            return -1

    if args.color == "always":
        colorama.init(strip=False)
    elif args.color == "auto":
        # colorama will detect:
        #  - when on Windows console, and fixup coloring, and
        #  - when not an interactive session, and disable coloring
        # renderers should use coloring and assume it will be stripped out if necessary.
        colorama.init()
    elif args.color == "never":
        colorama.init(strip=True)
    else:
        raise RuntimeError("unexpected --color value: " + args.color)

    if args.json:
        print(capa.render.render_json(meta, rules, capabilities))
    elif args.vverbose:
        print(capa.render.render_vverbose(meta, rules, capabilities))
    elif args.verbose:
        print(capa.render.render_verbose(meta, rules, capabilities))
    else:
        print(capa.render.render_default(meta, rules, capabilities))
    colorama.deinit()

    logger.debug("done.")

    return 0


def ida_main():
    import capa.ida.helpers
    import capa.features.extractors.ida

    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    if not capa.ida.helpers.is_supported_file_type():
        return -1

    logger.debug("-" * 80)
    logger.debug(" Using default embedded rules.")
    logger.debug(" ")
    logger.debug(" You can see the current default rule set here:")
    logger.debug("     https://github.com/fireeye/capa-rules")
    logger.debug("-" * 80)

    if hasattr(sys, "frozen") and hasattr(sys, "_MEIPASS"):
        logger.debug("detected running under PyInstaller")
        rules_path = os.path.join(sys._MEIPASS, "rules")
        logger.debug("default rule path (PyInstaller method): %s", rules_path)
    else:
        logger.debug("detected running from source")
        rules_path = os.path.join(os.path.dirname(__file__), "..", "rules")
        logger.debug("default rule path (source method): %s", rules_path)

    rules = get_rules(rules_path)
    rules = capa.rules.RuleSet(rules)

    meta = collect_metadata([], "", rules_path, format, "IdaExtractor")

    capabilities, counts = find_capabilities(rules, capa.features.extractors.ida.IdaFeatureExtractor())
    meta["analysis"].update(counts)

    if has_file_limitation(rules, capabilities, is_standalone=False):
        capa.ida.helpers.inform_user_ida_ui("capa encountered warnings during analysis")

    print(capa.render.render_default(meta, rules, capabilities))


def is_runtime_ida():
    try:
        import idc
    except ImportError:
        return False
    else:
        return True


if __name__ == "__main__":
    if is_runtime_ida():
        ida_main()
    else:
        sys.exit(main())
