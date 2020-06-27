#!/usr/bin/env python2
'''
capa - detect capabilities in programs.
'''
import os
import os.path
import sys
import logging
import collections

import tqdm
import argparse

import capa.rules
import capa.engine
import capa.render
import capa.features
import capa.features.freeze
import capa.features.extractors

from capa.helpers import oint


SUPPORTED_FILE_MAGIC = set(['MZ'])


logger = logging.getLogger('capa')


def set_vivisect_log_level(level):
    logging.getLogger('vivisect').setLevel(level)
    logging.getLogger('vtrace').setLevel(level)
    logging.getLogger('envi').setLevel(level)


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
    return function_matches, bb_matches


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

    logger.info('analyzed file and extracted %d features', len(file_features))

    file_features.update(function_features)

    _, matches = capa.engine.match(ruleset.file_rules, file_features, 0x0)
    return matches


def find_capabilities(ruleset, extractor, disable_progress=None):
    all_function_matches = collections.defaultdict(list)
    all_bb_matches = collections.defaultdict(list)

    for f in tqdm.tqdm(extractor.get_functions(), disable=disable_progress, unit=' functions'):
        function_matches, bb_matches = find_function_capabilities(ruleset, extractor, f)
        for rule_name, res in function_matches.items():
            all_function_matches[rule_name].extend(res)
        for rule_name, res in bb_matches.items():
            all_bb_matches[rule_name].extend(res)

    # mapping from matched rule feature to set of addresses at which it matched.
    # type: Dict[MatchedRule, Set[int]]
    function_features = {capa.features.MatchedRule(rule_name): set(map(lambda p: p[0], results))
                         for rule_name, results in all_function_matches.items()}

    all_file_matches = find_file_capabilities(ruleset, extractor, function_features)

    matches = {}
    matches.update(all_bb_matches)
    matches.update(all_function_matches)
    matches.update(all_file_matches)

    return matches


def pluck_meta(rules, key):
    for rule in rules:
        value = rule.meta.get(key)
        if value:
            yield value


def get_dispositions(matched_rules):
    for disposition in pluck_meta(matched_rules, 'maec/analysis-conclusion'):
        yield disposition

    for disposition in pluck_meta(matched_rules, 'maec/analysis-conclusion-ov'):
        yield disposition


def get_roles(matched_rules):
    for role in pluck_meta(matched_rules, 'maec/malware-category'):
        yield role

    for role in pluck_meta(matched_rules, 'maec/malware-category-ov'):
        yield role


RULE_CATEGORY = 'rule-category'


def is_other_feature_rule(rule):
    '''
    does this rule *not* have any of:
      - maec/malware-category
      - maec/analysis-conclusion
      - rule-category

    if so, it will be placed into the "other features" bucket
    '''
    if rule.meta.get('lib', False):
        return False

    for meta in ('maec/analysis-conclusion',
                 'maec/analysis-conclusion-ov',
                 'maec/malware-category',
                 'maec/malware-category-ov',
                 RULE_CATEGORY):
        if meta in rule.meta:
            return False
    return True


def render_capabilities_default(ruleset, results):
    rules = [ruleset.rules[rule_name] for rule_name in results.keys()]

    # we render the highest level conclusions first:
    #
    #  1. is it malware?
    #  2. what is the role? (dropper, backdoor, etc.)
    #
    # after this, we'll enumerate the specific objectives, behaviors, and techniques.
    dispositions = list(sorted(get_dispositions(rules)))
    if dispositions:
        print('disposition: ' + ', '.join(dispositions))

    categories = list(sorted(get_roles(rules)))
    if categories:
        print('role: ' + ', '.join(categories))

    # rules may have a meta tag `rule-category` that specifies:
    #
    #     rule-category: $objective[/$behavior[/$technique]]
    #
    # this classification describes a tree of increasingly specific conclusions.
    # the tree allows us to tie a high-level conclusion, e.g. an objective, to
    #   the evidence of this - the behaviors, techniques, rules, and ultimately, features.

    # this data structure is a nested map:
    #
    #     objective name -> behavior name -> technique name -> rule name -> rule
    #
    # at each level, a matched rule is also legal.
    # this indicates that only a portion of the rule-category was provided.
    o = collections.defaultdict(
        lambda: collections.defaultdict(
            lambda: collections.defaultdict(
                dict
            )
        )
    )
    objectives = set()
    behaviors = set()
    techniques = set()

    for rule in rules:
        objective = None
        behavior = None
        technique = None

        parts = rule.meta.get(RULE_CATEGORY, '').split('/')
        if len(parts) == 0 or list(parts) == ['']:
            continue
        if len(parts) > 0:
            objective = parts[0].replace('-', ' ')
            objectives.add(objective)
        if len(parts) > 1:
            behavior = parts[1].replace('-', ' ')
            behaviors.add(behavior)
        if len(parts) > 2:
            technique = parts[2].replace('-', ' ')
            techniques.add(technique)
        if len(parts) > 3:
            raise capa.rules.InvalidRule(RULE_CATEGORY + ' tag must have at most three components')

        if technique:
            o[objective][behavior][technique][rule.name] = rule
        elif behavior:
            o[objective][behavior][rule.name] = rule
        elif objective:
            o[objective][rule.name] = rule

    if objectives:
        print('\nobjectives:')
        for objective in sorted(objectives):
            print('  ' + objective)

    if behaviors:
        print('\nbehaviors:')
        for behavior in sorted(behaviors):
            print('  ' + behavior)

    if techniques:
        print('\ntechniques:')
        for technique in sorted(techniques):
            print('  ' + technique)

    other_features = list(filter(is_other_feature_rule, rules))
    if other_features:
        print('\nother features:')
        for rule in sorted(map(lambda r: r.name, other_features)):
            print('  ' + rule)

    # now, render a tree of the objectives, behaviors, techniques, and matched rule names.
    # it will look something like:
    #
    #     details:
    #       load data
    #         load data from self
    #           load data from resource
    #             extract resource via API
    #
    # implementation note:
    # when we enumerate the items in this tree, we have two cases:
    #
    #   1. usually, we'll get a pair (objective name, map of children); but its possible that
    #   2. we'll get a pair (rule name, rule instance)
    #
    # this is why we do the `ininstance(..., Rule)` check below.
    #
    # i believe the alternative, to have separate data structures for the tree and rules,
    # is probably more code and more confusing.
    if o:
        print('\ndetails:')
        for objective, behaviors in o.items():
            print('  ' + objective)

            if isinstance(behaviors, capa.rules.Rule):
                continue
            for behavior, techniques in behaviors.items():
                print('    ' + behavior)

                if isinstance(techniques, capa.rules.Rule):
                    continue
                for technique, rules in techniques.items():
                    print('      ' + technique)

                    if isinstance(rules, capa.rules.Rule):
                        continue
                    for rule in rules.keys():
                        print('        ' + rule)


def render_capabilities_concise(results):
    '''
    print the matching rules, newline separated.

    example:

        foo
        bar
        mimikatz::kull_m_arc_sendrecv
    '''
    for rule in sorted(results.keys()):
        print(rule)


def render_capabilities_verbose(ruleset, results):
    '''
    print the matching rules, and the functions in which they matched.

    example:

        foo:
          - 0x401000
          - 0x401005
        bar:
          - 0x402044
          - 0x402076
        mimikatz::kull_m_arc_sendrecv:
          - 0x40105d
    '''
    for rule, ress in results.items():
        if ruleset.rules[rule].meta.get('capa/subscope-rule', False):
            # don't display subscope rules
            continue

        rule_scope = ruleset.rules[rule].scope
        if rule_scope == capa.rules.FILE_SCOPE:
            # only display rule name at file scope
            print('%s' % rule)
            continue
        print('%s:' % (rule))
        seen = set([])
        for (fva, _) in sorted(ress, key=lambda p: p[0]):
            if fva in seen:
                continue
            print('  - 0x%x' % (fva))
            seen.add(fva)


def render_result(res, indent=''):
    '''
    render the given Result to stdout.

    args:
      res (capa.engine.Result)
      indent (str)
    '''
    # prune failing branches
    if not res.success:
        return

    if isinstance(res.statement, capa.engine.Some):
        if res.statement.count == 0:
            # we asked for optional, so we'll match even if no children matched.
            # but in this case, its not worth rendering the optional node.
            if sum(map(lambda c: c.success, res.children)) > 0:
                print('%soptional:' % indent)
        else:
            print('%s%d or more' % (indent, res.statement.count))
    elif not isinstance(res.statement, (capa.features.Feature, capa.engine.Range, capa.engine.Regex)):
        # when rending a structural node (and/or/not),
        #  then we only care about the node name.
        #
        # for example:
        #
        #     and:
        #       Number(0x3136b0): True
        #       Number(0x3136b0): True
        print('%s%s:' % (indent, res.statement.name.lower()))
    else:
        # but when rendering a Feature, want to see any arguments to it
        #
        # for example:
        #
        #     Number(0x3136b0): True
        print('%s%s:' % (indent, res.statement))
        for location in sorted(res.locations):
            print('%s  - virtual address: 0x%x' % (indent, location))

    for children in res.children:
        render_result(children, indent=indent + '  ')


def render_capabilities_vverbose(ruleset, results):
    '''
    print the matching rules, the functions in which they matched,
      and the logic tree with annotated matching features.

    example:

        function mimikatz::kull_m_arc_sendrecv:
          - 0x40105d
              Or:
                And:
                  string("ACR  > "):
                    - virtual address: 0x401089
                  number(0x3136b0):
                    - virtual address: 0x4010c8
    '''
    for rule, ress in results.items():
        if ruleset.rules[rule].meta.get('capa/subscope-rule', False):
            # don't display subscope rules
            continue

        print('rule %s:' % (rule))
        for (va, res) in sorted(ress, key=lambda p: p[0]):
            rule_scope = ruleset.rules[rule].scope
            if rule_scope == capa.rules.FILE_SCOPE:
                # does not make sense to display va at file scope
                print('  - %s:' % rule_scope)
            else:
                print('  - %s 0x%x:' % (rule_scope, va))
            render_result(res, indent='      ')


def appears_rule_cat(rules, capabilities, rule_cat):
    for rule_name in capabilities.keys():
        if rules.rules[rule_name].meta.get('rule-category', '').startswith(rule_cat):
            return True
    return False


def is_file_limitation(rules, capabilities, is_standalone=True):
    file_limitations = {
        # capa will likely detect installer specific functionality.
        # this is probably not what the user wants.
        'other-features/installer/': [
            ' This sample appears to be an installer.',
            ' ',
            ' capa cannot handle installers well. This means the results may be misleading or incomplete.'
            ' You should try to understand the install mechanism and analyze created files with capa.'
        ],
        # capa won't detect much in .NET samples.
        # it might match some file-level things.
        # for consistency, bail on things that we don't support.
        'other-features/compiled-to-dot-net': [
            ' This sample appears to be a .NET module.',
            ' ',
            ' .NET is a cross-platform framework for running managed applications.',
            ' capa cannot handle non-native files. This means that the results may be misleading or incomplete.',
            ' You may have to analyze the file manually, using a tool like the .NET decompiler dnSpy.'
        ],
        # capa will detect dozens of capabilities for AutoIt samples,
        # but these are due to the AutoIt runtime, not the payload script.
        # so, don't confuse the user with FP matches - bail instead
        'other-features/compiled-with-autoit': [
            ' This sample appears to be compiled with AutoIt.',
            ' ',
            ' AutoIt is a freeware BASIC-like scripting language designed for automating the Windows GUI.',
            ' capa cannot handle AutoIt scripts. This means that the results will be misleading or incomplete.',
            ' You may have to analyze the file manually, using a tool like the AutoIt decompiler MyAut2Exe.'
        ],
        # capa won't detect much in packed samples
        'anti-analysis/packing/': [
            ' This sample appears to be packed.',
            ' ',
            ' Packed samples have often been obfuscated to hide their logic.',
            ' capa cannot handle obfuscation well. This means the results may be misleading or incomplete.',
            ' If possible, you should try to unpack this input file before analyzing it with capa.'
        ]
    }

    for category, dialogue in file_limitations.items():
        if not appears_rule_cat(rules, capabilities, category):
            continue
        logger.warning('-' * 80)
        for line in dialogue:
            logger.warning(line)
        if is_standalone:
            logger.warning(' ')
            logger.warning(' Use -v or -vv if you really want to see the capabilities identified by capa.')
        logger.warning('-' * 80)
        return True
    return False


def is_supported_file_type(sample):
    '''
    Return if this is a supported file based on magic header values
    '''
    with open(sample, 'rb') as f:
        magic = f.read(2)
    if magic in SUPPORTED_FILE_MAGIC:
        return True
    else:
        return False


def get_shellcode_vw(sample, arch='auto'):
    '''
    Return shellcode workspace using explicit arch or via auto detect
    '''
    import viv_utils
    with open(sample, 'rb') as f:
        sample_bytes = f.read()
    if arch == 'auto':
        # choose arch with most functions, idea by Jay G.
        vw_cands = []
        for arch in ['i386', 'amd64']:
            vw_cands.append(viv_utils.getShellcodeWorkspace(sample_bytes, arch))
        if not vw_cands:
            raise ValueError('could not generate vivisect workspace')
        vw = max(vw_cands, key=lambda vw: len(vw.getFunctions()))
    else:
        vw = viv_utils.getShellcodeWorkspace(sample_bytes, arch)
    vw.setMeta('Format', 'blob')  # TODO fix in viv_utils
    return vw


def get_meta_str(vw):
    '''
    Return workspace meta information string
    '''
    meta = []
    for k in ['Format', 'Platform', 'Architecture']:
        if k in vw.metadata:
            meta.append('%s: %s' % (k.lower(), vw.metadata[k]))
    return '%s, number of functions: %d' % (', '.join(meta), len(vw.getFunctions()))


class UnsupportedFormatError(ValueError):
    pass


def get_workspace(path, format):
    import viv_utils
    logger.info('generating vivisect workspace for: %s', path)
    if format == 'auto':
        if not is_supported_file_type(path):
            raise UnsupportedFormatError()
        vw = viv_utils.getWorkspace(path)
    elif format == 'pe':
        vw = viv_utils.getWorkspace(path)
    elif format == 'sc32':
        vw = get_shellcode_vw(path, arch='i386')
    elif format == 'sc64':
        vw = get_shellcode_vw(path, arch='amd64')
    logger.info('%s', get_meta_str(vw))
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
    '''
    raises:
      UnsupportedFormatError:
    '''
    if sys.version_info >= (3, 0):
        return get_extractor_py3(path, format)
    else:
        return get_extractor_py2(path, format)


def is_nursery_rule_path(path):
    '''
    The nursery is a spot for rules that have not yet been fully polished.
    For example, they may not have references to public example of a technique.
    Yet, we still want to capture and report on their matches.
    The nursery is currently a subdirectory of the rules directory with that name.

    When nursery rules are loaded, their metadata section should be updated with:
      `nursery=True`.
    '''
    return 'nursery' in path


def get_rules(rule_path):
    if not os.path.exists(rule_path):
        raise IOError('%s does not exist or cannot be accessed' % rule_path)

    rule_paths = []
    if os.path.isfile(rule_path):
        rule_paths.append(rule_path)
    elif os.path.isdir(rule_path):
        logger.debug('reading rules from directory %s', rule_path)
        for root, dirs, files in os.walk(rule_path):
            for file in files:
                if not file.endswith('.yml'):
                    logger.warning('skipping non-.yml file: %s', file)
                    continue

                rule_path = os.path.join(root, file)
                rule_paths.append(rule_path)

    rules = []
    for rule_path in rule_paths:
        logger.debug('reading rule file: %s', rule_path)
        try:
            rule = capa.rules.Rule.from_yaml_file(rule_path)
        except capa.rules.InvalidRule:
            raise
        else:
            rule.meta['capa/path'] = rule_path
            if is_nursery_rule_path(rule_path):
                rule.meta['capa/nursery'] = True

            rules.append(rule)
            logger.debug('rule: %s scope: %s', rule.name, rule.scope)

    return rules


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    formats = [
        ('auto', '(default) detect file type automatically'),
        ('pe', 'Windows PE file'),
        ('sc32', '32-bit shellcode'),
        ('sc64', '64-bit shellcode'),
        ('freeze', 'features previously frozen by capa'),
    ]
    format_help = ', '.join(['%s: %s' % (f[0], f[1]) for f in formats])

    parser = argparse.ArgumentParser(description='detect capabilities in programs.')
    parser.add_argument('sample', type=str,
                        help='Path to sample to analyze')
    parser.add_argument('-r', '--rules', type=str, default='(embedded rules)',
                        help='Path to rule file or directory, use embedded rules by default')
    parser.add_argument('-t', '--tag', type=str,
                        help='Filter on rule meta field values')
    parser.add_argument('--json', action='store_true',
                        help='Emit JSON instead of text')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('-vv', '--vverbose', action='store_true',
                        help='Enable very verbose output')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Disable all output but errors')
    parser.add_argument('-f', '--format', choices=[f[0] for f in formats], default='auto',
                        help='Select sample format, %s' % format_help)
    args = parser.parse_args(args=argv)

    if args.quiet:
        logging.basicConfig(level=logging.ERROR)
        logging.getLogger().setLevel(logging.ERROR)
    elif args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    # disable vivisect-related logging, it's verbose and not relevant for capa users
    set_vivisect_log_level(logging.CRITICAL)

    # py2 doesn't know about cp65001, which is a variant of utf-8 on windows
    # tqdm bails when trying to render the progress bar in this setup.
    # because cp65001 is utf-8, we just map that codepage to the utf-8 codec.
    # see #380 and: https://stackoverflow.com/a/3259271/87207
    import codecs
    codecs.register(lambda name: codecs.lookup('utf-8') if name == 'cp65001' else None)

    if args.rules == '(embedded rules)':
        logger.info('-' * 80)
        logger.info(' Using default embedded rules.')
        logger.info(' To provide your own rules, use the form `capa.exe  ./path/to/rules/  /path/to/mal.exe`.')
        logger.info(' You can see the current default rule set here:')
        logger.info('     https://github.com/fireeye/capa-rules')
        logger.info('-' * 80)

        if hasattr(sys, 'frozen') and hasattr(sys, '_MEIPASS'):
            logger.debug('detected running under PyInstaller')
            args.rules = os.path.join(sys._MEIPASS, 'rules')
            logger.debug('default rule path (PyInstaller method): %s', args.rules)
        else:
            logger.debug('detected running from source')
            args.rules = os.path.join(os.path.dirname(__file__), '..', 'rules')
            logger.debug('default rule path (source method): %s', args.rules)
    else:
        logger.info('using rules path: %s', args.rules)

    try:
        rules = get_rules(args.rules)
        rules = capa.rules.RuleSet(rules)
        logger.info('successfully loaded %s rules', len(rules))
        if args.tag:
            rules = rules.filter_rules_by_meta(args.tag)
            logger.info('selected %s rules', len(rules))
            for i, r in enumerate(rules.rules, 1):
                # TODO don't display subscope rules?
                logger.debug(' %d. %s', i, r)
    except (IOError, capa.rules.InvalidRule, capa.rules.InvalidRuleSet) as e:
        logger.error('%s', str(e))
        return -1

    with open(args.sample, 'rb') as f:
        taste = f.read(8)

    if ((args.format == 'freeze')
            or (args.format == 'auto' and capa.features.freeze.is_freeze(taste))):
        with open(args.sample, 'rb') as f:
            extractor = capa.features.freeze.load(f.read())
    else:
        try:
            extractor = get_extractor(args.sample, args.format)
        except UnsupportedFormatError:
            logger.error('-' * 80)
            logger.error(' Input file does not appear to be a PE file.')
            logger.error(' ')
            logger.error(' capa currently only supports analyzing PE files (or shellcode, when using --format sc32|sc64).')
            logger.error(' If you don\'t know the input file type, you can try using the `file` utility to guess it.')
            logger.error('-' * 80)
            return -1
        except UnsupportedRuntimeError:
            logger.error('-' * 80)
            logger.error(' Unsupported runtime or Python interpreter.')
            logger.error(' ')
            logger.error(' capa supports running under Python 2.7 using Vivisect for binary analysis.')
            logger.error(' It can also run within IDA Pro, using either Python 2.7 or 3.5+.')
            logger.error(' ')
            logger.error(' If you\'re seeing this message on the command line, please ensure you\'re running Python 2.7.')
            logger.error('-' * 80)
            return -1

    capabilities = find_capabilities(rules, extractor)

    if is_file_limitation(rules, capabilities):
        # bail if capa encountered file limitation e.g. a packed binary
        # do show the output in verbose mode, though.
        if not (args.verbose or args.vverbose):
            return -1

    if args.json:
        print(capa.render.render_json(rules, capabilities))
    elif args.vverbose:
        print(capa.render.render_vverbose(rules, capabilities))
    elif args.verbose:
        print(capa.render.render_verbose(rules, capabilities))
    else:
        print(capa.render.render_default(rules, capabilities))

    logger.info('done.')

    return 0


def ida_main():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger().setLevel(logging.INFO)

    import capa.ida.helpers
    if not capa.ida.helpers.is_supported_file_type():
        return -1

    logger.info('-' * 80)
    logger.info(' Using default embedded rules.')
    logger.info(' ')
    logger.info(' You can see the current default rule set here:')
    logger.info('     https://github.com/fireeye/capa-rules')
    logger.info('-' * 80)

    if hasattr(sys, 'frozen') and hasattr(sys, '_MEIPASS'):
        logger.debug('detected running under PyInstaller')
        rules_path = os.path.join(sys._MEIPASS, 'rules')
        logger.debug('default rule path (PyInstaller method): %s', rules_path)
    else:
        logger.debug('detected running from source')
        rules_path = os.path.join(os.path.dirname(__file__), '..', 'rules')
        logger.debug('default rule path (source method): %s', rules_path)

    rules = get_rules(rules_path)
    import capa.rules
    rules = capa.rules.RuleSet(rules)

    import capa.features.extractors.ida
    capabilities = find_capabilities(rules, capa.features.extractors.ida.IdaFeatureExtractor())

    if is_file_limitation(rules, capabilities, is_standalone=False):
        capa.ida.helpers.inform_user_ida_ui('capa encountered warnings during analysis')

    render_capabilities_default(rules, capabilities)


def is_runtime_ida():
    try:
        import idc
    except ImportError:
        return False
    else:
        return True


if __name__ == '__main__':
    if is_runtime_ida():
        ida_main()
    else:
        sys.exit(main())
