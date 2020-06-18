'''
Run a capa rule file against the testbed (frozen features in a directory).

Example usage:
  run_rule_on_testbed.py <path to rules> <rule name> <testbed dir>
  run_rule_on_testbed.py ..\\rules "create pipe" samples
'''

import os
import sys
import json
import time
import logging

from collections import defaultdict

import argparse

import capa.main
import capa.rules
import capa.features.freeze

from scripts.testbed import FNAMES_EXTENSION, FREEZE_EXTENSION
from start_ida_export_fimages import export_fimages


logger = logging.getLogger(__name__)

# sorry globals...
file_count = 0
file_hits = 0
mal_hits = 0
other_hits = 0
function_hits = 0
errors = 0
function_names = set([])


CATEGORY = {
    'malicious': 'MAL',
    'benign': 'BEN',
}


def check_rule(path, rules, rule_name, only_matching, save_image, verbose):
    global file_count, file_hits, mal_hits, other_hits, function_hits, errors

    try:
        capabilities = get_capabilities(path, rules)
    except (ValueError, KeyError) as e:
        logger.error('cannot load %s due to %s: %s', path, type(e).__name__, str(e))
        errors += 1
        return

    file_count += 1
    hits = get_function_hits(capabilities, rule_name)
    if hits == 0:
        if not only_matching:
            render_no_hit(path)
    else:
        print('[x] rule matches %d function(s) in %s (%s)' % (hits, path, get_category(path)))

        file_hits += 1
        function_hits += hits

        if get_category(path) == 'MAL':
            mal_hits += 1
        else:
            other_hits += 1

        if verbose:
            render_hit_verbose(capabilities, path, verbose > 1)

        if save_image:
            fvas = ['0x%x' % fva for fva in get_hit_fvas(capabilities)]
            file_path = get_idb_or_sample_path(path)
            if file_path:
                if not export_fimages(file_path, save_image, fvas):
                    logger.warning('exporting images failed')
            else:
                logger.warning('could not get IDB or sample path')


def get_idb_or_sample_path(path):
    exts = ['.idb', '.i64', '.exe_', '.dll_', '.mal_']
    roots = [os.path.splitext(path)[0], path]
    for e in exts:
        for r in roots:
            p = '%s%s' % (r, e)
            if os.path.exists(p):
                return p
    return None


def get_capabilities(path, rules):
    logger.debug('matching rules in %s', path)
    with open(path, 'rb') as f:
        extractor = capa.features.freeze.load(f.read())
    return capa.main.find_capabilities(rules, extractor, disable_progress=True)


def get_function_hits(capabilities, rule_name):
    return len(capabilities.get(rule_name, []))


def get_category(path):
    for c in CATEGORY:
        if c in path:
            return CATEGORY[c]
    return 'UNK'


def render_no_hit(path):
    print('[ ] no match in %s (%s)' % (path, get_category(path)))


def render_hit_verbose(capabilities, path, vverbose):
    try:
        fnames = load_fnames(path)
    except IOError as e:
        logger.error('%s', str(e))
        fnames = None

    for rule, ress in capabilities.items():
        for (fva, res) in sorted(ress, key=lambda p: p[0]):
            if fnames and fva in fnames:
                fname = fnames[fva]
                function_names.add(fname)
            else:
                fname = '<name unknown>'
            print('  - function 0x%x (%s)' % (fva, fname))

            if vverbose:
                capa.main.render_result(res, indent='      ')


def get_hit_fvas(capabilities):
    fvas = []
    for rule, ress in capabilities.items():
        for (fva, res) in sorted(ress, key=lambda p: p[0]):
            fvas.append(fva)
    return fvas


def load_fnames(path):
    fnames_path = path.replace(FREEZE_EXTENSION, FNAMES_EXTENSION)
    if not os.path.exists(fnames_path):
        raise IOError('%s does not exist' % fnames_path)

    logger.debug('fnames path: %s', fnames_path)
    try:
        # json file with format { fva: fname }
        fnames = load_json(fnames_path)
        logger.debug('loaded JSON file')
    except TypeError:
        # csv file with format idbmd5;md5;fva;fname
        fnames = load_csv(fnames_path)
        logger.debug('loaded CSV file')
    fnames = convert_keys_to_int(fnames)
    logger.debug('read %d function names' % len(fnames))
    return fnames


def load_json(path):
    with open(path, 'r') as f:
        try:
            funcs = json.load(f)
        except ValueError as e:
            logger.debug('not a JSON file, %s', str(e))
            raise TypeError
    return funcs


def load_csv(path):
    funcs = defaultdict(str)
    with open(path, 'r') as f:
        data = f.read().splitlines()
    for line in data:
        try:
            idbmd5, md5, fva, name = line.split(':', 3)
        except ValueError as e:
            logger.warning('%s: "%s"', str(e), line)
        funcs[fva] = name
    return funcs


def convert_keys_to_int(funcs_in):
    funcs = {}
    for k, v in funcs_in.iteritems():
        try:
            k = int(k)
        except ValueError:
            k = int(k, 0x10)
        funcs[k] = v
    return funcs


def print_summary(verbose, start_time):
    global file_count, file_hits, function_hits, errors

    print('\n[SUMMARY]')
    m, s = divmod(time.time() - start_time, 60)
    logger.info('ran for %d:%02d minutes', m, s)
    ratio = ' (%d%%)' % ((float(file_hits) / file_count) * 100) if file_count else ''
    print('matched %d function(s) in %d/%d%s sample(s), encountered %d error(s)' % (
        function_hits, file_hits, file_count, ratio, errors))
    print('%d hits on (MAL) files; %d hits on other files' % (mal_hits, other_hits))

    if verbose:
        if len(function_names) > 0:
            print('matched function names (unique):')
            for fname in function_names:
                print '  - %s' % fname


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Run capa rule file against frozen features in a directory")
    parser.add_argument("rules", type=str,
                        help="Path to directory containing rules")
    parser.add_argument("rule_name", type=str,
                        help="Name of rule to test")
    parser.add_argument("frozen_path", type=str,
                        help="Path to frozen feature file or directory")
    parser.add_argument("-f", "--fast", action="store_true",
                        help="Don't test slow files")
    parser.add_argument("-o", "--only_matching", action="store_true",
                        help="Print only if rule matches")
    parser.add_argument("-s", "--save_image", action="store",
                        help="Directory to save exported images of function graphs")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase output verbosity")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Disable all output but errors")
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

    if not os.path.isdir(args.rules):
        logger.error('%s is not a directory', args.rules)
        return -1

    # load rule
    try:
        rules = capa.main.get_rules(args.rules)
        rules = list(capa.rules.get_rules_and_dependencies(rules, args.rule_name))
        rules = capa.rules.RuleSet(rules)
    except IOError as e:
        logger.error('%s', str(e))
        return -1
    except capa.rules.InvalidRule as e:
        logger.error('%s', str(e))
        return -1

    time0 = time.time()

    print('[RULE %s]' % args.rule_name)
    if os.path.isfile(args.frozen_path):
        check_rule(args.frozen_path, rules, args.rule_name, args.only_matching, args.save_image, args.verbose)

    try:
        # get only freeze files from directory
        freeze_files = []
        for root, dirs, files in os.walk(args.frozen_path):
            for file in files:
                if not file.endswith(FREEZE_EXTENSION):
                    continue

                path = os.path.join(root, file)
                if args.fast and 'slow' in path:
                    logger.debug('fast mode skipping %s', path)
                    continue

                freeze_files.append(path)

        for path in sorted(freeze_files):
            sample_time0 = time.time()
            check_rule(path, rules, args.rule_name, args.only_matching, args.save_image, args.verbose)
            logger.debug('rule check took %d seconds', time.time() - sample_time0)
    except KeyboardInterrupt:
        logger.info('Received keyboard interrupt, terminating')

    print_summary(args.verbose, time0)


if __name__ == "__main__":
    sys.exit(main())
