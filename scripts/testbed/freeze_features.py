'''
Freeze capa features.

Example usage:
  freeze_features.py <test files dir>
  freeze_features.py samples\benign
'''

import os
import sys
import time
import logging

import argparse

from scripts.testbed import FREEZE_EXTENSION
from capa.features.freeze import main as freeze_features


# only process files with these extensions
TARGET_EXTENSIONS = [
    '.mal_',
    '.exe_',
    '.dll_',
    '.sys_'
]


logger = logging.getLogger('check_rule')


def freeze(input_path, reprocess):
    if not os.path.exists(input_path):
        raise IOError('%s does not exist or cannot be accessed' % input_path)

    if os.path.isfile(input_path):
        outfile = '%s%s' % (input_path, FREEZE_EXTENSION)
        freeze_file(input_path, outfile, reprocess)

    elif os.path.isdir(input_path):
        logger.info('freezing features of %s files in %s', '|'.join(TARGET_EXTENSIONS), input_path)
        for root, dirs, files in os.walk(input_path):
            for file in files:
                if not os.path.splitext(file)[1] in TARGET_EXTENSIONS:
                    logger.debug('skipping non-target file: %s', file)
                    continue
                path = os.path.join(root, file)
                outfile = '%s%s' % (path, FREEZE_EXTENSION)
                freeze_file(path, outfile, reprocess)


def freeze_file(path, output, reprocess=False):
    logger.info('freezing features of %s', path)

    if os.path.exists(output) and not reprocess:
        logger.info('%s already exists, provide -r argument to reprocess', output)
        return

    try:
        freeze_features([path, output])  # args: sample, output
    except Exception as e:
        logger.error('could not freeze features for %s: %s', path, str(e))


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description='Freeze capa features of a file or of files in a directory')
    parser.add_argument('file_path', type=str,
                        help='Path to file or directory to analyze')
    parser.add_argument('-r', '--reprocess', action='store_true', default=False,
                        help='Overwrite existing analysis')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Disable all output but errors')
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

    time0 = time.time()
    try:
        freeze(args.file_path, args.reprocess)
    except IOError as e:
        logger.error('%s', str(e))
        return -1

    logger.info('freezing features took %d seconds', time.time() - time0)
    return 0


if __name__ == '__main__':
    sys.exit(main())
