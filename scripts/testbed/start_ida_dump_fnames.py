'''
Start IDA Pro in autonomous mode to dump JSON file of function names { fva: fname }.
Processes a single file or a directory.
Only runs on files with supported file extensions.

Example usage:
  start_ida_dump_fnames.py <candidate files dir>
  start_ida_dump_fnames.py samples\benign
'''

import os
import sys
import json
import hashlib
import logging
import subprocess

import argparse

from scripts.testbed import FNAMES_EXTENSION

IDA32_PATH = 'C:\\Program Files\\IDA Pro 7.3\\ida.exe'
IDA64_PATH = 'C:\\Program Files\\IDA Pro 7.3\\ida64.exe'

# expected in same directory as this file
DUMP_SCRIPT_PATH = os.path.abspath('_dump_fnames.py')

SUPPORTED_EXTENSIONS = [
    '.exe_',
    '.dll_',
    '.sys_',
    '.idb',
    '.i64',
]


logger = logging.getLogger(__name__)


def call_ida_dump_script(sample_path, reprocess):
    ''' call IDA in autonomous mode and return True if success, False on failure '''
    logger.info('processing %s (MD5: %s)', sample_path, get_md5_hexdigest(sample_path))

    # TODO detect 64-bit binaries
    if os.path.splitext(sample_path)[-1] == '.i64':
        IDA_PATH = IDA64_PATH
    else:
        IDA_PATH = IDA32_PATH

    if sample_path.endswith('.idb') or sample_path.endswith('.i64'):
        sample_path = sample_path[:-4]

    fnames = '%s%s' % (sample_path, FNAMES_EXTENSION)
    if os.path.exists(fnames) and not reprocess:
        logger.info('%s already exists and contains %d function names, provide -r argument to reprocess',
                    fnames, len(get_function_names(fnames)))
        return True

    out_path = os.path.split(fnames)[-1]  # relative to IDA database file
    args = [IDA_PATH, '-A', '-S%s "%s"' % (DUMP_SCRIPT_PATH, out_path), sample_path]
    logger.debug('calling "%s"' % ' '.join(args))
    subprocess.call(args)

    if not os.path.exists(fnames):
        logger.warning('%s was not created', fnames)
        return False

    logger.debug('extracted %d function names to %s', len(get_function_names(fnames)), fnames)
    return True


def get_md5_hexdigest(sample_path):
    m = hashlib.md5()
    with open(sample_path, 'rb') as f:
        m.update(f.read())
    return m.hexdigest()


def get_function_names(fnames_file):
    if not os.path.exists(fnames_file):
        return None
    with open(fnames_file, 'r') as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(
        description='Launch IDA Pro in autonomous mode to dump function names of a file or of files in a directory')
    parser.add_argument('file_path', type=str,
                        help='File or directory path to analyze')
    parser.add_argument('-r', '--reprocess', action='store_true', default=False,
                        help='Overwrite existing analysis')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    args = parser.parse_args(args=sys.argv[1:])

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    if not os.path.exists(args.file_path):
        logger.warning('%s does not exist', args.file_path)
        return -1

    if os.path.isfile(args.file_path):
        call_ida_dump_script(args.file_path, args.reprocess)
        return 0

    errors = 0

    logger.info('processing files in %s with file extension %s', args.file_path, '|'.join(SUPPORTED_EXTENSIONS))
    for root, dirs, files in os.walk(args.file_path):
        for file in files:
            if not os.path.splitext(file)[1] in SUPPORTED_EXTENSIONS:
                logger.debug('%s does not have supported file extension', file)
                continue
            path = os.path.join(root, file)
            if not call_ida_dump_script(path, args.reprocess):
                errors += 1

    if errors:
        logger.warning('encountered %d errors', errors)

    return 0


if __name__ == '__main__':
    sys.exit(main())
