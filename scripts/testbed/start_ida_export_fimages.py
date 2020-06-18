'''
Start IDA Pro in autonomous mode to export images of function graphs.

Example usage:
  start_ida_export_fimages.py <target file> <output dir> -f <function list>
  start_ida_export_fimages.py test.exe imgs -f 0x401000,0x402F90
'''

import os
import imp
import sys
import hashlib
import logging
import subprocess

import argparse

try:
    imp.find_module('graphviz')
    from graphviz import Source
    graphviz_found = True
except ImportError:
    graphviz_found = False


IDA32_PATH = 'C:\\Program Files\\IDA Pro 7.3\\ida.exe'
IDA64_PATH = 'C:\\Program Files\\IDA Pro 7.3\\ida64.exe'

# expected in same directory as this file
EXPORT_SCRIPT_PATH = os.path.abspath('_export_fimages.py')


logger = logging.getLogger(__name__)


def export_fimages(file_path, out_dir, functions, manual=False):
    '''
    Export images of function graphs.
    :param file_path: file to analyze
    :param out_dir: output directory
    :param functions: list of strings of hex formatted fvas
    :param manual: non-autonomous mode
    :return: True on success, False otherwise
    '''
    if not graphviz_found:
        logger.warning('please install graphviz to export images')
        return False

    if not os.path.exists(out_dir):
        os.mkdir(out_dir)

    script_args = [os.path.abspath(out_dir)] + functions
    call_ida_script(EXPORT_SCRIPT_PATH, script_args, file_path, manual)

    img_count = 0
    for root, dirs, files in os.walk(out_dir):
        for file in files:
            if not file.endswith('.dot'):
                continue
            try:
                s = Source.from_file(file, directory=out_dir)
                s.render(file, directory=out_dir, format='png', cleanup=True)
                img_count += 1
            except BaseException:
                logger.warning('graphviz error rendering file')
    if img_count > 0:
        logger.info('exported %d function graph images to "%s"', img_count, os.path.abspath(out_dir))
        return True
    else:
        logger.warning('failed to export function graph images')
        return False


def call_ida_script(script_path, script_args, sample_path, manual):
    logger.info('processing %s (MD5: %s)', sample_path, get_md5_hexdigest(sample_path))

    # TODO detect 64-bit binaries
    if os.path.splitext(sample_path)[-1] == '.i64':
        IDA_PATH = IDA64_PATH
    else:
        IDA_PATH = IDA32_PATH

    args = [IDA_PATH, '-A', '-S%s %s' % (script_path, ' '.join(script_args)), sample_path]

    if manual:
        args.remove('-A')

    logger.debug('calling "%s"' % ' '.join(args))
    if subprocess.call(args) == 0:
        return True
    else:
        return False


def get_md5_hexdigest(sample_path):
    m = hashlib.md5()
    with open(sample_path, 'rb') as f:
        m.update(f.read())
    return m.hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description="Launch IDA Pro in autonomous mode to export images of function graphs")
    parser.add_argument("file_path", type=str,
                        help="File to export from")
    parser.add_argument("out_dir", type=str,
                        help="Export target directory")
    parser.add_argument("-f", "--functions", action="store",
                        help="Comma separated list of functions to export")
    parser.add_argument("-m", "--manual", action="store_true",
                        help="Manual mode: show IDA dialog boxes")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")
    args = parser.parse_args(args=sys.argv[1:])

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    if not os.path.isfile(args.file_path):
        logger.warning('%s is not a file', args.file_path)
        return -1

    functions = args.functions.split(',')
    export_fimages(args.file_path, args.out_dir, functions, args.manual)

    return 0


if __name__ == "__main__":
    sys.exit(main())
