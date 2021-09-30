#!/usr/bin/env python2
"""
Copyright (C) 2021 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

detect-elf-os

Attempt to detect the underlying OS that the given ELF file targets.
"""
import sys
import logging
import argparse
import contextlib
from typing import BinaryIO

import capa.helpers
import capa.features.extractors.elf

logger = logging.getLogger("capa.detect-elf-os")


def main(argv=None):
    if capa.helpers.is_runtime_ida():
        from capa.ida.helpers import IDAIO

        f: BinaryIO = IDAIO()

    else:
        if argv is None:
            argv = sys.argv[1:]

        parser = argparse.ArgumentParser(description="Detect the underlying OS for the given ELF file")
        parser.add_argument("sample", type=str, help="path to ELF file")

        logging_group = parser.add_argument_group("logging arguments")

        logging_group.add_argument("-d", "--debug", action="store_true", help="enable debugging output on STDERR")
        logging_group.add_argument(
            "-q", "--quiet", action="store_true", help="disable all status output except fatal errors"
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

        f = open(args.sample, "rb")

    with contextlib.closing(f):
        try:
            print(capa.features.extractors.elf.detect_elf_os(f))
            return 0
        except capa.features.extractors.elf.CorruptElfFile as e:
            logger.error("corrupt ELF file: %s", str(e.args[0]))
            return -1


if __name__ == "__main__":
    if capa.helpers.is_runtime_ida():
        main()
    else:
        sys.exit(main())
