#!/usr/bin/env python2
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
detect-elf-os

Attempt to detect the underlying OS that the given ELF file targets.
"""
import sys
import logging
import argparse
import contextlib
from typing import BinaryIO

import capa.main
import capa.helpers
import capa.features.extractors.elf

logger = logging.getLogger("capa.detect-elf-os")


def main(argv=None):
    if capa.helpers.is_runtime_ida():
        from capa.ida.helpers import IDAIO

        f: BinaryIO = IDAIO()  # type: ignore

    else:
        if argv is None:
            argv = sys.argv[1:]

        parser = argparse.ArgumentParser(description="Detect the underlying OS for the given ELF file")
        capa.main.install_common_args(parser, wanted={"input_file"})
        args = parser.parse_args(args=argv)

        try:
            capa.main.handle_common_args(args)
            capa.main.ensure_input_exists_from_cli(args)
        except capa.main.ShouldExitError as e:
            return e.status_code

        f = args.input_file.open("rb")

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
