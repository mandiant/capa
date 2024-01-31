#!/usr/bin/env python
"""
Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

proto-from-results-json.py

Convert a JSON result document into the protobuf format.

Example:

    $ capa --json foo.exe > foo.json
    $ python proto-from-results.py foo.json | hexyl | head
    ┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
    │00000000│ 0a d4 05 0a 1a 32 30 32 ┊ 33 2d 30 32 2d 31 30 20 │_.•_•202┊3-02-10 │
    │00000010│ 31 31 3a 34 39 3a 35 32 ┊ 2e 36 39 33 34 30 30 12 │11:49:52┊.693400•│
    │00000020│ 05 35 2e 30 2e 30 1a 34 ┊ 74 65 73 74 73 2f 64 61 │•5.0.0•4┊tests/da│
    │00000030│ 74 61 2f 50 72 61 63 74 ┊ 69 63 61 6c 20 4d 61 6c │ta/Pract┊ical Mal│
    │00000040│ 77 61 72 65 20 41 6e 61 ┊ 6c 79 73 69 73 20 4c 61 │ware Ana┊lysis La│
    │00000050│ 62 20 30 31 2d 30 31 2e ┊ 64 6c 6c 5f 1a 02 2d 6a │b 01-01.┊dll_••-j│
    │00000060│ 22 c4 01 0a 20 32 39 30 ┊ 39 33 34 63 36 31 64 65 │".•_ 290┊934c61de│
    │00000070│ 39 31 37 36 61 64 36 38 ┊ 32 66 66 64 64 36 35 66 │9176ad68┊2ffdd65f│
    │00000080│ 30 61 36 36 39 12 28 61 ┊ 34 62 33 35 64 65 37 31 │0a669•(a┊4b35de71│

"""
import sys
import logging
import argparse
from pathlib import Path

import capa.main
import capa.render.proto
import capa.render.result_document

logger = logging.getLogger("capa.proto-from-results-json")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Convert a capa JSON result document into the protobuf format")
    capa.main.install_common_args(parser)
    parser.add_argument("json", type=str, help="path to JSON result document file, produced by `capa --json`")
    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
    except capa.main.ShouldExitError as e:
        return e.status_code

    rd = capa.render.result_document.ResultDocument.from_file(Path(args.json))
    pb = capa.render.proto.doc_to_pb2(rd)

    sys.stdout.buffer.write(pb.SerializeToString(deterministic=True))
    sys.stdout.flush()


if __name__ == "__main__":
    sys.exit(main())
