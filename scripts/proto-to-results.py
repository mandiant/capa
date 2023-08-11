#!/usr/bin/env python
"""
Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

proto-to-results-json.py

Convert a protobuf result document into the JSON format.

Example:

    $ capa --json foo.exe > foo.json
    $ python proto-from-results.py foo.json > foo.pb
    $ python proto-to-results.py foo.pb | jq . | head
    ────┼────────────────────────────────────────────────────
    1   │ {
    2   │   "meta": {
    3   │     "analysis": {
    4   │       "arch": "i386",
    5   │       "base_address": {
    6   │         "type": "absolute",
    7   │         "value": 268435456
    8   │       },
    9   │       "extractor": "VivisectFeatureExtractor",
    10  │       "feature_counts": {
    ────┴────────────────────────────────────────────────────

"""
import sys
import logging
import argparse
from pathlib import Path

import capa.render.json
import capa.render.proto
import capa.render.proto.capa_pb2
import capa.render.result_document

logger = logging.getLogger("capa.proto-to-results-json")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Convert a capa protobuf result document into the JSON format")
    parser.add_argument(
        "pb", type=str, help="path to protobuf result document file, produced by `proto-from-results.py`"
    )

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

    pb = Path(args.pb).read_bytes()

    rdpb = capa.render.proto.capa_pb2.ResultDocument()
    rdpb.ParseFromString(pb)

    rd = capa.render.proto.doc_from_pb2(rdpb)
    print(rd.model_dump_json(exclude_none=True, indent=2))


if __name__ == "__main__":
    sys.exit(main())
