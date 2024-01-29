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

import capa.main
import capa.render.json
import capa.render.proto
import capa.render.proto.capa_pb2
import capa.render.result_document

logger = logging.getLogger("capa.proto-to-results-json")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="Convert a capa protobuf result document into the JSON format")
    capa.main.install_common_args(parser)
    parser.add_argument(
        "pb", type=str, help="path to protobuf result document file, produced by `proto-from-results.py`"
    )
    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
    except capa.main.ShouldExitError as e:
        return e.status_code

    pb = Path(args.pb).read_bytes()

    rdpb = capa.render.proto.capa_pb2.ResultDocument()
    rdpb.ParseFromString(pb)

    rd = capa.render.proto.doc_from_pb2(rdpb)
    print(rd.model_dump_json(exclude_none=True, indent=2))


if __name__ == "__main__":
    sys.exit(main())
