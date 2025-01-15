#!/usr/bin/env python2
# Copyright 2023 Google LLC
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
detect-binexport2-capabilities.py

Detect capabilities in a BinExport2 file and write the results into the protobuf format.

Example:

    $ python detect-binexport2-capabilities.py suspicious.BinExport2 | xxd | head
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

import capa.main
import capa.rules
import capa.engine
import capa.loader
import capa.helpers
import capa.features
import capa.exceptions
import capa.render.proto
import capa.render.verbose
import capa.features.freeze
import capa.capabilities.common
import capa.render.result_document as rd
from capa.loader import FORMAT_BINEXPORT2, BACKEND_BINEXPORT2

logger = logging.getLogger("capa.detect-binexport2-capabilities")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="detect capabilities in programs.")
    capa.main.install_common_args(
        parser,
        wanted={"format", "os", "backend", "input_file", "signatures", "rules", "tag"},
    )
    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
        capa.main.ensure_input_exists_from_cli(args)

        input_format = capa.main.get_input_format_from_cli(args)
        assert input_format == FORMAT_BINEXPORT2

        backend = capa.main.get_backend_from_cli(args, input_format)
        assert backend == BACKEND_BINEXPORT2

        sample_path = capa.main.get_sample_path_from_cli(args, backend)
        assert sample_path is not None
        os_ = capa.loader.get_os(sample_path)

        rules = capa.main.get_rules_from_cli(args)

        extractor = capa.main.get_extractor_from_cli(args, input_format, backend)
        # alternatively, if you have all this handy in your library code:
        #
        #     extractor = capa.loader.get_extractor(
        #         args.input_file,
        #         FORMAT_BINEXPORT2,
        #         os_,
        #         BACKEND_BINEXPORT2,
        #         sig_paths=[],
        #         sample_path=sample_path,
        #     )
        #
        # or even more concisely:
        #
        #     be2 = capa.features.extractors.binexport2.get_binexport2(input_path)
        #     buf = sample_path.read_bytes()
        #     extractor = capa.features.extractors.binexport2.extractor.BinExport2FeatureExtractor(be2, buf)
    except capa.main.ShouldExitError as e:
        return e.status_code

    capabilities, counts = capa.capabilities.common.find_capabilities(rules, extractor)

    meta = capa.loader.collect_metadata(argv, args.input_file, input_format, os_, args.rules, extractor, counts)
    meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities)

    doc = rd.ResultDocument.from_capa(meta, rules, capabilities)
    pb = capa.render.proto.doc_to_pb2(doc)

    sys.stdout.buffer.write(pb.SerializeToString(deterministic=True))
    sys.stdout.flush()

    return 0


if __name__ == "__main__":
    sys.exit(main())
