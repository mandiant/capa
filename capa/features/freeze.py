"""
capa freeze file format: `| capa0000 | + zlib(utf-8(json(...)))`

json format:

    {
      'version': 1,
      'base address': int(base address),
      'functions': {
        int(function va): {
          int(basic block va): [int(instruction va), ...]
          ...
        },
        ...
      },
      'scopes': {
        'global': [
          (str(name), [any(arg), ...], int(va), ()),
          ...
        },
        'file': [
          (str(name), [any(arg), ...], int(va), ()),
          ...
        },
        'function': [
          (str(name), [any(arg), ...], int(va), (int(function va), )),
          ...
        ],
        'basic block': [
          (str(name), [any(arg), ...], int(va), (int(function va),
                                                 int(basic block va))),
          ...
        ],
        'instruction': [
          (str(name), [any(arg), ...], int(va), (int(function va),
                                                 int(basic block va),
                                                 int(instruction va))),
          ...
        ],
      }
    }

Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
import json
import zlib
import logging
from typing import Dict, Type

import capa.helpers
import capa.features.file
import capa.features.insn
import capa.features.common
import capa.features.basicblock
import capa.features.extractors.base_extractor
from capa.features.common import Feature

logger = logging.getLogger(__name__)


def serialize_feature(feature):
    return feature.freeze_serialize()


KNOWN_FEATURES: Dict[str, Type[Feature]] = {F.__name__: F for F in capa.features.common.Feature.__subclasses__()}
KNOWN_FEATURES.update({F.__name__: F for F in capa.features.insn._Operand.__subclasses__()})  # type: ignore


def deserialize_feature(doc):
    F = KNOWN_FEATURES[doc[0]]
    return F.freeze_deserialize(doc[1])


def dumps(extractor):
    """
    serialize the given extractor to a string

    args:
      extractor: capa.features.extractors.base_extractor.FeatureExtractor:

    returns:
      str: the serialized features.
    """
    hex = capa.helpers.hex
    ret = {
        "version": 1,
        "base address": extractor.get_base_address(),
        "functions": {},
        "scopes": {
            "global": [],
            "file": [],
            "function": [],
            "basic block": [],
            "instruction": [],
        },
    }
    for feature, va in extractor.extract_global_features():
        ret["scopes"]["global"].append(serialize_feature(feature) + (hex(va), ()))

    for feature, va in extractor.extract_file_features():
        ret["scopes"]["file"].append(serialize_feature(feature) + (hex(va), ()))

    for f in extractor.get_functions():
        ret["functions"][hex(f)] = {}

        for feature, va in extractor.extract_function_features(f):
            ret["scopes"]["function"].append(serialize_feature(feature) + (hex(va), (hex(f),)))

        for bb in extractor.get_basic_blocks(f):
            ret["functions"][hex(f)][hex(bb)] = []

            for feature, va in extractor.extract_basic_block_features(f, bb):
                ret["scopes"]["basic block"].append(
                    serialize_feature(feature)
                    + (
                        hex(va),
                        (
                            hex(f),
                            hex(bb),
                        ),
                    )
                )

            for insnva, insn in sorted(
                [(int(insn), insn) for insn in extractor.get_instructions(f, bb)], key=lambda p: p[0]
            ):
                ret["functions"][hex(f)][hex(bb)].append(hex(insnva))

                for feature, va in extractor.extract_insn_features(f, bb, insn):
                    ret["scopes"]["instruction"].append(
                        serialize_feature(feature)
                        + (
                            hex(va),
                            (
                                hex(f),
                                hex(bb),
                                hex(insnva),
                            ),
                        )
                    )
    return json.dumps(ret)


def loads(s):
    """deserialize a set of features (as a NullFeatureExtractor) from a string."""
    doc = json.loads(s)

    if doc.get("version") != 1:
        raise ValueError("unsupported freeze format version: %d" % (doc.get("version")))

    features = {
        "base address": doc.get("base address"),
        "global features": [],
        "file features": [],
        "functions": {},
    }

    for fva, function in doc.get("functions", {}).items():
        fva = int(fva, 0x10)
        features["functions"][fva] = {
            "features": [],
            "basic blocks": {},
        }

        for bbva, bb in function.items():
            bbva = int(bbva, 0x10)
            features["functions"][fva]["basic blocks"][bbva] = {
                "features": [],
                "instructions": {},
            }

            for insnva in bb:
                insnva = int(insnva, 0x10)
                features["functions"][fva]["basic blocks"][bbva]["instructions"][insnva] = {
                    "features": [],
                }

    # in the following blocks, each entry looks like:
    #
    #     ('MatchedRule', ('foo', ), '0x401000', ('0x401000', ))
    #      ^^^^^^^^^^^^^  ^^^^^^^^^  ^^^^^^^^^^  ^^^^^^^^^^^^^^
    #      feature name   args       addr         func/bb/insn
    for feature in doc.get("scopes", {}).get("global", []):
        va, loc = feature[2:]
        va = int(va, 0x10)
        feature = deserialize_feature(feature[:2])
        features["global features"].append((va, feature))

    for feature in doc.get("scopes", {}).get("file", []):
        va, loc = feature[2:]
        va = int(va, 0x10)
        feature = deserialize_feature(feature[:2])
        features["file features"].append((va, feature))

    for feature in doc.get("scopes", {}).get("function", []):
        # fetch the pair like:
        #
        #     ('0x401000', ('0x401000', ))
        #      ^^^^^^^^^^  ^^^^^^^^^^^^^^
        #      addr         func/bb/insn
        va, loc = feature[2:]
        va = int(va, 0x10)
        loc = [int(lo, 0x10) for lo in loc]

        # decode the feature from the pair like:
        #
        #     ('MatchedRule', ('foo', ))
        #      ^^^^^^^^^^^^^  ^^^^^^^^^
        #      feature name   args
        feature = deserialize_feature(feature[:2])
        features["functions"][loc[0]]["features"].append((va, feature))

    for feature in doc.get("scopes", {}).get("basic block", []):
        va, loc = feature[2:]
        va = int(va, 0x10)
        loc = [int(lo, 0x10) for lo in loc]
        feature = deserialize_feature(feature[:2])
        features["functions"][loc[0]]["basic blocks"][loc[1]]["features"].append((va, feature))

    for feature in doc.get("scopes", {}).get("instruction", []):
        va, loc = feature[2:]
        va = int(va, 0x10)
        loc = [int(lo, 0x10) for lo in loc]
        feature = deserialize_feature(feature[:2])
        features["functions"][loc[0]]["basic blocks"][loc[1]]["instructions"][loc[2]]["features"].append((va, feature))

    return capa.features.extractors.base_extractor.NullFeatureExtractor(features)


MAGIC = "capa0000".encode("ascii")


def dump(extractor):
    """serialize the given extractor to a byte array."""
    return MAGIC + zlib.compress(dumps(extractor).encode("utf-8"))


def is_freeze(buf: bytes) -> bool:
    return buf[: len(MAGIC)] == MAGIC


def load(buf):
    """deserialize a set of features (as a NullFeatureExtractor) from a byte array."""
    if not is_freeze(buf):
        raise ValueError("missing magic header")
    return loads(zlib.decompress(buf[len(MAGIC) :]).decode("utf-8"))


def main(argv=None):
    import sys
    import argparse

    import capa.main

    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="save capa features to a file")
    capa.main.install_common_args(parser, {"sample", "format", "backend", "signatures"})
    parser.add_argument("output", type=str, help="Path to output file")
    args = parser.parse_args(args=argv)
    capa.main.handle_common_args(args)

    sigpaths = capa.main.get_signatures(args.signatures)

    extractor = capa.main.get_extractor(args.sample, args.format, args.backend, sigpaths, False)

    with open(args.output, "wb") as f:
        f.write(dump(extractor))

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
