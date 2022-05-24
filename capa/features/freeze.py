"""
capa freeze file format: `| capa0000 | + zlib(utf-8(json(...)))`

freeze document schema:

    {
      'version': 2,
      'base address': address(base address),
      'functions': [
        [address(function): [
          [address(basic block): [
             address(instruction), 
             address(instruction),
             ...]
          ],
          ...]
        ],
      ...],
      'scopes': {
        'global': [
          (str(name), [any(arg), ...], address(_), ()),
          ...
        },
        'file': [
          (str(name), [any(arg), ...], address(_), ()),
          ...
        },
        'function': [
          (str(name), [any(arg), ...], address(function), (address(function), )),
          ...
        ],
        'basic block': [
          (str(name), [any(arg), ...], address(basic block), (address(function),
                                                              address(basic block))),
          ...
        ],
        'instruction': [
          (str(name), [any(arg), ...], address(instruction), (int(function),
                                                              int(basic block),
                                                              int(instruction))),
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
import capa.features.address
import capa.features.basicblock
import capa.features.extractors.base_extractor
from capa.features.address import Address
from capa.features.common import Feature
from capa.helpers import assert_never

logger = logging.getLogger(__name__)


def serialize_feature(feature):
    return feature.freeze_serialize()


KNOWN_FEATURES: Dict[str, Type[Feature]] = {F.__name__: F for F in capa.features.common.Feature.__subclasses__()}
KNOWN_FEATURES.update({F.__name__: F for F in capa.features.insn._Operand.__subclasses__()})  # type: ignore

def deserialize_feature(doc):
    F = KNOWN_FEATURES[doc[0]]
    return F.freeze_deserialize(doc[1])


def serialize_address(a: Address) -> any:
    if isinstance(a, capa.features.address.AbsoluteVirtualAddress):
        return ("absolute", int(a))

    elif isinstance(a, capa.features.address.RelativeVirtualAddress):
        return ("relative", int(a))

    elif isinstance(a, capa.features.address.FileOffsetAddress):
        return ("file", int(a))

    elif isinstance(a, capa.features.address.DNTokenAddress):
        return ("dn token", a.token)

    elif isinstance(a, capa.features.address.DNTokenOffsetAddress):
        return ("dn token offset", a.token, a.offset)

    elif a == capa.features.address.NO_ADDRESS:
        return ("no address")

    else:
        assert_never(a)


def deserialize_address(doc: any) -> Address:
    atype = doc[0]

    if atype == "absolute":
        return capa.features.address.AbsoluteVirtualAddress(doc[1])

    elif atype == "relative":
        return capa.features.address.RelativeVirtualAddress(doc[1])

    elif atype == "file":
        return capa.features.address.FileOffsetAddress(doc[1])

    elif atype == "dn token":
        return capa.features.address.DNTokenAddress(doc[1])

    elif atype == "dn token offset":
        return capa.features.address.DNTokenOffsetAddress(doc[1], doc[2])

    elif doc == "no address":
        return capa.features.address.NO_ADDRESS

    else:
        assert_never(atype)


def dumps(extractor: capa.features.extractors.base_extractor.FeatureExtractor) -> str:
    """
    serialize the given extractor to a string
    """
    ret = {
        "version": 2,
        "base address": serialize_address(extractor.get_base_address()),
        "functions": [],
        "scopes": {
            "global": [],
            "file": [],
            "function": [],
            "basic block": [],
            "instruction": [],
        },
    }
    for feature, addr in extractor.extract_global_features():
        ret["scopes"]["global"].append(serialize_feature(feature) + (serialize_address(addr), ()))

    for feature, addr in extractor.extract_file_features():
        ret["scopes"]["file"].append(serialize_feature(feature) + (serialize_address(addr), ()))

    for f in extractor.get_functions():
        faddr = serialize_address(f.address)

        for feature, addr in extractor.extract_function_features(f):
            ret["scopes"]["function"].append(serialize_feature(feature) + (serialize_address(addr), (faddr,)))

        fentries = []
        for bb in extractor.get_basic_blocks(f):
            bbaddr = serialize_address(bb.address)

            for feature, addr in extractor.extract_basic_block_features(f, bb):
                ret["scopes"]["basic block"].append(
                    serialize_feature(feature)
                    + (
                        serialize_address(addr),
                        (
                            faddr,
                            bbaddr,
                        ),
                    )
                )

            bbentries = []
            for insn in extractor.get_instructions(f, bb):
                iaddr = serialize_address(insn.address)

                for feature, addr in extractor.extract_insn_features(f, bb, insn):
                    ret["scopes"]["instruction"].append(
                        serialize_feature(feature)
                        + (
                            serialize_address(addr),
                            (
                                faddr,
                                bbaddr,
                                iaddr,
                            ),
                        )
                    )

                bbentries.append(iaddr)

            fentries.append((bbaddr, bbentries))

        ret["functions"].append((faddr, fentries))

    return json.dumps(ret)


def loads(s: str) -> capa.features.extractors.base_extractor.FeatureExtractor:
    """deserialize a set of features (as a NullFeatureExtractor) from a string."""
    doc = json.loads(s)

    if doc.get("version") != 2:
        raise ValueError("unsupported freeze format version: %d" % (doc.get("version")))

    features = {
        "base address": deserialize_address(doc.get("base address")),
        "global features": [],
        "file features": [],
        "functions": {},
    }

    for pair in doc.get("functions", []):
        faddr, function = pair

        faddr = deserialize_address(faddr)
        features["functions"][faddr] = {
            "features": [],
            "basic blocks": {},
        }

        for pair in function:
            bbaddr, bb = pair

            bbaddr = deserialize_address(bbaddr)
            features["functions"][faddr]["basic blocks"][bbaddr] = {
                "features": [],
                "instructions": {},
            }

            for iaddr in bb:
                iaddr = deserialize_address(iaddr)
                features["functions"][faddr]["basic blocks"][bbaddr]["instructions"][iaddr] = {
                    "features": [],
                }

    # in the following blocks, each entry looks like:
    #
    #     ('MatchedRule', ('foo', ), '0x401000', ('0x401000', ))
    #      ^^^^^^^^^^^^^  ^^^^^^^^^  ^^^^^^^^^^  ^^^^^^^^^^^^^^
    #      feature name   args       addr         func/bb/insn
    for feature in doc.get("scopes", {}).get("global", []):
        addr, loc = feature[2:]
        addr = deserialize_address(addr)
        feature = deserialize_feature(feature[:2])
        features["global features"].append((addr, feature))

    for feature in doc.get("scopes", {}).get("file", []):
        addr, loc = feature[2:]
        addr = deserialize_address(addr)
        feature = deserialize_feature(feature[:2])
        features["file features"].append((addr, feature))

    for feature in doc.get("scopes", {}).get("function", []):
        # fetch the pair like:
        #
        #     ('0x401000', ('0x401000', ))
        #      ^^^^^^^^^^  ^^^^^^^^^^^^^^
        #      addr         func/bb/insn
        addr, loc = feature[2:]
        addr = deserialize_address(addr)
        loc = list(map(deserialize_address, loc))
        faddr, = loc

        # decode the feature from the pair like:
        #
        #     ('MatchedRule', ('foo', ))
        #      ^^^^^^^^^^^^^  ^^^^^^^^^
        #      feature name   args
        feature = deserialize_feature(feature[:2])
        features["functions"][faddr]["features"].append((addr, feature))

    for feature in doc.get("scopes", {}).get("basic block", []):
        addr, loc = feature[2:]
        addr = deserialize_address(addr)
        loc = list(map(deserialize_address, loc))
        faddr, bbaddr = loc
        feature = deserialize_feature(feature[:2])
        features["functions"][faddr]["basic blocks"][bbaddr]["features"].append((addr, feature))

    for feature in doc.get("scopes", {}).get("instruction", []):
        addr, loc = feature[2:]
        addr = deserialize_address(addr)
        loc = list(map(deserialize_address, loc))
        faddr, bbaddr, iaddr = loc
        feature = deserialize_feature(feature[:2])
        features["functions"][faddr]["basic blocks"][bbaddr]["instructions"][iaddr]["features"].append((addr, feature))

    return capa.features.extractors.base_extractor.NullFeatureExtractor(features)


MAGIC = "capa0000".encode("ascii")


def dump(extractor: capa.features.extractors.base_extractor.FeatureExtractor) -> bytes:
    """serialize the given extractor to a byte array."""
    return MAGIC + zlib.compress(dumps(extractor).encode("utf-8"))


def is_freeze(buf: bytes) -> bool:
    return buf[: len(MAGIC)] == MAGIC


def load(buf: bytes) -> capa.features.extractors.base_extractor.FeatureExtractor:
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
