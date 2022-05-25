"""
capa freeze file format: `| capa0000 | + zlib(utf-8(json(...)))`

Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
import zlib
import logging
import collections
from enum import Enum
from typing import Any, Dict, List, Type, Tuple, Set

from pydantic import Field, BaseModel

import capa.helpers
import capa.features.file
import capa.features.insn
import capa.features.common
import capa.features.address
import capa.features.basicblock
import capa.features.extractors.base_extractor
from capa.helpers import assert_never

logger = logging.getLogger(__name__)


class HashableModel(BaseModel):
    class Config:
        frozen = True


class AddressType(str, Enum):
    ABSOLUTE = "absolute"
    RELATIVE = "relative"
    FILE = "file"
    DN_TOKEN = "dn token"
    DN_TOKEN_OFFSET = "dn token offset"
    NO_ADDRESS = "no address"


class Address(HashableModel):
    type: AddressType
    value: Any

    @classmethod
    def from_capa(cls, a: capa.features.address.Address) -> "Address":
        if isinstance(a, capa.features.address.AbsoluteVirtualAddress):
            return cls(type=AddressType.ABSOLUTE, value=int(a))

        elif isinstance(a, capa.features.address.RelativeVirtualAddress):
            return cls(type=AddressType.RELATIVE, value=int(a))

        elif isinstance(a, capa.features.address.FileOffsetAddress):
            return cls(type=AddressType.FILE, value=int(a))

        elif isinstance(a, capa.features.address.DNTokenAddress):
            # TODO: probably need serialization here
            return cls(type=AddressType.DN_TOKEN, value=a.token)

        elif isinstance(a, capa.features.address.DNTokenOffsetAddress):
            # TODO: probably need serialization here
            return cls(type=AddressType.DN_TOKEN_OFFSET, value=(a.token, a.offset))

        elif a == capa.features.address.NO_ADDRESS or isinstance(a, capa.features.address._NoAddress):
            return cls(type=AddressType.NO_ADDRESS, value=None)

        elif isinstance(a, capa.features.address.Address) and not issubclass(type(a), capa.features.address.Address):
            raise ValueError("don't use an Address instance directly")

        elif isinstance(a, capa.features.address.Address):
            raise ValueError("don't use an Address instance directly")

        else:
            assert_never(a)

    def to_capa(self) -> capa.features.address.Address:
        if self.type is AddressType.ABSOLUTE:
            return capa.features.address.AbsoluteVirtualAddress(self.value)

        elif self.type is AddressType.RELATIVE:
            return capa.features.address.RelativeVirtualAddress(self.value)

        elif self.type is AddressType.FILE:
            return capa.features.address.FileOffsetAddress(self.value)

        elif self.type is AddressType.DN_TOKEN:
            return capa.features.address.DNTokenAddress(self.value)

        elif self.type is AddressType.DN_TOKEN_OFFSET:
            return capa.features.address.DNTokenOffsetAddress(*self.value)

        elif self.type is AddressType.NO_ADDRESS:
            return capa.features.address.NO_ADDRESS

        else:
            assert_never(self.type)


KNOWN_FEATURES: Dict[str, Type[capa.features.common.Feature]] = {
    F.__name__: F for F in capa.features.common.Feature.__subclasses__()
}
KNOWN_FEATURES.update({F.__name__: F for F in capa.features.insn._Operand.__subclasses__()})  # type: ignore


class Feature(HashableModel):
    name: str
    args: Tuple[Any, ...]

    @classmethod
    def from_capa(cls, f: capa.features.common.Feature) -> "Feature":
        name, args = f.freeze_serialize()
        return cls(name=name, args=tuple(args))

    def to_capa(self) -> capa.features.common.Feature:
        F = KNOWN_FEATURES[self.name]
        return F.freeze_deserialize(self.args)


class GlobalFeature(HashableModel):
    feature: Feature


class FileFeature(HashableModel):
    address: Address
    feature: Feature


class FunctionFeature(HashableModel):
    """
    args:
        function: the address of the function to which this feature belongs.
        address: the address at which this feature is found.

    function != address because, e.g., the feature may be found *within* the scope (function).
    versus right at its starting address.
    """
    function: Address
    address: Address
    feature: Feature


class BasicBlockFeature(HashableModel):
    """
    args:
        basic_block: the address of the basic block to which this feature belongs.
        address: the address at which this feature is found.

    basic_block != address because, e.g., the feature may be found *within* the scope (basic block).
    versus right at its starting address.
    """
    basic_block: Address
    address: Address
    feature: Feature


class InstructionFeature(HashableModel):
    """
    args:
        instruction: the address of the instruction to which this feature belongs.
        address: the address at which this feature is found.

    instruction != address because, e.g., the feature may be found *within* the scope (basic block),
    versus right at its starting address.
    """
    instruction: Address
    address: Address
    feature: Feature


class Features(BaseModel):
    global_: List[GlobalFeature] = Field(alias="global")
    file: List[FileFeature]
    function: List[FunctionFeature]
    basic_block: List[BasicBlockFeature] = Field(alias="basic block")
    instruction: List[InstructionFeature]

    class Config:
        allow_population_by_field_name = True


class InstructionLayout(BaseModel):
    address: Address


class BasicBlockLayout(BaseModel):
    address: Address
    instructions: List[InstructionLayout]


class FunctionLayout(BaseModel):
    address: Address
    basic_blocks: List[BasicBlockLayout]


class Layout(BaseModel):
    functions: List[FunctionLayout]


class Freeze(BaseModel):
    version: int = 2
    base_address: Address = Field(alias="base address")
    layout: Layout
    features: Features

    class Config:
        allow_population_by_field_name = True


def dumps(extractor: capa.features.extractors.base_extractor.FeatureExtractor) -> str:
    """
    serialize the given extractor to a string
    """

    global_features: List[GlobalFeature] = []
    for feature, _ in extractor.extract_global_features():
        global_features.append(
            GlobalFeature(
                feature=Feature.from_capa(feature),
            )
        )

    file_features: List[FileFeature] = []
    for feature, address in extractor.extract_file_features():
        file_features.append(
            FileFeature(
                feature=Feature.from_capa(feature),
                address=Address.from_capa(address),
            )
        )

    function_features: Set[FunctionFeature] = set()
    basic_block_features: Set[BasicBlockFeature] = set()
    instruction_features: Set[InstructionFeature] = set()
    function_layouts: List[FunctionLayout] = []

    for f in extractor.get_functions():
        faddr = Address.from_capa(f.address)

        for feature, addr in extractor.extract_function_features(f):
            function_features.add(
                FunctionFeature(
                    function=faddr,
                    address=Address.from_capa(addr),
                    feature=Feature.from_capa(feature),
                )
            )

        basic_block_layouts: List[BasicBlockLayout] = []
        for bb in extractor.get_basic_blocks(f):
            bbaddr = Address.from_capa(bb.address)

            for feature, addr in extractor.extract_basic_block_features(f, bb):
                basic_block_features.add(
                    BasicBlockFeature(
                        basic_block=bbaddr,
                        address=Address.from_capa(addr),
                        feature=Feature.from_capa(feature),
                    )
                )

            instruction_layouts: List[InstructionLayout] = []
            for insn in extractor.get_instructions(f, bb):
                iaddr = Address.from_capa(insn.address)

                for feature, addr in extractor.extract_insn_features(f, bb, insn):
                    instruction_features.add(
                        InstructionFeature(
                            instruction=iaddr,
                            address=Address.from_capa(addr),
                            feature=Feature.from_capa(feature),
                        )
                    )

                instruction_layouts.append(
                    InstructionLayout(
                        address=iaddr,
                    )
                )

            basic_block_layouts.append(
                BasicBlockLayout(
                    address=bbaddr,
                    instructions=instruction_layouts,
                )
            )

        function_layouts.append(
            FunctionLayout(
                address=faddr,
                basic_blocks=basic_block_layouts,
            )
        )

    layout = Layout(
        functions=function_layouts,
    )

    features = Features(
        global_=global_features,
        file=file_features,
        function=list(function_features),
        basic_block=list(basic_block_features),
        instruction=list(instruction_features),
    )

    freeze = Freeze(
        version=2,
        base_address=Address.from_capa(extractor.get_base_address()),
        layout=layout,
        features=features,
    )

    return freeze.json()


def loads(s: str) -> capa.features.extractors.base_extractor.FeatureExtractor:
    """deserialize a set of features (as a NullFeatureExtractor) from a string."""
    import capa.features.extractors.null as null

    freeze = Freeze.parse_raw(s)
    if freeze.version != 2:
        raise ValueError("unsupported freeze format version: %d", freeze.version)

    function_features_by_address: Dict[
        capa.features.address.Address, List[Tuple[capa.features.address.Address, capa.features.common.Feature]]
    ] = collections.defaultdict(list)
    for f in freeze.features.function:
        function_features_by_address[f.function.to_capa()].append((f.address.to_capa(), f.feature.to_capa()))

    basic_block_features_by_address: Dict[
        capa.features.address.Address, List[Tuple[capa.features.address.Address, capa.features.common.Feature]]
    ] = collections.defaultdict(list)
    for bb in freeze.features.basic_block:
        basic_block_features_by_address[bb.basic_block.to_capa()].append((bb.address.to_capa(), bb.feature.to_capa()))

    instruction_features_by_address: Dict[
        capa.features.address.Address, List[Tuple[capa.features.address.Address, capa.features.common.Feature]]
    ] = collections.defaultdict(list)
    for i in freeze.features.instruction:
        instruction_features_by_address[i.instruction.to_capa()].append((i.address.to_capa(), i.feature.to_capa()))

    return null.NullFeatureExtractor(
        base_address=freeze.base_address.to_capa(),
        global_features=[f.feature.to_capa() for f in freeze.features.global_],
        file_features=[(f.address.to_capa(), f.feature.to_capa()) for f in freeze.features.file],
        functions={
            f.address.to_capa(): null.FunctionFeatures(
                features=function_features_by_address.get(f.address.to_capa(), []),
                basic_blocks={
                    bb.address.to_capa(): null.BasicBlockFeatures(
                        features=basic_block_features_by_address.get(bb.address.to_capa(), []),
                        instructions={
                            i.address.to_capa(): null.InstructionFeatures(
                                features=instruction_features_by_address.get(i.address.to_capa(), []),
                            )
                            for i in bb.instructions
                        },
                    )
                    for bb in f.basic_blocks
                },
            )
            for f in freeze.layout.functions
        },
    )


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
