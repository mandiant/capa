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
from enum import Enum
from typing import Any, List, Tuple, Union

from pydantic import Field, BaseModel

import capa.helpers
import capa.version
import capa.features.file
import capa.features.insn
import capa.features.common
import capa.features.address
import capa.features.basicblock
import capa.features.extractors.base_extractor
from capa.helpers import assert_never
from capa.features.freeze.features import Feature, feature_from_capa

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
    value: Union[int, Tuple[int, int], None]

    @classmethod
    def from_capa(cls, a: capa.features.address.Address) -> "Address":
        if isinstance(a, capa.features.address.AbsoluteVirtualAddress):
            return cls(type=AddressType.ABSOLUTE, value=int(a))

        elif isinstance(a, capa.features.address.RelativeVirtualAddress):
            return cls(type=AddressType.RELATIVE, value=int(a))

        elif isinstance(a, capa.features.address.FileOffsetAddress):
            return cls(type=AddressType.FILE, value=int(a))

        elif isinstance(a, capa.features.address.DNTokenAddress):
            return cls(type=AddressType.DN_TOKEN, value=int(a))

        elif isinstance(a, capa.features.address.DNTokenOffsetAddress):
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
            assert isinstance(self.value, int)
            return capa.features.address.AbsoluteVirtualAddress(self.value)

        elif self.type is AddressType.RELATIVE:
            assert isinstance(self.value, int)
            return capa.features.address.RelativeVirtualAddress(self.value)

        elif self.type is AddressType.FILE:
            assert isinstance(self.value, int)
            return capa.features.address.FileOffsetAddress(self.value)

        elif self.type is AddressType.DN_TOKEN:
            assert isinstance(self.value, int)
            return capa.features.address.DNTokenAddress(self.value)

        elif self.type is AddressType.DN_TOKEN_OFFSET:
            assert isinstance(self.value, tuple)
            token, offset = self.value
            assert isinstance(token, int)
            assert isinstance(offset, int)
            return capa.features.address.DNTokenOffsetAddress(token, offset)

        elif self.type is AddressType.NO_ADDRESS:
            return capa.features.address.NO_ADDRESS

        else:
            assert_never(self.type)

    def __lt__(self, other: "Address") -> bool:
        if self.type != other.type:
            return self.type < other.type

        if self.type is AddressType.NO_ADDRESS:
            return True

        else:
            assert self.type == other.type
            # mypy doesn't realize we've proven that either
            # both are ints, or both are tuples of ints.
            # and both of these are comparable.
            return self.value < other.value  # type: ignore


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

    basic_block: Address = Field(alias="basic block")
    address: Address
    feature: Feature

    class Config:
        allow_population_by_field_name = True


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


class InstructionFeatures(BaseModel):
    address: Address
    features: Tuple[InstructionFeature, ...]


class BasicBlockFeatures(BaseModel):
    address: Address
    features: Tuple[BasicBlockFeature, ...]
    instructions: Tuple[InstructionFeatures, ...]


class FunctionFeatures(BaseModel):
    address: Address
    features: Tuple[FunctionFeature, ...]
    basic_blocks: Tuple[BasicBlockFeatures, ...] = Field(alias="basic blocks")

    class Config:
        allow_population_by_field_name = True


class Features(BaseModel):
    global_: Tuple[GlobalFeature, ...] = Field(alias="global")
    file: Tuple[FileFeature, ...]
    functions: Tuple[FunctionFeatures, ...]

    class Config:
        allow_population_by_field_name = True


class Extractor(BaseModel):
    name: str
    version: str = capa.version.__version__

    class Config:
        allow_population_by_field_name = True


class Freeze(BaseModel):
    version: int = 2
    base_address: Address = Field(alias="base address")
    extractor: Extractor
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
                feature=feature_from_capa(feature),
            )
        )

    file_features: List[FileFeature] = []
    for feature, address in extractor.extract_file_features():
        file_features.append(
            FileFeature(
                feature=feature_from_capa(feature),
                address=Address.from_capa(address),
            )
        )

    function_features: List[FunctionFeatures] = []
    for f in extractor.get_functions():
        faddr = Address.from_capa(f.address)
        ffeatures = [
            FunctionFeature(
                function=faddr,
                address=Address.from_capa(addr),
                feature=feature_from_capa(feature),
            )
            for feature, addr in extractor.extract_function_features(f)
        ]

        basic_blocks = []
        for bb in extractor.get_basic_blocks(f):
            bbaddr = Address.from_capa(bb.address)
            bbfeatures = [
                BasicBlockFeature(
                    basic_block=bbaddr,
                    address=Address.from_capa(addr),
                    feature=feature_from_capa(feature),
                )  # type: ignore
                # Mypy is unable to recognise `basic_block` as a argument due to alias
                for feature, addr in extractor.extract_basic_block_features(f, bb)
            ]

            instructions = []
            for insn in extractor.get_instructions(f, bb):
                iaddr = Address.from_capa(insn.address)
                ifeatures = [
                    InstructionFeature(
                        instruction=iaddr,
                        address=Address.from_capa(addr),
                        feature=feature_from_capa(feature),
                    )
                    for feature, addr in extractor.extract_insn_features(f, bb, insn)
                ]

                instructions.append(
                    InstructionFeatures(
                        address=iaddr,
                        features=tuple(ifeatures),
                    )
                )

            basic_blocks.append(
                BasicBlockFeatures(
                    address=bbaddr,
                    features=tuple(bbfeatures),
                    instructions=tuple(instructions),
                )
            )

        function_features.append(
            FunctionFeatures(
                address=faddr,
                features=tuple(ffeatures),
                basic_blocks=basic_blocks,
            )  # type: ignore
            # Mypy is unable to recognise `basic_blocks` as a argument due to alias
        )

    features = Features(
        global_=global_features,
        file=tuple(file_features),
        functions=tuple(function_features),
    )  # type: ignore
    # Mypy is unable to recognise `global_` as a argument due to alias

    freeze = Freeze(
        version=2,
        base_address=Address.from_capa(extractor.get_base_address()),
        extractor=Extractor(name=extractor.__class__.__name__),
        features=features,
    )  # type: ignore
    # Mypy is unable to recognise `base_address` as a argument due to alias

    return freeze.json()


def loads(s: str) -> capa.features.extractors.base_extractor.FeatureExtractor:
    """deserialize a set of features (as a NullFeatureExtractor) from a string."""
    import capa.features.extractors.null as null

    freeze = Freeze.parse_raw(s)
    if freeze.version != 2:
        raise ValueError(f"unsupported freeze format version: {freeze.version}")

    return null.NullFeatureExtractor(
        base_address=freeze.base_address.to_capa(),
        global_features=[f.feature.to_capa() for f in freeze.features.global_],
        file_features=[(f.address.to_capa(), f.feature.to_capa()) for f in freeze.features.file],
        functions={
            f.address.to_capa(): null.FunctionFeatures(
                features=[(fe.address.to_capa(), fe.feature.to_capa()) for fe in f.features],
                basic_blocks={
                    bb.address.to_capa(): null.BasicBlockFeatures(
                        features=[(fe.address.to_capa(), fe.feature.to_capa()) for fe in bb.features],
                        instructions={
                            i.address.to_capa(): null.InstructionFeatures(
                                features=[(fe.address.to_capa(), fe.feature.to_capa()) for fe in i.features]
                            )
                            for i in bb.instructions
                        },
                    )
                    for bb in f.basic_blocks
                },
            )
            for f in freeze.features.functions
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
    capa.main.install_common_args(parser, {"sample", "format", "backend", "os", "signatures"})
    parser.add_argument("output", type=str, help="Path to output file")
    args = parser.parse_args(args=argv)
    capa.main.handle_common_args(args)

    sigpaths = capa.main.get_signatures(args.signatures)

    extractor = capa.main.get_extractor(args.sample, args.format, args.os, args.backend, sigpaths, False)

    with open(args.output, "wb") as f:
        f.write(dump(extractor))

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
