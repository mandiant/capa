"""
capa freeze file format: `| capa0000 | + zlib(utf-8(json(...)))`

Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
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
from enum import Enum
from typing import List, Tuple, Union, Literal

from pydantic import Field, BaseModel, ConfigDict

# TODO(williballenthin): use typing.TypeAlias directly in Python 3.10+
# https://github.com/mandiant/capa/issues/1699
from typing_extensions import TypeAlias

import capa.helpers
import capa.version
import capa.features.file
import capa.features.insn
import capa.features.common
import capa.features.address
import capa.features.basicblock
import capa.features.extractors.null as null
from capa.helpers import assert_never
from capa.features.freeze.features import Feature, feature_from_capa
from capa.features.extractors.base_extractor import (
    SampleHashes,
    FeatureExtractor,
    StaticFeatureExtractor,
    DynamicFeatureExtractor,
)

logger = logging.getLogger(__name__)

CURRENT_VERSION = 3


class HashableModel(BaseModel):
    model_config = ConfigDict(frozen=True)


class AddressType(str, Enum):
    ABSOLUTE = "absolute"
    RELATIVE = "relative"
    FILE = "file"
    DN_TOKEN = "dn token"
    DN_TOKEN_OFFSET = "dn token offset"
    PROCESS = "process"
    THREAD = "thread"
    CALL = "call"
    NO_ADDRESS = "no address"


class Address(HashableModel):
    type: AddressType
    value: Union[int, Tuple[int, ...], None] = None  # None default value to support deserialization of NO_ADDRESS

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

        elif isinstance(a, capa.features.address.ProcessAddress):
            return cls(type=AddressType.PROCESS, value=(a.ppid, a.pid))

        elif isinstance(a, capa.features.address.ThreadAddress):
            return cls(type=AddressType.THREAD, value=(a.process.ppid, a.process.pid, a.tid))

        elif isinstance(a, capa.features.address.DynamicCallAddress):
            return cls(type=AddressType.CALL, value=(a.thread.process.ppid, a.thread.process.pid, a.thread.tid, a.id))

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

        elif self.type is AddressType.PROCESS:
            assert isinstance(self.value, tuple)
            ppid, pid = self.value
            assert isinstance(ppid, int)
            assert isinstance(pid, int)
            return capa.features.address.ProcessAddress(ppid=ppid, pid=pid)

        elif self.type is AddressType.THREAD:
            assert isinstance(self.value, tuple)
            ppid, pid, tid = self.value
            assert isinstance(ppid, int)
            assert isinstance(pid, int)
            assert isinstance(tid, int)
            return capa.features.address.ThreadAddress(
                process=capa.features.address.ProcessAddress(ppid=ppid, pid=pid), tid=tid
            )

        elif self.type is AddressType.CALL:
            assert isinstance(self.value, tuple)
            ppid, pid, tid, id_ = self.value
            return capa.features.address.DynamicCallAddress(
                thread=capa.features.address.ThreadAddress(
                    process=capa.features.address.ProcessAddress(ppid=ppid, pid=pid), tid=tid
                ),
                id=id_,
            )

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


class ProcessFeature(HashableModel):
    """
    args:
        process: the address of the process to which this feature belongs.
        address: the address at which this feature is found.

    process != address because, e.g., the feature may be found *within* the scope (process).
    """

    process: Address
    address: Address
    feature: Feature


class ThreadFeature(HashableModel):
    """
    args:
        thread: the address of the thread to which this feature belongs.
        address: the address at which this feature is found.

    thread != address because, e.g., the feature may be found *within* the scope (thread).
    """

    thread: Address
    address: Address
    feature: Feature


class CallFeature(HashableModel):
    """
    args:
        call: the address of the call to which this feature belongs.
        address: the address at which this feature is found.

    call != address for consistency with Process and Thread.
    """

    call: Address
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
    model_config = ConfigDict(populate_by_name=True)


class InstructionFeature(HashableModel):
    """
    args:
        instruction: the address of the instruction to which this feature belongs.
        address: the address at which this feature is found.

    instruction != address because, for consistency with Function and BasicBlock.
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
    model_config = ConfigDict(populate_by_name=True)


class CallFeatures(BaseModel):
    address: Address
    name: str
    features: Tuple[CallFeature, ...]


class ThreadFeatures(BaseModel):
    address: Address
    features: Tuple[ThreadFeature, ...]
    calls: Tuple[CallFeatures, ...]


class ProcessFeatures(BaseModel):
    address: Address
    name: str
    features: Tuple[ProcessFeature, ...]
    threads: Tuple[ThreadFeatures, ...]


class StaticFeatures(BaseModel):
    global_: Tuple[GlobalFeature, ...] = Field(alias="global")
    file: Tuple[FileFeature, ...]
    functions: Tuple[FunctionFeatures, ...]
    model_config = ConfigDict(populate_by_name=True)


class DynamicFeatures(BaseModel):
    global_: Tuple[GlobalFeature, ...] = Field(alias="global")
    file: Tuple[FileFeature, ...]
    processes: Tuple[ProcessFeatures, ...]
    model_config = ConfigDict(populate_by_name=True)


Features: TypeAlias = Union[StaticFeatures, DynamicFeatures]


class Extractor(BaseModel):
    name: str
    version: str = capa.version.__version__
    model_config = ConfigDict(populate_by_name=True)


class Freeze(BaseModel):
    version: int = CURRENT_VERSION
    base_address: Address = Field(alias="base address")
    sample_hashes: SampleHashes
    flavor: Literal["static", "dynamic"]
    extractor: Extractor
    features: Features
    model_config = ConfigDict(populate_by_name=True)


def dumps_static(extractor: StaticFeatureExtractor) -> str:
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

    features = StaticFeatures(
        global_=global_features,
        file=tuple(file_features),
        functions=tuple(function_features),
    )  # type: ignore
    # Mypy is unable to recognise `global_` as a argument due to alias

    freeze = Freeze(
        version=CURRENT_VERSION,
        base_address=Address.from_capa(extractor.get_base_address()),
        sample_hashes=extractor.get_sample_hashes(),
        flavor="static",
        extractor=Extractor(name=extractor.__class__.__name__),
        features=features,
    )  # type: ignore
    # Mypy is unable to recognise `base_address` as a argument due to alias

    return freeze.model_dump_json()


def dumps_dynamic(extractor: DynamicFeatureExtractor) -> str:
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

    process_features: List[ProcessFeatures] = []
    for p in extractor.get_processes():
        paddr = Address.from_capa(p.address)
        pname = extractor.get_process_name(p)
        pfeatures = [
            ProcessFeature(
                process=paddr,
                address=Address.from_capa(addr),
                feature=feature_from_capa(feature),
            )
            for feature, addr in extractor.extract_process_features(p)
        ]

        threads = []
        for t in extractor.get_threads(p):
            taddr = Address.from_capa(t.address)
            tfeatures = [
                ThreadFeature(
                    basic_block=taddr,
                    address=Address.from_capa(addr),
                    feature=feature_from_capa(feature),
                )  # type: ignore
                # Mypy is unable to recognise `basic_block` as a argument due to alias
                for feature, addr in extractor.extract_thread_features(p, t)
            ]

            calls = []
            for call in extractor.get_calls(p, t):
                caddr = Address.from_capa(call.address)
                cname = extractor.get_call_name(p, t, call)
                cfeatures = [
                    CallFeature(
                        call=caddr,
                        address=Address.from_capa(addr),
                        feature=feature_from_capa(feature),
                    )
                    for feature, addr in extractor.extract_call_features(p, t, call)
                ]

                calls.append(
                    CallFeatures(
                        address=caddr,
                        name=cname,
                        features=tuple(cfeatures),
                    )
                )

            threads.append(
                ThreadFeatures(
                    address=taddr,
                    features=tuple(tfeatures),
                    calls=tuple(calls),
                )
            )

        process_features.append(
            ProcessFeatures(
                address=paddr,
                name=pname,
                features=tuple(pfeatures),
                threads=tuple(threads),
            )
        )

    features = DynamicFeatures(
        global_=global_features,
        file=tuple(file_features),
        processes=tuple(process_features),
    )  # type: ignore
    # Mypy is unable to recognise `global_` as a argument due to alias

    # workaround around mypy issue: https://github.com/python/mypy/issues/1424
    get_base_addr = getattr(extractor, "get_base_addr", None)
    base_addr = get_base_addr() if get_base_addr else capa.features.address.NO_ADDRESS

    freeze = Freeze(
        version=CURRENT_VERSION,
        base_address=Address.from_capa(base_addr),
        sample_hashes=extractor.get_sample_hashes(),
        flavor="dynamic",
        extractor=Extractor(name=extractor.__class__.__name__),
        features=features,
    )  # type: ignore
    # Mypy is unable to recognise `base_address` as a argument due to alias

    return freeze.model_dump_json()


def loads_static(s: str) -> StaticFeatureExtractor:
    """deserialize a set of features (as a NullStaticFeatureExtractor) from a string."""
    freeze = Freeze.model_validate_json(s)
    if freeze.version != CURRENT_VERSION:
        raise ValueError(f"unsupported freeze format version: {freeze.version}")

    assert freeze.flavor == "static"
    assert isinstance(freeze.features, StaticFeatures)

    return null.NullStaticFeatureExtractor(
        base_address=freeze.base_address.to_capa(),
        sample_hashes=freeze.sample_hashes,
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


def loads_dynamic(s: str) -> DynamicFeatureExtractor:
    """deserialize a set of features (as a NullDynamicFeatureExtractor) from a string."""
    freeze = Freeze.model_validate_json(s)
    if freeze.version != CURRENT_VERSION:
        raise ValueError(f"unsupported freeze format version: {freeze.version}")

    assert freeze.flavor == "dynamic"
    assert isinstance(freeze.features, DynamicFeatures)

    return null.NullDynamicFeatureExtractor(
        base_address=freeze.base_address.to_capa(),
        sample_hashes=freeze.sample_hashes,
        global_features=[f.feature.to_capa() for f in freeze.features.global_],
        file_features=[(f.address.to_capa(), f.feature.to_capa()) for f in freeze.features.file],
        processes={
            p.address.to_capa(): null.ProcessFeatures(
                name=p.name,
                features=[(fe.address.to_capa(), fe.feature.to_capa()) for fe in p.features],
                threads={
                    t.address.to_capa(): null.ThreadFeatures(
                        features=[(fe.address.to_capa(), fe.feature.to_capa()) for fe in t.features],
                        calls={
                            c.address.to_capa(): null.CallFeatures(
                                name=c.name,
                                features=[(fe.address.to_capa(), fe.feature.to_capa()) for fe in c.features],
                            )
                            for c in t.calls
                        },
                    )
                    for t in p.threads
                },
            )
            for p in freeze.features.processes
        },
    )


MAGIC = "capa0000".encode("ascii")


def dumps(extractor: FeatureExtractor) -> str:
    """serialize the given extractor to a string."""
    if isinstance(extractor, StaticFeatureExtractor):
        doc = dumps_static(extractor)
    elif isinstance(extractor, DynamicFeatureExtractor):
        doc = dumps_dynamic(extractor)
    else:
        raise ValueError("Invalid feature extractor")

    return doc


def dump(extractor: FeatureExtractor) -> bytes:
    """serialize the given extractor to a byte array."""
    return MAGIC + zlib.compress(dumps(extractor).encode("utf-8"))


def is_freeze(buf: bytes) -> bool:
    return buf[: len(MAGIC)] == MAGIC


def loads(s: str):
    doc = json.loads(s)

    if doc["version"] != CURRENT_VERSION:
        raise ValueError(f"unsupported freeze format version: {doc['version']}")

    if doc["flavor"] == "static":
        return loads_static(s)
    elif doc["flavor"] == "dynamic":
        return loads_dynamic(s)
    else:
        raise ValueError(f"unsupported freeze format flavor: {doc['flavor']}")


def load(buf: bytes):
    """deserialize a set of features (as a NullFeatureExtractor) from a byte array."""
    if not is_freeze(buf):
        raise ValueError("missing magic header")

    s = zlib.decompress(buf[len(MAGIC) :]).decode("utf-8")

    return loads(s)


def main(argv=None):
    import sys
    import argparse
    from pathlib import Path

    import capa.main

    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="save capa features to a file")
    capa.main.install_common_args(parser, {"input_file", "format", "backend", "os", "signatures"})
    parser.add_argument("output", type=str, help="Path to output file")
    args = parser.parse_args(args=argv)

    try:
        capa.main.handle_common_args(args)
        capa.main.ensure_input_exists_from_cli(args)
        input_format = capa.main.get_input_format_from_cli(args)
        backend = capa.main.get_backend_from_cli(args, input_format)
        extractor = capa.main.get_extractor_from_cli(args, input_format, backend)
    except capa.main.ShouldExitError as e:
        return e.status_code

    Path(args.output).write_bytes(dump(extractor))

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
