# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import abc
import dataclasses
from typing import Any, Dict, Tuple, Union, Iterator
from dataclasses import dataclass

import capa.features.address
from capa.features.common import Feature
from capa.features.address import Address, AbsoluteVirtualAddress

# feature extractors may reference functions, BBs, insns by opaque handle values.
# you can use the `.address` property to get and render the address of the feature.
#
# these handles are only consumed by routines on
# the feature extractor from which they were created.


@dataclass
class FunctionHandle:
    """reference to a function recognized by a feature extractor.

    Attributes:
        address: the address of the function.
        inner: extractor-specific data.
        ctx: a context object for the extractor.
    """

    address: Address
    inner: Any
    ctx: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclass
class BBHandle:
    """reference to a basic block recognized by a feature extractor.

    Attributes:
        address: the address of the basic block start address.
        inner: extractor-specific data.
    """

    address: Address
    inner: Any


@dataclass
class InsnHandle:
    """reference to a instruction recognized by a feature extractor.

    Attributes:
        address: the address of the instruction address.
        inner: extractor-specific data.
    """

    address: Address
    inner: Any


class FeatureExtractor:
    """
    FeatureExtractor defines the interface for fetching features from a sample.

    There may be multiple backends that support fetching features for capa.
    For example, we use vivisect by default, but also want to support saving
     and restoring features from a JSON file.
    When we restore the features, we'd like to use exactly the same matching logic
     to find matching rules.
    Therefore, we can define a FeatureExtractor that provides features from the
     serialized JSON file and do matching without a binary analysis pass.
    Also, this provides a way to hook in an IDA backend.

    This class is not instantiated directly; it is the base class for other implementations.
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self):
        #
        # note: a subclass should define ctor parameters for its own use.
        #  for example, the Vivisect feature extract might require the vw and/or path.
        # this base class doesn't know what to do with that info, though.
        #
        super().__init__()

    @abc.abstractmethod
    def get_base_address(self) -> Union[AbsoluteVirtualAddress, capa.features.address._NoAddress]:
        """
        fetch the preferred load address at which the sample was analyzed.

        when the base address is `NO_ADDRESS`, then the loader has no concept of a preferred load address.
        such as: shellcode, .NET modules, etc.
        in these scenarios, RelativeVirtualAddresses aren't used.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def extract_global_features(self) -> Iterator[Tuple[Feature, Address]]:
        """
        extract features found at every scope ("global").

        example::

            extractor = VivisectFeatureExtractor(vw, path)
            for feature, va in extractor.get_global_features():
                print('0x%x: %s', va, feature)

        yields:
          Tuple[Feature, Address]: feature and its location
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        """
        extract file-scope features.

        example::

            extractor = VivisectFeatureExtractor(vw, path)
            for feature, va in extractor.get_file_features():
                print('0x%x: %s', va, feature)

        yields:
          Tuple[Feature, Address]: feature and its location
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_functions(self) -> Iterator[FunctionHandle]:
        """
        enumerate the functions and provide opaque values that will
         subsequently be provided to `.extract_function_features()`, etc.
        """
        raise NotImplementedError()

    def is_library_function(self, addr: Address) -> bool:
        """
        is the given address a library function?
        the backend may implement its own function matching algorithm, or none at all.
        we accept an address here, rather than function object,
         to handle addresses identified in instructions.

        this information is used to:
          - filter out matches in library functions (by default), and
          - recognize when to fetch symbol names for called (non-API) functions

        args:
          addr (Address): the address of a function.

        returns:
          bool: True if the given address is the start of a library function.
        """
        return False

    def get_function_name(self, addr: Address) -> str:
        """
        fetch any recognized name for the given address.
        this is only guaranteed to return a value when the given function is a recognized library function.
        we accept a VA here, rather than function object, to handle addresses identified in instructions.

        args:
          addr (Address): the address of a function.

        returns:
          str: the function name

        raises:
          KeyError: when the given function does not have a name.
        """
        raise KeyError(addr)

    @abc.abstractmethod
    def extract_function_features(self, f: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
        """
        extract function-scope features.
        the arguments are opaque values previously provided by `.get_functions()`, etc.

        example::

            extractor = VivisectFeatureExtractor(vw, path)
            for function in extractor.get_functions():
                for feature, address in extractor.extract_function_features(function):
                    print('0x%x: %s', address, feature)

        args:
          f [FunctionHandle]: an opaque value previously fetched from `.get_functions()`.

        yields:
          Tuple[Feature, Address]: feature and its location
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_basic_blocks(self, f: FunctionHandle) -> Iterator[BBHandle]:
        """
        enumerate the basic blocks in the given function and provide opaque values that will
         subsequently be provided to `.extract_basic_block_features()`, etc.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def extract_basic_block_features(self, f: FunctionHandle, bb: BBHandle) -> Iterator[Tuple[Feature, Address]]:
        """
        extract basic block-scope features.
        the arguments are opaque values previously provided by `.get_functions()`, etc.

        example::

            extractor = VivisectFeatureExtractor(vw, path)
            for function in extractor.get_functions():
                for bb in extractor.get_basic_blocks(function):
                    for feature, address in extractor.extract_basic_block_features(function, bb):
                        print('0x%x: %s', address, feature)

        args:
          f [FunctionHandle]: an opaque value previously fetched from `.get_functions()`.
          bb [BBHandle]: an opaque value previously fetched from `.get_basic_blocks()`.

        yields:
          Tuple[Feature, Address]: feature and its location
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def get_instructions(self, f: FunctionHandle, bb: BBHandle) -> Iterator[InsnHandle]:
        """
        enumerate the instructions in the given basic block and provide opaque values that will
         subsequently be provided to `.extract_insn_features()`, etc.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def extract_insn_features(
        self, f: FunctionHandle, bb: BBHandle, insn: InsnHandle
    ) -> Iterator[Tuple[Feature, Address]]:
        """
        extract instruction-scope features.
        the arguments are opaque values previously provided by `.get_functions()`, etc.

        example::

            extractor = VivisectFeatureExtractor(vw, path)
            for function in extractor.get_functions():
                for bb in extractor.get_basic_blocks(function):
                    for insn in extractor.get_instructions(function, bb):
                        for feature, address in extractor.extract_insn_features(function, bb, insn):
                            print('0x%x: %s', address, feature)

        args:
          f [FunctionHandle]: an opaque value previously fetched from `.get_functions()`.
          bb [BBHandle]: an opaque value previously fetched from `.get_basic_blocks()`.
          insn [InsnHandle]: an opaque value previously fetched from `.get_instructions()`.

        yields:
          Tuple[Feature, Address]: feature and its location
        """
        raise NotImplementedError()
