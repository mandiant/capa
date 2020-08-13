# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import abc


class FeatureExtractor(object):
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
        super(FeatureExtractor, self).__init__()

    @abc.abstractmethod
    def get_base_address(self):
        """
        fetch the preferred load address at which the sample was analyzed.

        returns: int
        """
        raise NotImplemented

    @abc.abstractmethod
    def extract_file_features(self):
        """
        extract file-scope features.

        example::

            extractor = VivisectFeatureExtractor(vw, path)
            for feature, va in extractor.get_file_features():
                print('0x%x: %s', va, feature)

        yields:
          Tuple[capa.features.Feature, int]: feature and its location
        """
        raise NotImplemented

    @abc.abstractmethod
    def get_functions(self):
        """
        enumerate the functions and provide opaque values that will
         subsequently be provided to `.extract_function_features()`, etc.

        by "opaque value", we mean that this can be any object, as long as it
         provides enough context to `.extract_function_features()`.

        the opaque value should support casting to int (`__int__`) for the function start address.

        yields:
          any: the opaque function value.
        """
        raise NotImplemented

    @abc.abstractmethod
    def extract_function_features(self, f):
        """
        extract function-scope features.
        the arguments are opaque values previously provided by `.get_functions()`, etc.

        example::

            extractor = VivisectFeatureExtractor(vw, path)
            for function in extractor.get_functions():
                for feature, va in extractor.extract_function_features(function):
                    print('0x%x: %s', va, feature)

        args:
          f [any]: an opaque value previously fetched from `.get_functions()`.

        yields:
          Tuple[capa.features.Feature, int]: feature and its location
        """
        raise NotImplemented

    @abc.abstractmethod
    def get_basic_blocks(self, f):
        """
        enumerate the basic blocks in the given function and provide opaque values that will
         subsequently be provided to `.extract_basic_block_features()`, etc.

        by "opaque value", we mean that this can be any object, as long as it
         provides enough context to `.extract_basic_block_features()`.

        the opaque value should support casting to int (`__int__`) for the basic block start address.

        yields:
          any: the opaque basic block value.
        """
        raise NotImplemented

    @abc.abstractmethod
    def extract_basic_block_features(self, f, bb):
        """
        extract basic block-scope features.
        the arguments are opaque values previously provided by `.get_functions()`, etc.

        example::

            extractor = VivisectFeatureExtractor(vw, path)
            for function in extractor.get_functions():
                for bb in extractor.get_basic_blocks(function):
                    for feature, va in extractor.extract_basic_block_features(function, bb):
                        print('0x%x: %s', va, feature)

        args:
          f [any]: an opaque value previously fetched from `.get_functions()`.
          bb [any]: an opaque value previously fetched from `.get_basic_blocks()`.

        yields:
          Tuple[capa.features.Feature, int]: feature and its location
        """
        raise NotImplemented

    @abc.abstractmethod
    def get_instructions(self, f, bb):
        """
        enumerate the instructions in the given basic block and provide opaque values that will
         subsequently be provided to `.extract_insn_features()`, etc.

        by "opaque value", we mean that this can be any object, as long as it
         provides enough context to `.extract_insn_features()`.

        the opaque value should support casting to int (`__int__`) for the instruction address.

        yields:
          any: the opaque function value.
        """
        raise NotImplemented

    @abc.abstractmethod
    def extract_insn_features(self, f, bb, insn):
        """
        extract instruction-scope features.
        the arguments are opaque values previously provided by `.get_functions()`, etc.

        example::

            extractor = VivisectFeatureExtractor(vw, path)
            for function in extractor.get_functions():
                for bb in extractor.get_basic_blocks(function):
                    for insn in extractor.get_instructions(function, bb):
                        for feature, va in extractor.extract_insn_features(function, bb, insn):
                            print('0x%x: %s', va, feature)

        args:
          f [any]: an opaque value previously fetched from `.get_functions()`.
          bb [any]: an opaque value previously fetched from `.get_basic_blocks()`.
          insn [any]: an opaque value previously fetched from `.get_instructions()`.

        yields:
          Tuple[capa.features.Feature, int]: feature and its location
        """
        raise NotImplemented


class NullFeatureExtractor(FeatureExtractor):
    """
    An extractor that extracts some user-provided features.
    The structure of the single parameter is demonstrated in the example below.

    This is useful for testing, as we can provide expected values and see if matching works.
    Also, this is how we represent features deserialized from a freeze file.

    example::

        extractor = NullFeatureExtractor({
            'base address: 0x401000,
            'file features': [
                (0x402345, capa.features.Characteristic('embedded pe')),
            ],
            'functions': {
                0x401000: {
                    'features': [
                        (0x401000, capa.features.Characteristic('nzxor')),
                    ],
                    'basic blocks': {
                        0x401000: {
                            'features': [
                                (0x401000, capa.features.Characteristic('tight-loop')),
                            ],
                            'instructions': {
                                0x401000: {
                                    'features': [
                                        (0x401000, capa.features.Characteristic('nzxor')),
                                    ],
                                },
                                0x401002: ...
                            }
                        },
                        0x401005: ...
                    }
                },
                0x40200: ...
            }
        )
    """

    def __init__(self, features):
        super(NullFeatureExtractor, self).__init__()
        self.features = features

    def get_base_address(self):
        return self.features["base address"]

    def extract_file_features(self):
        for p in self.features.get("file features", []):
            va, feature = p
            yield feature, va

    def get_functions(self):
        for va in sorted(self.features["functions"].keys()):
            yield va

    def extract_function_features(self, f):
        for p in self.features.get("functions", {}).get(f, {}).get("features", []):  # noqa: E127 line over-indented
            va, feature = p
            yield feature, va

    def get_basic_blocks(self, f):
        for va in sorted(
            self.features.get("functions", {})  # noqa: E127 line over-indented
            .get(f, {})
            .get("basic blocks", {})
            .keys()
        ):
            yield va

    def extract_basic_block_features(self, f, bb):
        for p in (
            self.features.get("functions", {})  # noqa: E127 line over-indented
            .get(f, {})
            .get("basic blocks", {})
            .get(bb, {})
            .get("features", [])
        ):
            va, feature = p
            yield feature, va

    def get_instructions(self, f, bb):
        for va in sorted(
            self.features.get("functions", {})  # noqa: E127 line over-indented
            .get(f, {})
            .get("basic blocks", {})
            .get(bb, {})
            .get("instructions", {})
            .keys()
        ):
            yield va

    def extract_insn_features(self, f, bb, insn):
        for p in (
            self.features.get("functions", {})  # noqa: E127 line over-indented
            .get(f, {})
            .get("basic blocks", {})
            .get(bb, {})
            .get("instructions", {})
            .get(insn, {})
            .get("features", [])
        ):
            va, feature = p
            yield feature, va
