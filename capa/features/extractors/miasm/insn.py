# Copyright (C) 2020 FireEye, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: https://github.com/fireeye/capa/blob/master/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.


def extract_insn_api_features(extractor, _, _, insn):
    """parse API features from the given instruction."""
    raise NotImplementedError()


def extract_insn_number_features(extractor, f, bb, insn):
    """parse number features from the given instruction."""
    raise NotImplementedError()


def extract_insn_string_features(extractor, f, bb, insn):
    """parse string features from the given instruction."""
    raise NotImplementedError()


def extract_insn_offset_features(extractor, f, bb, insn):
    """parse structure offset features from the given instruction."""
    raise NotImplementedError()


def extract_insn_nzxor_characteristic_features(extractor, f, bb, insn):
    """
    parse non-zeroing XOR instruction from the given instruction.
    ignore expected non-zeroing XORs, e.g. security cookies.
    """
    raise NotImplementedError()


def extract_insn_mnemonic_features(extractor, f, bb, insn):
    """parse mnemonic features from the given instruction."""
    raise NotImplementedError()


def extract_insn_peb_access_characteristic_features(extractor, f, bb, insn):
    """
    parse peb access from the given function. fs:[0x30] on x86, gs:[0x60] on x64
    """
    raise NotImplementedError()


def extract_insn_segment_access_features(extractor, f, bb, insn):
    """ parse the instruction for access to fs or gs """
    raise NotImplementedError()


def extract_insn_cross_section_cflow(extractor, f, bb, insn):
    """
    inspect the instruction for a CALL or JMP that crosses section boundaries.
    """
    raise NotImplementedError()


# this is a feature that's most relevant at the function scope,
# however, its most efficient to extract at the instruction scope.
def extract_function_calls_from(f, bb, insn):
    raise NotImplementedError()


def extract_features(extractor, f, bb, insn):
    """
    extract features from the given insn.
    args:
      extractor (MiasmFeatureExtractor)
      f (miasm.expression.expression.LocKey): the function from which to extract features
      bb (miasm.core.asmblock.AsmBlock): the basic block to process.
      insn (Instruction): the instruction to process.
    yields:
      Feature, set[VA]: the features and their location found in this insn.
    """
    for insn_handler in INSTRUCTION_HANDLERS:
        for feature, va in insn_handler(extractor, f, bb, insn):
            yield feature, va


INSTRUCTION_HANDLERS = (
    # extract_insn_api_features,
    # extract_insn_number_features,
    # extract_insn_string_features,
    # extract_insn_bytes_features,
    # extract_insn_offset_features,
    # extract_insn_nzxor_characteristic_features,
    # extract_insn_mnemonic_features,
    # extract_insn_peb_access_characteristic_features,
    # extract_insn_cross_section_cflow,
    # extract_insn_segment_access_features,
    # extract_function_calls_from,
    # extract_function_indirect_call_characteristic_features,
)
