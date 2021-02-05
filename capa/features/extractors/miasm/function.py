# Copyright (C) 2020 FireEye, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: https://github.com/fireeye/capa/blob/master/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from capa.features import Characteristic


def extract_function_calls_to(extractor, loc_key):
    for pred_key in extractor.cfg.predecessors(loc_key):
        pred_block = extractor.cfg.loc_key_to_block(pred_key)
        pred_insn = pred_block.get_subcall_instr()
        if pred_insn and pred_insn.is_subcall():
            dst = pred_insn.args[0]
            if dst.is_loc() and dst.loc_key == loc_key:
                yield Characteristic("calls to"), pred_insn.offset


def extract_function_loop(extractor, loc_key):
    """
    returns if the function has a loop
    """
    block = extractor.cfg.loc_key_to_block(loc_key)
    disassembler = extractor.machine.dis_engine(
        extractor.container.bin_stream, loc_db=extractor.loc_db, follow_call=False
    )
    offset = extractor.block_offset(block)
    cfg = disassembler.dis_multiblock(offset)
    if cfg.has_loop():
        yield Characteristic("loop"), offset


def extract_features(extractor, loc_key):
    """
    extract features from the given function.
    args:
      cfg (AsmCFG): the CFG of the function from which to extract features
      loc_key (LocKey): LocKey which represents the beginning of the function
    yields:
      Feature, set[VA]: the features and their location found in this function.
    """
    for func_handler in FUNCTION_HANDLERS:
        for feature, va in func_handler(extractor, loc_key):
            yield feature, va


FUNCTION_HANDLERS = (extract_function_calls_to, extract_function_loop)
