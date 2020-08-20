# Copyright (C) 2020 FireEye, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: https://github.com/fireeye/capa/blob/master/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import miasm.analysis.binary
import miasm.analysis.machine

import capa.features.extractors.miasm.file
import capa.features.extractors.miasm.insn
import capa.features.extractors.miasm.function
import capa.features.extractors.miasm.basicblock
from capa.features.extractors import FeatureExtractor


class MiasmFeatureExtractor(FeatureExtractor):
    def __init__(self, buf):
        super(MiasmFeatureExtractor, self).__init__()
        self.buf = buf
        self.container = miasm.analysis.binary.Container.from_string(buf)
        self.pe = self.container.executable
        self.machine = miasm.analysis.machine.Machine(self.container.arch)
        self.cfg = self._build_cfg()

    def get_base_address(self):
        return self.container.entry_point

    def extract_file_features(self):
        for feature, va in capa.features.extractors.miasm.file.extract_file_features(self.buf, self.pe):
            yield feature, va

    # TODO: Improve this function (it just considers all loc_keys target of calls a function), port to miasm
    def get_functions(self):
        """
        returns all loc_keys which are the argument of any call function
        """
        functions = set()

        for block in self.cfg.blocks:
            for line in block.lines:
                if line.is_subcall() and line.args[0].is_loc():
                    loc_key = line.args[0].loc_key
                    if loc_key not in functions:
                        functions.add(loc_key)
                        yield loc_key

    def extract_function_features(self, loc_key):
        for feature, va in capa.features.extractors.miasm.function.extract_features(self, loc_key):
            yield feature, va

    def block_offset(self, bb):
        return bb.lines[0].offset

    def get_basic_blocks(self, loc_key):
        """
        get the basic blocks of the function represented by lock_key
        """
        block = self.cfg.loc_key_to_block(loc_key)
        disassembler = self.machine.dis_engine(self.container.bin_stream, follow_call=False)
        cfg = disassembler.dis_multiblock(self.block_offset(block))
        return cfg.blocks

    def extract_basic_block_features(self, _, bb):
        for feature, va in capa.features.extractors.miasm.basicblock.extract_features(bb):
            yield feature, va

    def get_instructions(self, _, bb):
        return bb.lines

    def extract_insn_features(self, f, bb, insn):
        for feature, va in capa.features.extractors.miasm.insn.extract_features(self, f, bb, insn):
            yield feature, va

    def _get_entry_points(self):
        entry_points = {self.get_base_address()}

        for _, va in miasm.jitter.loader.pe.get_export_name_addr_list(self.pe):
            entry_points.add(va)

        return entry_points

    # This is more efficient that using the `blocks` argument in `dis_multiblock`
    # See http://www.williballenthin.com/post/2020-01-12-miasm-part-2
    # TODO: port this efficiency improvement to miasm
    def _build_cfg(self):
        loc_db = self.container.loc_db
        disassembler = self.machine.dis_engine(self.container.bin_stream, follow_call=True, loc_db=loc_db)
        job_done = set()
        cfgs = {}

        for va in self._get_entry_points():
            cfgs[va] = disassembler.dis_multiblock(va, job_done=job_done)

        complete_cfs = miasm.core.asmblock.AsmCFG(loc_db)
        for cfg in cfgs.values():
            complete_cfs.merge(cfg)

        disassembler.apply_splitting(complete_cfs)
        return complete_cfs
