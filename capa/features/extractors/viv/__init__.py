# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import types
import logging

import viv_utils
import vivisect.const

import capa.features.extractors
import capa.features.extractors.viv.file
import capa.features.extractors.viv.insn
import capa.features.extractors.viv.function
import capa.features.extractors.viv.basicblock
from capa.features.extractors import FeatureExtractor

__all__ = ["file", "function", "basicblock", "insn"]
logger = logging.getLogger(__name__)


def get_va(self):
    try:
        # vivisect type
        return self.va
    except AttributeError:
        pass

    raise TypeError()


def add_va_int_cast(o):
    """
    dynamically add a cast-to-int (`__int__`) method to the given object
    that returns the value of the `.va` property.

    this bit of skullduggery lets use cast viv-utils objects as ints.
    the correct way of doing this is to update viv-utils (or subclass the objects here).
    """
    setattr(o, "__int__", types.MethodType(get_va, o))
    return o


import time
import contextlib


@contextlib.contextmanager
def timing(msg):
    t0 = time.time()
    yield
    t1 = time.time()
    logger.debug("perf: %s: %0.2fs", msg, t1 - t0)



class VivisectFeatureExtractor(FeatureExtractor):
    def __init__(self, vw, path):
        super(VivisectFeatureExtractor, self).__init__()
        self.vw = vw
        self.path = path

        import flirt

        # vc32rtf.sig:
        #   60,195 total signatures
        #   parsing sig: 0.13s
        #   compiling sigs: 1.18s
        #
        # libcmt_15_msvc_x86
        #   396 total signatures
        #   parsing pat: 0.09s
        #   parsing sigs: 0.01s
 
        #sigfile = ""
        sigfile = "vc32rtf.sig"
        #sigfile = "libcmt_15_msvc_x86.pat"

        if sigfile.endswith(".sig"):
            with open(sigfile, "rb") as f:
                with timing("flirt: parsing .sig: " + sigfile):
                    sigs = flirt.parse_sig(f.read())
        elif sigfile.endswith(".pat"):
            with open(sigfile, "rb") as f:
                with timing("flirt: parsing .pat: " + sigfile):
                    sigs = flirt.parse_pat(f.read().decode("utf-8"))
        else:
            sigs = []

        logger.debug("flirt: sig count: %d", len(sigs))

        with timing("flirt: compiling sigs"):
            matcher = flirt.compile(sigs)

        with timing("flirt: matching sigs"):
            match_vw_flirt_signatures(matcher, vw)

    def get_base_address(self):
        # assume there is only one file loaded into the vw
        return list(self.vw.filemeta.values())[0]["imagebase"]

    def extract_file_features(self):
        for feature, va in capa.features.extractors.viv.file.extract_features(self.vw, self.path):
            yield feature, va

    def get_functions(self):
        for va in sorted(self.vw.getFunctions()):
            yield add_va_int_cast(viv_utils.Function(self.vw, va))

    def extract_function_features(self, f):
        for feature, va in capa.features.extractors.viv.function.extract_features(f):
            yield feature, va

    def get_basic_blocks(self, f):
        for bb in f.basic_blocks:
            yield add_va_int_cast(bb)

    def extract_basic_block_features(self, f, bb):
        for feature, va in capa.features.extractors.viv.basicblock.extract_features(f, bb):
            yield feature, va

    def get_instructions(self, f, bb):
        for insn in bb.instructions:
            yield add_va_int_cast(insn)

    def extract_insn_features(self, f, bb, insn):
        for feature, va in capa.features.extractors.viv.insn.extract_features(f, bb, insn):
            yield feature, va

    def is_library_function(self, va):
        return self.vw.funcmeta.get(va, {}).get("capa/library", False)

    def get_function_name(self, va):
        return viv_utils.get_function_name(self.vw, va)


def add_function_flirt_match(vw, va, name):
    fmeta = vw.funcmeta.get(va, {})
    fmeta["capa/library"] = True
    viv_utils.set_function_name(vw, va, name)


def get_match_name(match):
    for (name, type_, offset) in match.names:
        if offset == 0:
            return name
    raise ValueError("flirt: match: no best name: %s", match.names)


def match_function_flirt_signatures(matcher, vw, va):
    if va == 0x403970:
        add_function_flirt_match(vw, va, "__alloca_probe")
        return

    if vw.funcmeta.get(va, {}).get("capa/library", False):
        # already matched here.
        # this might be the case if recursive matching visited this address.
        return viv_utils.get_function_name(vw, va)

    # TODO: fix reads at the end of a section.
    # TODO: pick the right size to read here.
    buf = vw.readMemory(va, 0x200)
    matches = matcher.match(buf)

    matches = []
    for match in matcher.match(buf):
        references = list(filter(lambda n: n[1] == "reference", match.names))

        if not references:
            matches.append(match)

        else:
            # flirt uses reference names to assert that
            # the function contains a reference to another function with a given name.
            #
            # we need to loop through these references,
            # potentially recursively FLIRT match,
            # and check the name matches (or doesn't).

            # at the end of the following loop,
            # if this flag is still true,
            # then all the references have been validated.
            does_match_references = True

            #logger.debug("flirt: references needed for name %s for function at 0x%x: %s", get_match_name(match), va, references)

            # when a reference is used to differentiate rule matches,
            # then we can expect multiple rules to query the name of the same address.
            # so, this caches the names looked up in the below loop.
            # type: Map[int, str]
            local_names = {}
            for (ref_name, _, ref_offset) in references:
                ref_va = va + ref_offset

                # the reference offset may be inside an instruction,
                # so we use getLocation to select the containing instruction address.
                loc_va = vw.getLocation(ref_va)[vivisect.const.L_VA]

                # an instruction may have multiple xrefs from
                # so we loop through all code references,
                # searching for that name.
                #
                # TODO: if we assume there is a single code reference, this is a lot easier.
                # can we do that with FLIRT?
                #
                # if the name is found, then this flag will be set.
                does_match_the_reference = False
                for xref in vw.getXrefsFrom(loc_va):
                    if xref[vivisect.const.XR_RTYPE] != vivisect.const.REF_CODE:
                        continue

                    target = xref[vivisect.const.XR_TO]
                    if target in local_names:
                        # fast path: a prior loop already looked up this address.
                        found_name = local_names[target]
                    else:
                        # this is a bit slower, since we have to read buf, do match, etc.
                        # note that we don't ever save "this is not a library function",
                        # so there's not an easy way to short circuit at the start of this function.
                        found_name = match_function_flirt_signatures(matcher, vw, target)
                        local_names[target] = found_name

                    #logger.debug("flirt: reference: 0x%x: 0x%x: wanted: %s found: %s", loc_va, target, ref_name, found_name)

                    if found_name == ref_name:
                        does_match_the_reference = True
                        break

                if not does_match_the_reference:
                    does_match_references = False
                    break

            if does_match_references:
                # only if all references pass do we count it.
                matches.append(match)

    if matches:
        names = list(set(map(get_match_name, matches)))
        if len(names) == 1:
            name = names[0]
            add_function_flirt_match(vw, va, name)
            logger.debug("flirt: found library function: 0x%x: %s", va, name)
            return name
        else:
            logger.warning("flirt: conflicting names: 0x%x: %s", va, names)
            return None


def match_vw_flirt_signatures(matcher, vw):
    for va in sorted(vw.getFunctions()):
        match_function_flirt_signatures(matcher, vw, va)