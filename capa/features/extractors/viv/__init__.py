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
        return is_library_function(self.vw, va)

    def get_function_name(self, va):
        return viv_utils.get_function_name(self.vw, va)


# vivisect funcmeta key for a bool to indicate if a function is recognized from a library.
# not expecting anyone to use this, aka private symbol.
_LIBRARY_META_KEY = "is-library"


def is_library_function(vw, va):
    """
    is the function at the given address a library function?
    this may be determined by a signature matching backend.
    if there's no function at the given address, `False` is returned.

    note: if its a library function, it should also have a name set.

    args:
      vw (vivisect.Workspace):
      va (int): the virtual address of a function.

    returns:
      bool: if the function is recognized as from a library.
    """
    return vw.funcmeta.get(va, {}).get(_LIBRARY_META_KEY, False)


def make_library_function(vw, va):
    """
    mark the function with the given address a library function.
    the associated accessor is `is_library_function`.

    if there's no function at the given address, this routine has no effect.

    note: if its a library function, it should also have a name set.
    its up to the caller to do this part.

    args:
      vw (vivisect.Workspace):
      va (int): the virtual address of a function.
    """
    fmeta = vw.funcmeta.get(va, {})
    fmeta[_LIBRARY_META_KEY] = True


def add_function_flirt_match(vw, va, name):
    """
    mark the function at the given address as a library function with the given name.
    the name overrides any existing function name.

    args:
      vw (vivisect.Workspace):
      va (int): the virtual address of a function.
      name (str): the name to assign to the function.
    """
    make_library_function(vw, va)
    viv_utils.set_function_name(vw, va, name)


def get_match_name(match):
    """
    fetch the best name for a `flirt.FlirtSignature` instance.
    these instances returned by `flirt.FlirtMatcher.match()`
    may have multiple names, such as public and local names for different parts
    of a function. the best name is that at offset zero (the function name).

    probably every signature has a best name, though I'm not 100% sure.

    args:
      match (flirt.FlirtSignature): the signature to get a name from.

    returns:
      str: the best name of the function matched by the given signature.
    """
    for (name, type_, offset) in match.names:
        if offset == 0:
            return name
    raise ValueError("flirt: match: no best name: %s", match.names)


def match_function_flirt_signatures(matcher, vw, va):
    """
    match the given FLIRT signatures against the function at the given address.
    upon success, update the workspace with match metadata, setting the
    function as a library function and assigning its name.

    if multiple different signatures match the function, don't do anything.

    args:
      match (flirt.FlirtMatcher): the compiled FLIRT signature matcher.
      vw (vivisect.workspace): the analyzed program's workspace.
      va (int): the virtual address of a function to match.

    returns:
      Optional[str]: the recognized function name, or `None`.
    """
    function_meta = vw.funcmeta.get(va)
    if not function_meta:
        # not a function, we're not going to consider this.
        return None

    if is_library_function(vw, va):
        # already matched here.
        # this might be the case if recursive matching visited this address.
        return viv_utils.get_function_name(vw, va)

    # 0x200 comes from:
    #  0x20 bytes for default byte signature size in flirt
    #  0x100 bytes for max checksum data size
    #  some wiggle room for tail bytes
    size = function_meta.get("Size", 0x200)
    # TODO: fix reads at the end of a section.
    buf = vw.readMemory(va, size)

    matches = []
    for match in matcher.match(buf):
        # collect all the name tuples (name, type, offset) with type==reference.
        # ignores other name types like "public" and "local".
        references = list(filter(lambda n: n[1] == "reference", match.names))

        if not references:
            # there are no references that we need to check, so this is a complete match.
            # common case.
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
                    # FLIRT signatures only match code,
                    # so we're only going to resolve references that point to code.
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
        # we may have multiple signatures that match the same function, like `strcpy`.
        # these could be copies from multiple libraries.
        # so we don't mind if there are multiple matches, as long as names are the same.
        #
        # but if there are multiple candidate names, that's a problem.
        # our signatures are not precise enough.
        # we could maybe mark the function as "is a library function", but not assign name.
        # though, if we have signature FPs among library functions, it could easily FP with user code too.
        # so safest thing to do is not make any claim about the function.
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
    """
    enumerate all functions in the workspace and match the given FLIRT signatures.
    upon each success, update the workspace with match metadata, setting the
    function as a library function and assigning its name.

    if multiple different signatures match a function, don't do anything.

    args:
      match (flirt.FlirtMatcher): the compiled FLIRT signature matcher.
      vw (vivisect.workspace): the analyzed program's workspace.
    """
    for va in sorted(vw.getFunctions()):
        match_function_flirt_signatures(matcher, vw, va)