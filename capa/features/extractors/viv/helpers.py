# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
from typing import Optional

import envi
from vivisect import VivWorkspace
from vivisect.const import XR_TO, REF_CODE


def get_coderef_from(vw: VivWorkspace, va: int) -> Optional[int]:
    """
    return first code `tova` whose origin is the specified va
    return None if no code reference is found
    """
    xrefs = vw.getXrefsFrom(va, REF_CODE)
    if len(xrefs) > 0:
        return xrefs[0][XR_TO]
    else:
        return None


def read_memory(vw, va: int, size: int) -> bytes:
    # as documented in #176, vivisect will not readMemory() when the section is not marked readable.
    #
    # but here, we don't care about permissions.
    # so, copy the viv implementation of readMemory and remove the permissions check.
    #
    # this is derived from:
    #   https://github.com/vivisect/vivisect/blob/5eb4d237bddd4069449a6bc094d332ceed6f9a96/envi/memory.py#L453-L462
    for mva, mmaxva, mmap, mbytes in vw._map_defs:
        if va >= mva and va < mmaxva:
            mva, msize, mperms, mfname = mmap
            offset = va - mva
            return mbytes[offset : offset + size]
    raise envi.exc.SegmentationViolation(va)
