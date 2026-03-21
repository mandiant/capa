# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
from enum import Enum
from dataclasses import dataclass

import capa.features.insn
from capa.features.extractors.base_extractor import FunctionHandle, StaticFeatureExtractor

logger = logging.getLogger(__name__)


REASON_DEFAULT = "analyze"
REASON_LIBRARY = "library/flirt function"
REASON_CRT_NAME = "crt/runtime function name pattern"
REASON_TINY_NO_API = "tiny function without API evidence"
REASON_THUNK = "thunk-like function"
REASON_RUNTIME_SECTION = "runtime section pattern"
REASON_LARGE_COMPLEXITY = "large function complexity"

CRT_NAME_PREFIXES = (
    "__security_",
    "__scrt_",
    "__acrt_",
    "__vcrt_",
    "__chkstk",
    "_chkstk",
    "__gshandler",
    "__cxx",
    "_cxx",
    "__initterm",
    "_initterm",
    "__crt",
    "__imp_",
    "_imp__",
)

RUNTIME_SECTION_NAMES = {
    ".init",
    ".fini",
    ".init_array",
    ".fini_array",
    ".ctors",
    ".dtors",
    ".plt",
    ".plt.got",
    ".plt.sec",
}


class TriageDecision(str, Enum):
    ANALYZE = "analyze"
    SKIP = "skip"
    DEPRIORITIZE = "deprioritize"


@dataclass(frozen=True)
class TriageResult:
    decision: TriageDecision
    reason: str = REASON_DEFAULT


def _looks_like_runtime_name(name: str) -> bool:
    lname = name.lower()
    return lname.startswith(CRT_NAME_PREFIXES) or lname.startswith("j_") or lname.startswith("nullsub_")


def _get_function_name(extractor: StaticFeatureExtractor, fh: FunctionHandle) -> str:
    try:
        return extractor.get_function_name(fh.address)
    except KeyError:
        return ""


def _get_section_name(fh: FunctionHandle) -> str:
    inner = fh.inner
    if inner is None:
        return ""
    section = getattr(inner, "section_name", "")
    if isinstance(section, str):
        return section
    vw = getattr(inner, "vw", None)
    va = getattr(inner, "va", None)
    if vw is None or va is None:
        return ""
    for seg_va, seg_size, seg_name, _ in vw.getSegments():
        if seg_va <= va < seg_va + seg_size:
            return seg_name
    return ""


def _collect_size_and_signals(extractor: StaticFeatureExtractor, fh: FunctionHandle) -> tuple[int, int, bool, bool]:
    bb_count = 0
    insn_count = 0
    has_api = False
    is_thunk_candidate = False

    for bbh in extractor.get_basic_blocks(fh):
        bb_count += 1
        instructions = list(extractor.get_instructions(fh, bbh))
        insn_count += len(instructions)

        if bb_count == 1 and 0 < len(instructions) <= 3:
            last = instructions[-1].inner
            mnem = getattr(last, "mnem", "")
            if mnem in ("jmp", "ret"):
                is_thunk_candidate = True

        for ih in instructions:
            mnem = getattr(ih.inner, "mnem", "")
            if isinstance(mnem, str) and mnem.lower().startswith("call"):
                has_api = True
                break
        if has_api and bb_count > 1:
            # for triage we only need API presence, not full counting.
            continue

    is_thunk = bb_count == 1 and is_thunk_candidate
    return bb_count, insn_count, has_api, is_thunk


def _has_api_feature_evidence(extractor: StaticFeatureExtractor, fh: FunctionHandle) -> bool:
    """
    confirm API evidence using extracted instruction features.
    this avoids false negatives from mnemonic-only call heuristics.
    """
    for bbh in extractor.get_basic_blocks(fh):
        for ih in extractor.get_instructions(fh, bbh):
            for feature, _ in extractor.extract_insn_features(fh, bbh, ih):
                if isinstance(feature, capa.features.insn.API):
                    return True
    return False


def classify_function(extractor: StaticFeatureExtractor, fh: FunctionHandle) -> TriageResult:
    if fh.inner is None:
        result = TriageResult(TriageDecision.ANALYZE, REASON_DEFAULT)
        logger.debug(
            "function triage: address=%s decision=%s reason=%s (no function context)",
            fh.address,
            result.decision.value,
            result.reason,
        )
        return result

    name = _get_function_name(extractor, fh)
    section_name = _get_section_name(fh).lower()
    bb_count, insn_count, has_api, is_thunk = _collect_size_and_signals(extractor, fh)

    if not has_api and (is_thunk or section_name in RUNTIME_SECTION_NAMES or (name and bb_count <= 1 and insn_count <= 4)):
        has_api = _has_api_feature_evidence(extractor, fh)

    if name and _looks_like_runtime_name(name):
        result = TriageResult(TriageDecision.SKIP, REASON_CRT_NAME)
    elif is_thunk and not has_api:
        result = TriageResult(TriageDecision.SKIP, REASON_THUNK)
    elif section_name in RUNTIME_SECTION_NAMES and not has_api and insn_count <= 8:
        result = TriageResult(TriageDecision.SKIP, REASON_RUNTIME_SECTION)
    elif name and not has_api and bb_count <= 1 and insn_count <= 4:
        # conservative skip: only very small/no-API helpers.
        result = TriageResult(TriageDecision.SKIP, REASON_TINY_NO_API)
    elif bb_count >= 512 or insn_count >= 4096:
        result = TriageResult(TriageDecision.DEPRIORITIZE, REASON_LARGE_COMPLEXITY)
    else:
        result = TriageResult(TriageDecision.ANALYZE, REASON_DEFAULT)

    logger.debug(
        "function triage: address=%s decision=%s reason=%s bb=%d insn=%d has_api=%s thunk=%s section=%s name=%s",
        fh.address,
        result.decision.value,
        result.reason,
        bb_count,
        insn_count,
        has_api,
        is_thunk,
        section_name,
        name,
    )
    return result


def classify_library_function(fh: FunctionHandle) -> TriageResult:
    result = TriageResult(TriageDecision.SKIP, REASON_LIBRARY)
    logger.debug(
        "function triage: address=%s decision=%s reason=%s",
        fh.address,
        result.decision.value,
        result.reason,
    )
    return result
