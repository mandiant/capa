# Copyright 2022 Google LLC
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

# tests/data/dynamic/cape/v2.2/0000a65749f5902c4d82ffa701198038f0b4870b00a27cfca109f8f933476d82.json.gz
#
#    proc: 0000A65749F5902C4D82.exe (ppid=2456, pid=3052)
#      ...
#      thread: 3064
#        call 8: GetSystemTimeAsFileTime()
#        call 9: GetSystemInfo()
#        call 10: LdrGetDllHandle(1974337536, kernel32.dll)
#        call 11: LdrGetProcedureAddress(2010595649, 0, AddVectoredExceptionHandler, 1974337536, kernel32.dll)
#        call 12: LdrGetDllHandle(1974337536, kernel32.dll)
#        call 13: LdrGetProcedureAddress(2010595072, 0, RemoveVectoredExceptionHandler, 1974337536, kernel32.dll)
#        call 14: RtlAddVectoredExceptionHandler(1921490089, 0)
#        call 15: GetSystemTime()
#        call 16: NtAllocateVirtualMemory(no, 4, 786432, 4784128, 4294967295)
#        call 17: NtAllocateVirtualMemory(no, 4, 12288, 4784128, 4294967295)
#        call 18: GetSystemInfo()
#        ...
#      ...

import textwrap
from typing import Iterator
from functools import lru_cache

import pytest
import fixtures

import capa.main
import capa.rules
import capa.capabilities.dynamic
from capa.features.extractors.base_extractor import ThreadFilter, DynamicFeatureExtractor


def filter_threads(extractor: DynamicFeatureExtractor, ppid: int, pid: int, tid: int) -> DynamicFeatureExtractor:
    for ph in extractor.get_processes():
        if (ph.address.ppid, ph.address.pid) != (ppid, pid):
            continue

        for th in extractor.get_threads(ph):
            if th.address.tid != tid:
                continue

            return ThreadFilter(
                extractor,
                {
                    th.address,
                },
            )

    raise ValueError("failed to find target thread")


@lru_cache(maxsize=1)
def get_0000a657_thread3064():
    extractor = fixtures.get_cape_extractor(fixtures.get_data_path_by_name("0000a657"))
    extractor = filter_threads(extractor, 2456, 3052, 3064)
    return extractor


def get_call_ids(matches) -> Iterator[int]:
    for address, _ in matches:
        yield address.id


# sanity check: match the first call
#
#    proc: 0000A65749F5902C4D82.exe (ppid=2456, pid=3052)
#      thread: 3064
#        call 8: GetSystemTimeAsFileTime()
def test_dynamic_call_scope():
    extractor = get_0000a657_thread3064()

    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: unsupported
                    dynamic: call
            features:
                - api: GetSystemTimeAsFileTime
        """
    )

    r = capa.rules.Rule.from_yaml(rule)
    ruleset = capa.rules.RuleSet([r])

    capabilities = capa.capabilities.dynamic.find_dynamic_capabilities(ruleset, extractor, disable_progress=True)
    assert r.name in capabilities.matches
    assert 8 in get_call_ids(capabilities.matches[r.name])


# match the first span.
#
#    proc: 0000A65749F5902C4D82.exe (ppid=2456, pid=3052)
#      thread: 3064
#        call 8: GetSystemTimeAsFileTime()
#        call 9: GetSystemInfo()
#        call 10: LdrGetDllHandle(1974337536, kernel32.dll)
#        call 11: LdrGetProcedureAddress(2010595649, 0, AddVectoredExceptionHandler, 1974337536, kernel32.dll)
#        call 12: LdrGetDllHandle(1974337536, kernel32.dll)
def test_dynamic_span_scope():
    extractor = get_0000a657_thread3064()

    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: unsupported
                    dynamic: span of calls
            features:
                - and:
                    - api: GetSystemTimeAsFileTime
                    - api: GetSystemInfo
                    - api: LdrGetDllHandle
                    - api: LdrGetProcedureAddress
                    - count(api(LdrGetDllHandle)): 2
        """
    )

    r = capa.rules.Rule.from_yaml(rule)
    ruleset = capa.rules.RuleSet([r])

    capabilities = capa.capabilities.dynamic.find_dynamic_capabilities(ruleset, extractor, disable_progress=True)
    assert r.name in capabilities.matches
    assert 12 in get_call_ids(capabilities.matches[r.name])


# show that when the span is only 5 calls long (for example), it doesn't match beyond that 5-tuple.
#
#    proc: 0000A65749F5902C4D82.exe (ppid=2456, pid=3052)
#      thread: 3064
#        call 8: GetSystemTimeAsFileTime()
#        call 9: GetSystemInfo()
#        call 10: LdrGetDllHandle(1974337536, kernel32.dll)
#        call 11: LdrGetProcedureAddress(2010595649, 0, AddVectoredExceptionHandler, 1974337536, kernel32.dll)
#        call 12: LdrGetDllHandle(1974337536, kernel32.dll)
#        call 13: LdrGetProcedureAddress(2010595072, 0, RemoveVectoredExceptionHandler, 1974337536, kernel32.dll)
#        call 14: RtlAddVectoredExceptionHandler(1921490089, 0)
#        call 15: GetSystemTime()
#        call 16: NtAllocateVirtualMemory(no, 4, 786432, 4784128, 4294967295)
def test_dynamic_span_scope_length():
    extractor = get_0000a657_thread3064()

    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: unsupported
                    dynamic: span of calls
            features:
                - and:
                    - api: GetSystemTimeAsFileTime
                    - api: RtlAddVectoredExceptionHandler
        """
    )

    r = capa.rules.Rule.from_yaml(rule)
    ruleset = capa.rules.RuleSet([r])

    # patch SPAN_SIZE since we may use a much larger value in the real world.
    from pytest import MonkeyPatch

    with MonkeyPatch.context() as m:
        m.setattr(capa.capabilities.dynamic, "SPAN_SIZE", 5)
        capabilities = capa.capabilities.dynamic.find_dynamic_capabilities(ruleset, extractor, disable_progress=True)

    assert r.name not in capabilities.matches


# show that you can use a call subscope in span-of-calls rules.
#
#    proc: 0000A65749F5902C4D82.exe (ppid=2456, pid=3052)
#      thread: 3064
#        ...
#        call 11: LdrGetProcedureAddress(2010595649, 0, AddVectoredExceptionHandler, 1974337536, kernel32.dll)
#        ...
def test_dynamic_span_call_subscope():
    extractor = get_0000a657_thread3064()

    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: unsupported
                    dynamic: span of calls
            features:
                - and:
                    - call:
                        - and:
                            - api: LdrGetProcedureAddress
                            - string: AddVectoredExceptionHandler
        """
    )

    r = capa.rules.Rule.from_yaml(rule)
    ruleset = capa.rules.RuleSet([r])

    capabilities = capa.capabilities.dynamic.find_dynamic_capabilities(ruleset, extractor, disable_progress=True)
    assert r.name in capabilities.matches
    assert 11 in get_call_ids(capabilities.matches[r.name])


# show that you can use a span subscope in span rules.
#
#    proc: 0000A65749F5902C4D82.exe (ppid=2456, pid=3052)
#      thread: 3064
#        ...
#        call 10: LdrGetDllHandle(1974337536, kernel32.dll)
#        call 11: LdrGetProcedureAddress(2010595649, 0, AddVectoredExceptionHandler, 1974337536, kernel32.dll)
#        call 12: LdrGetDllHandle(1974337536, kernel32.dll)
#        call 13: LdrGetProcedureAddress(2010595072, 0, RemoveVectoredExceptionHandler, 1974337536, kernel32.dll)
#        ...
def test_dynamic_span_scope_span_subscope():
    extractor = get_0000a657_thread3064()

    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: unsupported
                    dynamic: span of calls
            features:
                - and:
                    - span of calls:
                        - description: resolve add VEH  # should match at 11
                        - and:
                            - api: LdrGetDllHandle
                            - api: LdrGetProcedureAddress
                            - string: AddVectoredExceptionHandler
                    - span of calls:
                        - description: resolve remove VEH  # should match at 13
                        - and:
                            - api: LdrGetDllHandle
                            - api: LdrGetProcedureAddress
                            - string: RemoveVectoredExceptionHandler
        """
    )

    r = capa.rules.Rule.from_yaml(rule)
    ruleset = capa.rules.RuleSet([r])

    capabilities = capa.capabilities.dynamic.find_dynamic_capabilities(ruleset, extractor, disable_progress=True)
    assert r.name in capabilities.matches
    assert 13 in get_call_ids(capabilities.matches[r.name])


# show that you can't use thread subscope in span rules.
def test_dynamic_span_scope_thread_subscope():
    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: unsupported
                    dynamic: span of calls
            features:
                - and:
                    - thread:
                        - string: "foo"
        """
    )

    with pytest.raises(capa.rules.InvalidRule):
        capa.rules.Rule.from_yaml(rule)


# show how you might use a span-of-calls rule: to match a small window for a collection of features.
#
#    proc: 0000A65749F5902C4D82.exe (ppid=2456, pid=3052)
#      thread: 3064
#        call 10: LdrGetDllHandle(1974337536, kernel32.dll)
#        call 11: LdrGetProcedureAddress(2010595649, 0, AddVectoredExceptionHandler, 1974337536, kernel32.dll)
#        call 12: ...
#        call 13: ...
#        call 14: RtlAddVectoredExceptionHandler(1921490089, 0)
def test_dynamic_span_example():
    extractor = get_0000a657_thread3064()

    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: unsupported
                    dynamic: span of calls
            features:
                - and:
                    - call:
                        - and:
                            - api: LdrGetDllHandle
                            - string: "kernel32.dll"
                    - call:
                        - and:
                            - api: LdrGetProcedureAddress
                            - string: "AddVectoredExceptionHandler"
                    - api: RtlAddVectoredExceptionHandler
        """
    )

    r = capa.rules.Rule.from_yaml(rule)
    ruleset = capa.rules.RuleSet([r])

    capabilities = capa.capabilities.dynamic.find_dynamic_capabilities(ruleset, extractor, disable_progress=True)
    assert r.name in capabilities.matches
    assert 14 in get_call_ids(capabilities.matches[r.name])


# show how spans that overlap a single event are handled.
#
#    proc: 0000A65749F5902C4D82.exe (ppid=2456, pid=3052)
#      thread: 3064
#        ...
#        call 10: ...
#        call 11: LdrGetProcedureAddress(2010595649, 0, AddVectoredExceptionHandler, 1974337536, kernel32.dll)
#        call 12: ...
#        call 13: ...
#        call 14: ...
#        call 15: ...
#        ...
def test_dynamic_span_multiple_spans_overlapping_single_event():
    extractor = get_0000a657_thread3064()

    rule = textwrap.dedent(
        """
        rule:
            meta:
                name: test rule
                scopes:
                    static: unsupported
                    dynamic: span of calls
            features:
                - and:
                    - call:
                        - and:
                            - api: LdrGetProcedureAddress
                            - string: "AddVectoredExceptionHandler"
        """
    )

    r = capa.rules.Rule.from_yaml(rule)
    ruleset = capa.rules.RuleSet([r])

    capabilities = capa.capabilities.dynamic.find_dynamic_capabilities(ruleset, extractor, disable_progress=True)
    assert r.name in capabilities.matches
    # we only match the first overlapping span
    assert [11] == list(get_call_ids(capabilities.matches[r.name]))


# show that you can use match statements in span-of-calls rules.
#
#    proc: 0000A65749F5902C4D82.exe (ppid=2456, pid=3052)
#      thread: 3064
#        ...
#        call 10: LdrGetDllHandle(1974337536, kernel32.dll)
#        call 11: LdrGetProcedureAddress(2010595649, 0, AddVectoredExceptionHandler, 1974337536, kernel32.dll)
#        call 12: LdrGetDllHandle(1974337536, kernel32.dll)
#        call 13: LdrGetProcedureAddress(2010595072, 0, RemoveVectoredExceptionHandler, 1974337536, kernel32.dll)
#        ...
def test_dynamic_span_scope_match_statements():
    extractor = get_0000a657_thread3064()

    ruleset = capa.rules.RuleSet(
        [
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                rule:
                    meta:
                        name: resolve add VEH
                        namespace: linking/runtime-linking/veh
                        scopes:
                            static: unsupported
                            dynamic: span of calls
                    features:
                        - and:
                            - api: LdrGetDllHandle
                            - api: LdrGetProcedureAddress
                            - string: AddVectoredExceptionHandler
                """
                )
            ),
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                rule:
                    meta:
                        name: resolve remove VEH
                        namespace: linking/runtime-linking/veh
                        scopes:
                            static: unsupported
                            dynamic: span of calls
                    features:
                        - and:
                            - api: LdrGetDllHandle
                            - api: LdrGetProcedureAddress
                            - string: RemoveVectoredExceptionHandler
                """
                )
            ),
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                rule:
                    meta:
                        name: resolve add and remove VEH
                        scopes:
                            static: unsupported
                            dynamic: span of calls
                    features:
                        - and:
                            - match: resolve add VEH
                            - match: resolve remove VEH
                """
                )
            ),
            capa.rules.Rule.from_yaml(
                textwrap.dedent(
                    """
                rule:
                    meta:
                        name: has VEH runtime linking
                        scopes:
                            static: unsupported
                            dynamic: span of calls
                    features:
                        - and:
                            - match: linking/runtime-linking/veh
                """
                )
            ),
        ]
    )

    capabilities = capa.capabilities.dynamic.find_dynamic_capabilities(ruleset, extractor, disable_progress=True)

    # basic functionality, already known to work
    assert "resolve add VEH" in capabilities.matches
    assert "resolve remove VEH" in capabilities.matches

    # requires `match: <rule name>` to be working
    assert "resolve add and remove VEH" in capabilities.matches

    # requires `match: <namespace>` to be working
    assert "has VEH runtime linking" in capabilities.matches
