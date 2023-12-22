# -*- coding: utf-8 -*-
# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import re
import logging
import itertools
import collections
from typing import Any, List, Tuple, Iterator, Optional

import capa.features.extractors.cape.file as cape_file
from capa.rules import Scope, RuleSet
from capa.engine import FeatureSet, MatchResults
from capa.features.address import NO_ADDRESS
from capa.features.extractors.cape.models import Call, CapeReport
from capa.features.extractors.base_extractor import (
    CallHandle,
    ThreadHandle,
    ProcessHandle,
    FeatureExtractor,
    StaticFeatureExtractor,
    DynamicFeatureExtractor,
)


logger = logging.getLogger(__name__)


def find_file_capabilities(ruleset: RuleSet, extractor: FeatureExtractor, function_features: FeatureSet):
    file_features: FeatureSet = collections.defaultdict(set)

    for feature, va in itertools.chain(extractor.extract_file_features(), extractor.extract_global_features()):
        # not all file features may have virtual addresses.
        # if not, then at least ensure the feature shows up in the index.
        # the set of addresses will still be empty.
        if va:
            file_features[feature].add(va)
        else:
            if feature not in file_features:
                file_features[feature] = set()

    logger.debug("analyzed file and extracted %d features", len(file_features))

    file_features.update(function_features)

    _, matches = ruleset.match(Scope.FILE, file_features, NO_ADDRESS)
    return matches, len(file_features)


def has_file_limitation(rules: RuleSet, capabilities: MatchResults, is_standalone=True) -> bool:
    file_limitation_rules = list(filter(lambda r: r.is_file_limitation_rule(), rules.rules.values()))

    for file_limitation_rule in file_limitation_rules:
        if file_limitation_rule.name not in capabilities:
            continue

        logger.warning("-" * 80)
        for line in file_limitation_rule.meta.get("description", "").split("\n"):
            logger.warning(" %s", line)
        logger.warning(" Identified via rule: %s", file_limitation_rule.name)
        if is_standalone:
            logger.warning(" ")
            logger.warning(" Use -v or -vv if you really want to see the capabilities identified by capa.")
        logger.warning("-" * 80)

        # bail on first file limitation
        return True

    return False


def find_capabilities(
    ruleset: RuleSet, extractor: FeatureExtractor, disable_progress=None, **kwargs
) -> Tuple[MatchResults, Any]:
    from capa.capabilities.static import find_static_capabilities
    from capa.capabilities.dynamic import find_dynamic_capabilities

    if isinstance(extractor, StaticFeatureExtractor):
        # for the time being, extractors are either static or dynamic.
        # Remove this assertion once that has changed
        assert not isinstance(extractor, DynamicFeatureExtractor)
        return find_static_capabilities(ruleset, extractor, disable_progress=disable_progress, **kwargs)
    if isinstance(extractor, DynamicFeatureExtractor):
        return find_dynamic_capabilities(ruleset, extractor, disable_progress=disable_progress, **kwargs)

    raise ValueError(f"unexpected extractor type: {extractor.__class__.__name__}")


def extract_ip_addresses(strings: List[str]) -> Iterator[str]:
    """ yield (IPv4 and IPv6) IP address regex matches from list of strings """
    # Both the IPv4 and IPv6 regex patterns are discussed here:
    # (https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses)
    ipv4_pattern = r"""
    ((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|
    (2[0-4]|1{0,1}[0-9]){0,1}[0-9])
    """

    ipv6_pattern = r"""
    (
    ([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|
    ([0-9a-fA-F]{1,4}:){1,7}:|
    ([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|
    ([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|
    ([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|
    ([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|
    ([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|
    [0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|
    :((:[0-9a-fA-F]{1,4}){1,7}|:)|
    fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|
    ::(ffff(:0{1,4}){0,1}:){0,1}
    ((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
    (25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|
    ([0-9a-fA-F]{1,4}:){1,4}:
    ((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
    (25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])
    )
    """

    for string in strings:
        if re.search(ipv4_pattern, string):
            yield string

        if re.search(ipv6_pattern, string):
            yield string


def extract_domain_names(strings: List[str]) -> Iterator[str]:
    """ yield web domain regex matches from list of strings """
    # See this Stackoverflow post that discusses the parts of this regex (http://stackoverflow.com/a/7933253/433790)
    domain_pattern = r"^(?!.{256})(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{1,63}|xn--[a-z0-9]{1,59})$"
    for string in strings:
        if re.search(domain_pattern, string):
            yield string


def extract_file_names(
    process_handles: Iterator[ProcessHandle],
    thread_handles: Iterator[ThreadHandle],
    call_handles: Iterator[CallHandle],
    report: Optional[CapeReport],
):
    """
    extracts Windows API file maniuplation functions that processes import
    yields: 1) API name, and 2) file that it iteracts with

    'default.render_file_names' checks whether 'report' is None before calling 'extract_file_name'

    yield:
      ch.api (str): the API that interacts with the filename
      call.arguments[0].name (str): a filename, which is a parameter of some WinAPI file interaction functions
    """
    # Extract many Windows API functions that take a filename as an argument
    winapi_file_functions = []
    for feature, _ in cape_file.extract_import_names(report):
        assert type(feature.value) == "str"  # feature.value type annotation is: 'value: Union[str, int, float, bytes]'
        if feature.value.str.contains("File"):  # a lot of Windows API file interaction function names contain "File"
            winapi_file_functions.append(feature[0])

    for ph in process_handles:
        for th in thread_handles:
            for ch in call_handles:
                call: Call = ch.inner
                if call.api in winapi_file_functions:
                    # winapi_file_functions functions take file name as their first variable
                    # since calling conventions commonly store function parameters on the stack in reverse order,
                    # we yield the file name with call.arguments[-1].name
                    # although should we use call.arguments[0].name to get file names for different calling conventions?
                    yield call.api, call.arguments[-1].name
