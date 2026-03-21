#!/usr/bin/env python3
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

"""
Demo helper for:
  - function triage counts (skip/deprioritize/analyze)
  - connected-block rule syntax
"""

import argparse
import textwrap
from pathlib import Path
from collections import Counter
from typing import Counter as CounterType

import capa.loader
import capa.rules
from capa.rules import Scope
from capa.capabilities.triage import TriageDecision, classify_function
from capa.features.extractors.viv.extractor import VivisectFeatureExtractor
from capa.features.common import OS_AUTO, FORMAT_AUTO


CONNECTED_BLOCKS_RULE = textwrap.dedent(
    """
    rule:
      meta:
        name: demo connected blocks
        scopes:
          static: function
          dynamic: process
      features:
        - connected blocks:
            - and:
                - api: kernel32.CreateFileA
                - api: kernel32.WriteFile
    """
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="sample path")
    args = parser.parse_args()

    vw = capa.loader.get_workspace(args.input, FORMAT_AUTO, sigpaths=[])
    extractor = VivisectFeatureExtractor(vw, args.input, OS_AUTO)

    triage_counts: CounterType[str] = Counter()
    for fh in extractor.get_functions():
        if extractor.is_library_function(fh.address):
            triage_counts[TriageDecision.SKIP.value] += 1
            continue
        triage = classify_function(extractor, fh)
        triage_counts[triage.decision.value] += 1

    print("triage counts:")
    print(f"  analyze      : {triage_counts[TriageDecision.ANALYZE.value]}")
    print(f"  deprioritize : {triage_counts[TriageDecision.DEPRIORITIZE.value]}")
    print(f"  skip         : {triage_counts[TriageDecision.SKIP.value]}")
    print()
    print("connected blocks rule syntax:")
    print(CONNECTED_BLOCKS_RULE.strip())

    r = capa.rules.Rule.from_yaml(CONNECTED_BLOCKS_RULE)
    print()
    print("parsed rule scopes:", r.scopes)
    print("connected blocks scope literal:", Scope.CONNECTED_BLOCKS.value)


if __name__ == "__main__":
    main()
