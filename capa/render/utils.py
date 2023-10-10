# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import io
import gzip
import json
from typing import Dict, Union, Iterator
from pathlib import Path

import termcolor

import capa.render.result_document as rd


def bold(s: str) -> str:
    """draw attention to the given string"""
    return termcolor.colored(s, "cyan")


def bold2(s: str) -> str:
    """draw attention to the given string, within a `bold` section"""
    return termcolor.colored(s, "green")


def warn(s: str) -> str:
    return termcolor.colored(s, "yellow")


def format_parts_id(data: Union[rd.AttackSpec, rd.MBCSpec]):
    """
    format canonical representation of ATT&CK/MBC parts and ID
    """
    return f"{'::'.join(data.parts)} [{data.id}]"


def capability_rules(doc: rd.ResultDocument) -> Iterator[rd.RuleMatches]:
    """enumerate the rules in (namespace, name) order that are 'capability' rules (not lib/subscope/disposition/etc)."""
    for _, _, rule in sorted((rule.meta.namespace or "", rule.meta.name, rule) for rule in doc.rules.values()):
        if rule.meta.lib:
            continue
        if rule.meta.is_subscope_rule:
            continue
        if rule.meta.maec.analysis_conclusion:
            continue
        if rule.meta.maec.analysis_conclusion_ov:
            continue
        if rule.meta.maec.malware_family:
            continue
        if rule.meta.maec.malware_category:
            continue
        if rule.meta.maec.malware_category_ov:
            continue

        yield rule


def load_rules_prevalence() -> Dict[str, str]:
    CD = Path(__file__).resolve().parent.parent.parent
    file = CD / "assets/rules_prevalence.json.gz"
    if not file.exists():
        raise FileNotFoundError(f"File '{file}' not found.")
    try:
        with gzip.open(file, "rb") as gzfile:
            return json.loads(gzfile.read().decode("utf-8"))
    except Exception as e:
        raise RuntimeError(f"An error occurred while loading '{file}': {e}")


class StringIO(io.StringIO):
    def writeln(self, s):
        self.write(s)
        self.write("\n")
