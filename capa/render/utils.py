# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import io

import termcolor


def bold(s: str) -> str:
    """draw attention to the given string"""
    return termcolor.colored(s, "blue")


def bold2(s: str) -> str:
    """draw attention to the given string, within a `bold` section"""
    return termcolor.colored(s, "green")


def hex(n: int) -> str:
    """render the given number using upper case hex, like: 0x123ABC"""
    if n < 0:
        return "-0x%X" % (-n)
    else:
        return "0x%X" % n


def parse_parts_id(s: str):
    id = ""
    parts = s.split("::")
    if len(parts) > 0:
        last = parts.pop()
        last, _, id = last.rpartition(" ")
        id = id.lstrip("[").rstrip("]")
        parts.append(last)
    return parts, id


def format_parts_id(data):
    """
    format canonical representation of ATT&CK/MBC parts and ID
    """
    return "%s [%s]" % ("::".join(data["parts"]), data["id"])


def capability_rules(doc):
    """enumerate the rules in (namespace, name) order that are 'capability' rules (not lib/subscope/disposition/etc)."""
    for (_, _, rule) in sorted(
        map(lambda rule: (rule["meta"].get("namespace", ""), rule["meta"]["name"], rule), doc["rules"].values())
    ):
        if rule["meta"].get("lib"):
            continue
        if rule["meta"].get("capa/subscope"):
            continue
        if rule["meta"].get("maec/analysis-conclusion"):
            continue
        if rule["meta"].get("maec/analysis-conclusion-ov"):
            continue
        if rule["meta"].get("maec/malware-family"):
            continue
        if rule["meta"].get("maec/malware-category"):
            continue
        if rule["meta"].get("maec/malware-category-ov"):
            continue

        yield rule


class StringIO(io.StringIO):
    def writeln(self, s):
        self.write(s)
        self.write("\n")
