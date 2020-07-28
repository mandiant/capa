# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import six
import termcolor


def bold(s):
    """draw attention to the given string"""
    return termcolor.colored(s, "blue")


def bold2(s):
    """draw attention to the given string, within a `bold` section"""
    return termcolor.colored(s, "green")


def hex(n):
    """render the given number using upper case hex, like: 0x123ABC"""
    if n < 0:
        return "-0x%X" % (-n)
    else:
        return "0x%X" % n


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
        if rule["meta"].get("maec/malware-category"):
            continue
        if rule["meta"].get("maec/malware-category-ov"):
            continue

        yield rule


class StringIO(six.StringIO):
    def writeln(self, s):
        self.write(s)
        self.write("\n")
