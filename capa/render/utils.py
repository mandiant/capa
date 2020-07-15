# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

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
