"""
example::

    send data
    namespace    communication
    author       william.ballenthin@mandiant.com
    description  all known techniques for sending data to a potential C2 server
    scope        function
    examples     BFB9B5391A13D0AFD787E87AB90F14F5:0x13145D60
    matches      0x10004363
                 0x100046c9
                 0x1000454e
                 0x10003a13
                 0x10003415
                 0x10003797

Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
import enum

import tabulate

import capa.rules
import capa.helpers
import capa.render.utils as rutils
import capa.features.freeze as frz
import capa.render.result_document as rd
from capa.rules import RuleSet
from capa.engine import MatchResults


def format_address(address: frz.Address) -> str:
    if address.type == frz.AddressType.ABSOLUTE:
        assert isinstance(address.value, int)
        return capa.helpers.hex(address.value)
    elif address.type == frz.AddressType.RELATIVE:
        assert isinstance(address.value, int)
        return f"base address+{capa.helpers.hex(address.value)}"
    elif address.type == frz.AddressType.FILE:
        assert isinstance(address.value, int)
        return f"file+{capa.helpers.hex(address.value)}"
    elif address.type == frz.AddressType.DN_TOKEN:
        assert isinstance(address.value, int)
        return f"token({capa.helpers.hex(address.value)})"
    elif address.type == frz.AddressType.DN_TOKEN_OFFSET:
        assert isinstance(address.value, tuple)
        token, offset = address.value
        assert isinstance(token, int)
        assert isinstance(offset, int)
        return f"token({capa.helpers.hex(token)})+{capa.helpers.hex(offset)}"
    elif address.type == frz.AddressType.NO_ADDRESS:
        return "global"
    else:
        raise ValueError("unexpected address type")


def render_meta(ostream, doc: rd.ResultDocument):
    """
    like:

        md5                  84882c9d43e23d63b82004fae74ebb61
        sha1                 c6fb3b50d946bec6f391aefa4e54478cf8607211
        sha256               5eced7367ed63354b4ed5c556e2363514293f614c2c2eb187273381b2ef5f0f9
        path                 /tmp/suspicious.dll_
        timestamp            2020-07-03T10:17:05.796933
        capa version         0.0.0
        os                   windows
        format               pe
        arch                 amd64
        extractor            VivisectFeatureExtractor
        base address         0x10000000
        rules                (embedded rules)
        function count       42
        total feature count  1918
    """
    rows = [
        ("md5", doc.meta.sample.md5),
        ("sha1", doc.meta.sample.sha1),
        ("sha256", doc.meta.sample.sha256),
        ("path", doc.meta.sample.path),
        ("timestamp", doc.meta.timestamp),
        ("capa version", doc.meta.version),
        ("os", doc.meta.analysis.os),
        ("format", doc.meta.analysis.format),
        ("arch", doc.meta.analysis.arch),
        ("extractor", doc.meta.analysis.extractor),
        ("base address", format_address(doc.meta.analysis.base_address)),
        ("rules", "\n".join(doc.meta.analysis.rules)),
        ("function count", len(doc.meta.analysis.feature_counts.functions)),
        ("library function count", len(doc.meta.analysis.library_functions)),
        (
            "total feature count",
            doc.meta.analysis.feature_counts.file
            + sum(map(lambda f: f.count, doc.meta.analysis.feature_counts.functions)),
        ),
    ]

    ostream.writeln(tabulate.tabulate(rows, tablefmt="plain"))


def render_rules(ostream, doc: rd.ResultDocument):
    """
    like:

        receive data (2 matches)
        namespace    communication
        description  all known techniques for receiving data from a potential C2 server
        scope        function
        matches      0x10003A13
                     0x10003797
    """
    had_match = False
    for rule in rutils.capability_rules(doc):
        count = len(rule.matches)
        if count == 1:
            capability = rutils.bold(rule.meta.name)
        else:
            capability = f"{rutils.bold(rule.meta.name)} ({count} matches)"

        ostream.writeln(capability)
        had_match = True

        rows = []
        for key in ("namespace", "description", "scope"):
            v = getattr(rule.meta, key)
            if not v:
                continue

            if isinstance(v, list) and len(v) == 1:
                v = v[0]

            if isinstance(v, enum.Enum):
                v = v.value

            rows.append((key, v))

        if rule.meta.scope != capa.rules.FILE_SCOPE:
            locations = list(map(lambda m: m[0], doc.rules[rule.meta.name].matches))
            rows.append(("matches", "\n".join(map(format_address, locations))))

        ostream.writeln(tabulate.tabulate(rows, tablefmt="plain"))
        ostream.write("\n")

    if not had_match:
        ostream.writeln(rutils.bold("no capabilities found"))


def render_verbose(doc: rd.ResultDocument):
    ostream = rutils.StringIO()

    render_meta(ostream, doc)
    ostream.write("\n")

    render_rules(ostream, doc)
    ostream.write("\n")

    return ostream.getvalue()


def render(meta, rules: RuleSet, capabilities: MatchResults) -> str:
    return render_verbose(rd.ResultDocument.from_capa(meta, rules, capabilities))
