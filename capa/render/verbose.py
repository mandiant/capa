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

Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""

from typing import cast

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
    elif address.type == frz.AddressType.PROCESS:
        assert isinstance(address.value, tuple)
        ppid, pid = address.value
        assert isinstance(ppid, int)
        assert isinstance(pid, int)
        return f"process{{pid:{pid}}}"
    elif address.type == frz.AddressType.THREAD:
        assert isinstance(address.value, tuple)
        ppid, pid, tid = address.value
        assert isinstance(ppid, int)
        assert isinstance(pid, int)
        assert isinstance(tid, int)
        return f"process{{pid:{pid},tid:{tid}}}"
    elif address.type == frz.AddressType.CALL:
        assert isinstance(address.value, tuple)
        ppid, pid, tid, id_ = address.value
        return f"process{{pid:{pid},tid:{tid},call:{id_}}}"
    elif address.type == frz.AddressType.NO_ADDRESS:
        return "global"
    else:
        raise ValueError("unexpected address type")


def _get_process_name(layout: rd.DynamicLayout, addr: frz.Address) -> str:
    for p in layout.processes:
        if p.address == addr:
            return p.name

    raise ValueError("name not found for process", addr)


def _get_call_name(layout: rd.DynamicLayout, addr: frz.Address) -> str:
    call = addr.to_capa()
    assert isinstance(call, capa.features.address.DynamicCallAddress)

    thread = frz.Address.from_capa(call.thread)
    process = frz.Address.from_capa(call.thread.process)

    # danger: O(n**3)
    for p in layout.processes:
        if p.address == process:
            for t in p.matched_threads:
                if t.address == thread:
                    for c in t.matched_calls:
                        if c.address == addr:
                            return c.name
    raise ValueError("name not found for call", addr)


def render_process(layout: rd.DynamicLayout, addr: frz.Address) -> str:
    process = addr.to_capa()
    assert isinstance(process, capa.features.address.ProcessAddress)
    name = _get_process_name(layout, addr)
    return f"{name}{{pid:{process.pid}}}"


def render_thread(layout: rd.DynamicLayout, addr: frz.Address) -> str:
    thread = addr.to_capa()
    assert isinstance(thread, capa.features.address.ThreadAddress)
    name = _get_process_name(layout, frz.Address.from_capa(thread.process))
    return f"{name}{{pid:{thread.process.pid},tid:{thread.tid}}}"


def render_call(layout: rd.DynamicLayout, addr: frz.Address) -> str:
    call = addr.to_capa()
    assert isinstance(call, capa.features.address.DynamicCallAddress)

    pname = _get_process_name(layout, frz.Address.from_capa(call.thread.process))
    cname = _get_call_name(layout, addr)

    fname, _, rest = cname.partition("(")
    args, _, rest = rest.rpartition(")")

    s = []
    s.append(f"{fname}(")
    for arg in args.split(", "):
        s.append(f"  {arg},")
    s.append(f"){rest}")

    newline = "\n"
    return (
        f"{pname}{{pid:{call.thread.process.pid},tid:{call.thread.tid},call:{call.id}}}\n{rutils.mute(newline.join(s))}"
    )


def render_static_meta(ostream, meta: rd.StaticMetadata):
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
        analysis             static
        extractor            VivisectFeatureExtractor
        base address         0x10000000
        rules                (embedded rules)
        function count       42
        total feature count  1918
    """

    rows = [
        ("md5", meta.sample.md5),
        ("sha1", meta.sample.sha1),
        ("sha256", meta.sample.sha256),
        ("path", meta.sample.path),
        ("timestamp", meta.timestamp),
        ("capa version", meta.version),
        ("os", meta.analysis.os),
        ("format", meta.analysis.format),
        ("arch", meta.analysis.arch),
        ("analysis", meta.flavor.value),
        ("extractor", meta.analysis.extractor),
        ("base address", format_address(meta.analysis.base_address)),
        ("rules", "\n".join(meta.analysis.rules)),
        ("function count", len(meta.analysis.feature_counts.functions)),
        ("library function count", len(meta.analysis.library_functions)),
        (
            "total feature count",
            meta.analysis.feature_counts.file + sum(f.count for f in meta.analysis.feature_counts.functions),
        ),
    ]

    ostream.writeln(tabulate.tabulate(rows, tablefmt="plain"))


def render_dynamic_meta(ostream, meta: rd.DynamicMetadata):
    """
    like:

        md5                  84882c9d43e23d63b82004fae74ebb61
        sha1                 c6fb3b50d946bec6f391aefa4e54478cf8607211
        sha256               5eced7367ed63354b4ed5c556e2363514293f614c2c2eb187273381b2ef5f0f9
        path                 /tmp/packed-report,jspn
        timestamp            2023-07-17T10:17:05.796933
        capa version         0.0.0
        os                   windows
        format               pe
        arch                 amd64
        extractor            CAPEFeatureExtractor
        rules                (embedded rules)
        process count        42
        total feature count  1918
    """

    rows = [
        ("md5", meta.sample.md5),
        ("sha1", meta.sample.sha1),
        ("sha256", meta.sample.sha256),
        ("path", meta.sample.path),
        ("timestamp", meta.timestamp),
        ("capa version", meta.version),
        ("os", meta.analysis.os),
        ("format", meta.analysis.format),
        ("arch", meta.analysis.arch),
        ("analysis", meta.flavor.value),
        ("extractor", meta.analysis.extractor),
        ("rules", "\n".join(meta.analysis.rules)),
        ("process count", len(meta.analysis.feature_counts.processes)),
        (
            "total feature count",
            meta.analysis.feature_counts.file + sum(p.count for p in meta.analysis.feature_counts.processes),
        ),
    ]

    ostream.writeln(tabulate.tabulate(rows, tablefmt="plain"))


def render_meta(osstream, doc: rd.ResultDocument):
    if doc.meta.flavor == rd.Flavor.STATIC:
        render_static_meta(osstream, cast(rd.StaticMetadata, doc.meta))
    elif doc.meta.flavor == rd.Flavor.DYNAMIC:
        render_dynamic_meta(osstream, cast(rd.DynamicMetadata, doc.meta))
    else:
        raise ValueError("invalid meta analysis")


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

        ns = rule.meta.namespace
        if ns:
            rows.append(("namespace", ns))

        desc = rule.meta.description
        if desc:
            rows.append(("description", desc))

        if doc.meta.flavor == rd.Flavor.STATIC:
            scope = rule.meta.scopes.static
        elif doc.meta.flavor == rd.Flavor.DYNAMIC:
            scope = rule.meta.scopes.dynamic
        else:
            raise ValueError("invalid meta analysis")
        if scope:
            rows.append(("scope", scope.value))

        if capa.rules.Scope.FILE not in rule.meta.scopes:
            locations = [m[0] for m in doc.rules[rule.meta.name].matches]
            lines = []

            if doc.meta.flavor == rd.Flavor.STATIC:
                lines = [format_address(loc) for loc in locations]
            elif doc.meta.flavor == rd.Flavor.DYNAMIC:
                assert rule.meta.scopes.dynamic is not None
                assert isinstance(doc.meta.analysis.layout, rd.DynamicLayout)

                if rule.meta.scopes.dynamic == capa.rules.Scope.PROCESS:
                    lines = [render_process(doc.meta.analysis.layout, loc) for loc in locations]
                elif rule.meta.scopes.dynamic == capa.rules.Scope.THREAD:
                    lines = [render_thread(doc.meta.analysis.layout, loc) for loc in locations]
                elif rule.meta.scopes.dynamic == capa.rules.Scope.CALL:
                    # because we're only in verbose mode, we won't show the full call details (name, args, retval)
                    # we'll only show the details of the thread in which the calls are found.
                    # so select the thread locations and render those.
                    thread_locations = set()
                    for loc in locations:
                        cloc = loc.to_capa()
                        assert isinstance(cloc, capa.features.address.DynamicCallAddress)
                        thread_locations.add(frz.Address.from_capa(cloc.thread))

                    lines = [render_thread(doc.meta.analysis.layout, loc) for loc in thread_locations]
                else:
                    capa.helpers.assert_never(rule.meta.scopes.dynamic)
            else:
                capa.helpers.assert_never(doc.meta.flavor)

            rows.append(("matches", "\n".join(lines)))

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
