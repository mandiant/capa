"""
IDA Pro script that imports a capa report,
produced via `capa --json /path/to/sample`,
into the current database.

It will mark up functions with their capa matches, like:

    ; capa: print debug messages (host-interaction/log/debug/write-event)
    ; capa: delete service (host-interaction/service/delete)
    ; Attributes: bp-based frame

    public UninstallService
    UninstallService proc near
    ...

To use, invoke from the IDA Pro scripting dialog,
such as via Alt-F9,
and then select the existing capa report from the file system.

This script will verify that the report matches the workspace.
Check the output window for any errors, and/or the summary of changes.

Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""

import logging
import binascii
from pathlib import Path

import ida_nalt
import ida_funcs
import ida_kernwin

import capa.rules
import capa.features.freeze
import capa.render.result_document

logger = logging.getLogger("capa")


def append_func_cmt(va, cmt, repeatable=False):
    """
    add the given comment to the given function,
    if it doesn't already exist.
    """
    func = ida_funcs.get_func(va)
    if not func:
        raise ValueError("not a function")

    existing = ida_funcs.get_func_cmt(func, repeatable) or ""
    if cmt in existing:
        return

    if len(existing) > 0:
        new = existing + "\n" + cmt
    else:
        new = cmt

    ida_funcs.set_func_cmt(func, new, repeatable)


def main():
    path = ida_kernwin.ask_file(False, "*", "capa report")
    if not path:
        return 0

    result_doc = capa.render.result_document.ResultDocument.from_file(Path(path))
    meta, capabilities = result_doc.to_capa()

    # in IDA 7.4, the MD5 hash may be truncated, for example:
    # wanted: 84882c9d43e23d63b82004fae74ebb61
    # found: b'84882C9D43E23D63B82004FAE74EBB6\x00'
    #
    # see: https://github.com/idapython/bin/issues/11
    a = meta.sample.md5.lower()
    b = binascii.hexlify(ida_nalt.retrieve_input_file_md5()).decode("ascii").lower()
    if not a.startswith(b):
        logger.error("sample mismatch")
        return -2

    rows = []
    for name in capabilities.keys():
        rule = result_doc.rules[name]
        if rule.meta.lib:
            continue
        if rule.meta.is_subscope_rule:
            continue
        if rule.meta.scopes.static == capa.rules.Scope.FUNCTION:
            continue

        ns = rule.meta.namespace

        for address, _ in rule.matches:
            if address.type != capa.features.freeze.AddressType.ABSOLUTE:
                continue

            va = address.value
            rows.append((ns, name, va))

    # order by (namespace, name) so that like things show up together
    rows = sorted(rows)
    for ns, name, va in rows:
        if ns:
            cmt = name + f"({ns})"
        else:
            cmt = name

        logger.info("0x%x: %s", va, cmt)
        try:
            # message will look something like:
            #
            #     capa: delete service (host-interaction/service/delete)
            append_func_cmt(va, "capa: " + cmt, repeatable=False)
        except ValueError:
            continue

    logger.info("ok")


main()
