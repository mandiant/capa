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

Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
You may obtain a copy of the License at: [package root]/LICENSE.txt
Unless required by applicable law or agreed to in writing, software distributed under the License
 is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""
import json
import logging

import idautils
import ida_funcs
import ida_kernwin

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

    new = existing + "\n" + cmt
    ida_funcs.set_func_cmt(func, new, repeatable)


def main():
    path = ida_kernwin.ask_file(False, "*", "capa report")
    if not path:
        return 0

    with open(path, "rb") as f:
        doc = json.loads(f.read().decode("utf-8"))

    if "meta" not in doc or "rules" not in doc:
        logger.error("doesn't appear to be a capa report")
        return -1

    # in IDA 7.4, the MD5 hash may be truncated, for example:
    # wanted: 84882c9d43e23d63b82004fae74ebb61
    # found: b'84882C9D43E23D63B82004FAE74EBB6\x00'
    #
    # see: https://github.com/idapython/bin/issues/11
    a = doc["meta"]["sample"]["md5"].lower()
    b = idautils.GetInputFileMD5().decode("ascii").lower().rstrip("\x00")
    if not a.startswith(b):
        logger.error("sample mismatch")
        return -2

    rows = []
    for rule in doc["rules"].values():
        if rule["meta"].get("lib"):
            continue
        if rule["meta"].get("capa/subscope"):
            continue
        if rule["meta"]["scope"] != "function":
            continue

        name = rule["meta"]["name"]
        ns = rule["meta"].get("namespace", "")
        for va in rule["matches"].keys():
            va = int(va)
            rows.append((ns, name, va))

    # order by (namespace, name) so that like things show up together
    rows = sorted(rows)
    for ns, name, va in rows:
        if ns:
            cmt = "%s (%s)" % (name, ns)
        else:
            cmt = "%s" % (name,)

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
