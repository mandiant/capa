# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
"""
Binary Ninja plugin that imports a capa report,
produced via `capa --json /path/to/sample`,
into the current database.

It will mark up functions with their capa matches, like:

    ; capa: print debug messages (host-interaction/log/debug/write-event)
    ; capa: delete service (host-interaction/service/delete)
    ; Attributes: bp-based frame

    public UninstallService
    UninstallService proc near
    ...

To use, invoke from the Binary Ninja Tools menu, or from the command-palette.

Adapted for Binary Ninja by @psifertex

This script will verify that the report matches the workspace.
Check the log window for any errors, and/or the summary of changes.

Derived from: https://github.com/mandiant/capa/blob/master/scripts/import-to-ida.py
"""
import os
import json
from pathlib import Path

import binaryninja
import binaryninja.interaction


def append_func_cmt(bv, va, cmt):
    """
    add the given comment to the given function,
    if it doesn't already exist.
    """
    func = bv.get_function_at(va)
    if not func:
        raise ValueError("not a function")

    if cmt in func.comment:
        return

    func.comment = func.comment + "\n" + cmt


def load_analysis(bv):
    shortname = Path(bv.file.filename).resolve().stem
    dirname = Path(bv.file.filename).resolve().parent
    binaryninja.log_info(f"dirname: {dirname}\nshortname: {shortname}\n")
    js_path = path = dirname / (shortname + ".js")
    json_path = dirname / (shortname + ".json")
    if os.access(str(js_path), os.R_OK):
        path = js_path
    elif os.access(str(json_path), os.R_OK):
        path = json_path
    else:
        path = binaryninja.interaction.get_open_filename_input("capa report:", "JSON (*.js *.json);;All Files (*)")
    if not path or not os.access(str(path), os.R_OK):
        binaryninja.log_error("Invalid filename.")
        return 0
    binaryninja.log_info(f"Using capa file {path}")

    doc = json.loads(path.read_bytes().decode("utf-8"))

    if "meta" not in doc or "rules" not in doc:
        binaryninja.log_error("doesn't appear to be a capa report")
        return -1

    a = doc["meta"]["sample"]["md5"].lower()
    md5 = binaryninja.Transform["MD5"]
    rawhex = binaryninja.Transform["RawHex"]
    b = rawhex.encode(md5.encode(bv.parent_view.read(bv.parent_view.start, bv.parent_view.end))).decode("utf-8")
    if a != b:
        binaryninja.log_error("sample mismatch")
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
            cmt = f"{name} ({ns})"
        else:
            cmt = f"{name}"

        binaryninja.log_info(f"{hex(va)}: {cmt}")
        try:
            # message will look something like:
            #
            #     capa: delete service (host-interaction/service/delete)
            append_func_cmt(bv, va, "capa: " + cmt)
        except ValueError:
            continue

    binaryninja.log_info("ok")


binaryninja.PluginCommand.register("Load capa file", "Loads an analysis file from capa", load_analysis)
