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
    shortname = os.path.splitext(os.path.basename(bv.file.filename))[0]
    dirname = os.path.dirname(bv.file.filename)
    binaryninja.log_info(f"dirname: {dirname}\nshortname: {shortname}\n")
    if os.access(os.path.join(dirname, shortname + ".js"), os.R_OK):
        path = os.path.join(dirname, shortname + ".js")
    elif os.access(os.path.join(dirname, shortname + ".json"), os.R_OK):
        path = os.path.join(dirname, shortname + ".json")
    else:
        path = binaryninja.interaction.get_open_filename_input("capa report:", "JSON (*.js *.json);;All Files (*)")
    if not path or not os.access(path, os.R_OK):
        binaryninja.log_error("Invalid filename.")
        return 0
    binaryninja.log_info("Using capa file %s" % path)

    with open(path, "rb") as f:
        doc = json.loads(f.read().decode("utf-8"))

    if "meta" not in doc or "rules" not in doc:
        binaryninja.log_error("doesn't appear to be a capa report")
        return -1

    a = doc["meta"]["sample"]["md5"].lower()
    md5 = binaryninja.Transform["MD5"]
    rawhex = binaryninja.Transform["RawHex"]
    b = rawhex.encode(md5.encode(bv.parent_view.read(bv.parent_view.start, bv.parent_view.end))).decode("utf-8")
    if not a == b:
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
            cmt = "%s (%s)" % (name, ns)
        else:
            cmt = "%s" % (name,)

        binaryninja.log_info("0x%x: %s" % (va, cmt))
        try:
            # message will look something like:
            #
            #     capa: delete service (host-interaction/service/delete)
            append_func_cmt(bv, va, "capa: " + cmt)
        except ValueError:
            continue

    binaryninja.log_info("ok")


binaryninja.PluginCommand.register("Load capa file", "Loads an analysis file from capa", load_analysis)
