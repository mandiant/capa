"""
example::

    send data
    namespace    communication
    author       william.ballenthin@fireeye.com
    description  all known techniques for sending data to a potential C2 server
    scope        function
    examples     BFB9B5391A13D0AFD787E87AB90F14F5:0x13145D60
    matches      0x10004363
                 0x100046c9
                 0x1000454e
                 0x10003a13
                 0x10003415
                 0x10003797
"""
import tabulate

import capa.rules
import capa.render.utils as rutils


def render_verbose(doc):
    ostream = rutils.StringIO()

    rows = [(
        rutils.bold("Capa Report for"),
        rutils.bold(doc["meta"]["sample"]["md5"]),
    )]
    for k in ("timestamp", "version"):
        rows.append((k,doc["meta"][k]))

    for k in ("path", "md5", "sha1", "sha256"):
        rows.append((k, doc["meta"]["sample"][k]))

    for k in ("format", "extractor"):
        rows.append((k, doc["meta"]["analysis"][k]))

    ostream.writeln(tabulate.tabulate(rows, tablefmt="plain"))
    ostream.write("\n")

    for rule in rutils.capability_rules(doc):
        count = len(rule["matches"])
        if count == 1:
            capability = rutils.bold(rule["meta"]["name"])
        else:
            capability = "%s (%d matches)" % (rutils.bold(rule["meta"]["name"]), count)

        ostream.writeln(capability)

        rows = []
        for key in ("namespace", "description", "scope"):
            if key == "name" or key not in rule["meta"]:
                continue

            v = rule["meta"][key]
            if isinstance(v, list) and len(v) == 1:
                v = v[0]
            rows.append((key, v))

        if rule["meta"]["scope"] != capa.rules.FILE_SCOPE:
            locations = doc["rules"][rule["meta"]["name"]]["matches"].keys()
            rows.append(("matches", "\n".join(map(rutils.hex, locations))))

        ostream.writeln(tabulate.tabulate(rows, tablefmt="plain"))
        ostream.write("\n")

    return ostream.getvalue()
