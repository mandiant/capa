# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import tabulate

import capa.rules
import capa.render.utils as rutils
import capa.render.verbose
import capa.features.common
import capa.render.result_document
from capa.rules import RuleSet
from capa.engine import MatchResults


def render_locations(ostream, match):
    # its possible to have an empty locations array here,
    # such as when we're in MODE_FAILURE and showing the logic
    # under a `not` statement (which will have no matched locations).
    locations = list(sorted(match.get("locations", [])))
    if len(locations) == 1:
        ostream.write(" @ ")
        ostream.write(rutils.hex(locations[0]))
    elif len(locations) > 1:
        ostream.write(" @ ")
        if len(locations) > 4:
            # don't display too many locations, because it becomes very noisy.
            # probably only the first handful of locations will be useful for inspection.
            ostream.write(", ".join(map(rutils.hex, locations[0:4])))
            ostream.write(", and %d more..." % (len(locations) - 4))
        else:
            ostream.write(", ".join(map(rutils.hex, locations)))


def render_statement(ostream, match, statement, indent=0):
    ostream.write("  " * indent)
    if statement["type"] in ("and", "or", "optional", "not", "subscope"):
        if statement["type"] == "subscope":
            # emit `basic block:`
            # rather than `subscope:`
            ostream.write(statement["subscope"])
        else:
            # emit `and:`
            ostream.write(statement["type"])
        ostream.write(":")
        if statement.get("description"):
            ostream.write(" = %s" % statement["description"])
        ostream.writeln("")
    elif statement["type"] == "some":
        ostream.write("%d or more:" % (statement["count"]))
        if statement.get("description"):
            ostream.write(" = %s" % statement["description"])
        ostream.writeln("")
    elif statement["type"] == "range":
        # `range` is a weird node, its almost a hybrid of statement+feature.
        # it is a specific feature repeated multiple times.
        # there's no additional logic in the feature part, just the existence of a feature.
        # so, we have to inline some of the feature rendering here.

        child = statement["child"]

        if child[child["type"]]:
            if child["type"] == "string":
                value = '"%s"' % capa.features.common.escape_string(child[child["type"]])
            else:
                value = child[child["type"]]
            value = rutils.bold2(value)
            if child.get("description"):
                ostream.write("count(%s(%s = %s)): " % (child["type"], value, child["description"]))
            else:
                ostream.write("count(%s(%s)): " % (child["type"], value))
        else:
            ostream.write("count(%s): " % child["type"])

        if statement["max"] == statement["min"]:
            ostream.write("%d" % (statement["min"]))
        elif statement["min"] == 0:
            ostream.write("%d or fewer" % (statement["max"]))
        elif statement["max"] == (1 << 64 - 1):
            ostream.write("%d or more" % (statement["min"]))
        else:
            ostream.write("between %d and %d" % (statement["min"], statement["max"]))

        if statement.get("description"):
            ostream.write(" = %s" % statement["description"])
        render_locations(ostream, match)
        ostream.writeln("")
    else:
        raise RuntimeError("unexpected match statement type: " + str(statement))


def render_string_value(s):
    return '"%s"' % capa.features.common.escape_string(s)


def render_feature(ostream, match, feature, indent=0):
    ostream.write("  " * indent)

    key = feature["type"]
    value = feature[feature["type"]]

    if key not in ("regex", "substring"):
        # like:
        #   number: 10 = SOME_CONSTANT @ 0x401000
        if key == "string":
            value = render_string_value(value)

        ostream.write(key)
        ostream.write(": ")

        if value:
            ostream.write(rutils.bold2(value))

            if "description" in feature:
                ostream.write(capa.rules.DESCRIPTION_SEPARATOR)
                ostream.write(feature["description"])

        if key not in ("os", "arch"):
            render_locations(ostream, match)
        ostream.write("\n")
    else:
        # like:
        #  regex: /blah/ = SOME_CONSTANT
        #    - "foo blah baz" @ 0x401000
        #    - "aaa blah bbb" @ 0x402000, 0x403400
        ostream.write(key)
        ostream.write(": ")
        ostream.write(value)
        ostream.write("\n")

        for match, locations in sorted(feature["matches"].items(), key=lambda p: p[0]):
            ostream.write("  " * (indent + 1))
            ostream.write("- ")
            ostream.write(rutils.bold2(render_string_value(match)))
            render_locations(ostream, {"locations": locations})
            ostream.write("\n")


def render_node(ostream, match, node, indent=0):
    if node["type"] == "statement":
        render_statement(ostream, match, node["statement"], indent=indent)
    elif node["type"] == "feature":
        render_feature(ostream, match, node["feature"], indent=indent)
    else:
        raise RuntimeError("unexpected node type: " + str(node))


# display nodes that successfully evaluated against the sample.
MODE_SUCCESS = "success"

# display nodes that did not evaluate to True against the sample.
# this is useful when rendering the logic tree under a `not` node.
MODE_FAILURE = "failure"


def render_match(ostream, match, indent=0, mode=MODE_SUCCESS):
    child_mode = mode
    if mode == MODE_SUCCESS:
        # display only nodes that evaluated successfully.
        if not match["success"]:
            return
        # optional statement with no successful children is empty
        if match["node"].get("statement", {}).get("type") == "optional" and not any(
            map(lambda m: m["success"], match["children"])
        ):
            return
        # not statement, so invert the child mode to show failed evaluations
        if match["node"].get("statement", {}).get("type") == "not":
            child_mode = MODE_FAILURE
    elif mode == MODE_FAILURE:
        # display only nodes that did not evaluate to True
        if match["success"]:
            return
        # optional statement with successful children is not relevant
        if match["node"].get("statement", {}).get("type") == "optional" and any(
            map(lambda m: m["success"], match["children"])
        ):
            return
        # not statement, so invert the child mode to show successful evaluations
        if match["node"].get("statement", {}).get("type") == "not":
            child_mode = MODE_SUCCESS
    else:
        raise RuntimeError("unexpected mode: " + mode)

    render_node(ostream, match, match["node"], indent=indent)

    for child in match["children"]:
        render_match(ostream, child, indent=indent + 1, mode=child_mode)


def render_rules(ostream, doc):
    """
    like:

        ## rules
        check for OutputDebugString error
        namespace  anti-analysis/anti-debugging/debugger-detection
        author     michael.hunhoff@mandiant.com
        scope      function
        mbc        Anti-Behavioral Analysis::Detect Debugger::OutputDebugString
        function @ 0x10004706
          and:
            api: kernel32.SetLastError @ 0x100047C2
            api: kernel32.GetLastError @ 0x10004A87
            api: kernel32.OutputDebugString @ 0x10004767, 0x10004787, 0x10004816, 0x10004895
    """
    functions_by_bb = {}
    for function, info in doc["meta"]["analysis"]["layout"]["functions"].items():
        for bb in info["matched_basic_blocks"]:
            functions_by_bb[bb] = function

    had_match = False

    for (_, _, rule) in sorted(
        map(lambda rule: (rule["meta"].get("namespace", ""), rule["meta"]["name"], rule), doc["rules"].values())
    ):
        # default scope hides things like lib rules, malware-category rules, etc.
        # but in vverbose mode, we really want to show everything.
        #
        # still ignore subscope rules because they're stitched into the final document.
        if rule["meta"].get("capa/subscope"):
            continue

        count = len(rule["matches"])
        if count == 1:
            capability = rutils.bold(rule["meta"]["name"])
        else:
            capability = "%s (%d matches)" % (rutils.bold(rule["meta"]["name"]), count)

        ostream.writeln(capability)
        had_match = True

        rows = []
        for key in capa.rules.META_KEYS:
            if key == "name" or key not in rule["meta"]:
                continue

            if key == "examples":
                # I can't think of a reason that an analyst would pivot to the concrete example
                # directly from the capa output.
                # the more likely flow is to review the rule and go from there.
                # so, don't make the output messy by showing the examples.
                continue

            v = rule["meta"][key]
            if not v:
                continue

            if key in ("att&ck", "mbc"):
                v = [rutils.format_parts_id(vv) for vv in v]

            if isinstance(v, list) and len(v) == 1:
                v = v[0]
            elif isinstance(v, list) and len(v) > 1:
                v = ", ".join(v)
            rows.append((key, v))

        ostream.writeln(tabulate.tabulate(rows, tablefmt="plain"))

        if rule["meta"]["scope"] == capa.rules.FILE_SCOPE:
            matches = list(doc["rules"][rule["meta"]["name"]]["matches"].values())
            if len(matches) != 1:
                # i think there should only ever be one match per file-scope rule,
                # because we do the file-scope evaluation a single time.
                # but i'm not 100% sure if this is/will always be true.
                # so, lets be explicit about our assumptions and raise an exception if they fail.
                raise RuntimeError("unexpected file scope match count: %d" % (len(matches)))
            render_match(ostream, matches[0], indent=0)
        else:
            for location, match in sorted(doc["rules"][rule["meta"]["name"]]["matches"].items()):
                ostream.write(rule["meta"]["scope"])
                ostream.write(" @ ")
                ostream.write(rutils.hex(location))

                if rule["meta"]["scope"] == capa.rules.BASIC_BLOCK_SCOPE:
                    ostream.write(" in function " + rutils.hex(functions_by_bb[location]))

                ostream.write("\n")
                render_match(ostream, match, indent=1)
        ostream.write("\n")

    if not had_match:
        ostream.writeln(rutils.bold("no capabilities found"))


def render_vverbose(doc):
    ostream = rutils.StringIO()

    capa.render.verbose.render_meta(ostream, doc)
    ostream.write("\n")

    render_rules(ostream, doc)
    ostream.write("\n")

    return ostream.getvalue()


def render(meta, rules: RuleSet, capabilities: MatchResults) -> str:
    doc = capa.render.result_document.convert_capabilities_to_result_document(meta, rules, capabilities)
    return render_vverbose(doc)
