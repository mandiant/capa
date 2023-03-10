# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Dict, Iterable

import tabulate

import capa.rules
import capa.helpers
import capa.render.utils as rutils
import capa.render.verbose
import capa.features.common
import capa.features.freeze as frz
import capa.features.address
import capa.render.result_document as rd
import capa.features.freeze.features as frzf
from capa.rules import RuleSet
from capa.engine import MatchResults


def render_locations(ostream, locations: Iterable[frz.Address]):
    import capa.render.verbose as v

    # its possible to have an empty locations array here,
    # such as when we're in MODE_FAILURE and showing the logic
    # under a `not` statement (which will have no matched locations).
    locations = list(sorted(locations))

    if len(locations) == 0:
        return

    ostream.write(" @ ")

    if len(locations) == 1:
        ostream.write(v.format_address(locations[0]))

    elif len(locations) > 4:
        # don't display too many locations, because it becomes very noisy.
        # probably only the first handful of locations will be useful for inspection.
        ostream.write(", ".join(map(v.format_address, locations[0:4])))
        ostream.write(f", and {(len(locations) - 4)} more...")

    elif len(locations) > 1:
        ostream.write(", ".join(map(v.format_address, locations)))

    else:
        raise RuntimeError("unreachable")


def render_statement(ostream, match: rd.Match, statement: rd.Statement, indent=0):
    ostream.write("  " * indent)

    if isinstance(statement, rd.SubscopeStatement):
        # emit `basic block:`
        # rather than `subscope:`
        ostream.write(statement.scope)

        ostream.write(":")
        if statement.description:
            ostream.write(f" = {statement.description}")
        ostream.writeln("")

    elif isinstance(statement, (rd.CompoundStatement)):
        # emit `and:`  `or:`  `optional:`  `not:`
        ostream.write(statement.type)

        ostream.write(":")
        if statement.description:
            ostream.write(f" = {statement.description}")
        ostream.writeln("")

    elif isinstance(statement, rd.SomeStatement):
        ostream.write(f"{statement.count} or more:")

        if statement.description:
            ostream.write(f" = {statement.description}")
        ostream.writeln("")

    elif isinstance(statement, rd.RangeStatement):
        # `range` is a weird node, its almost a hybrid of statement+feature.
        # it is a specific feature repeated multiple times.
        # there's no additional logic in the feature part, just the existence of a feature.
        # so, we have to inline some of the feature rendering here.

        child = statement.child
        value = child.dict(by_alias=True).get(child.type)

        if value:
            if isinstance(child, frzf.StringFeature):
                value = f'"{capa.features.common.escape_string(value)}"'

            value = rutils.bold2(value)

            if child.description:
                ostream.write(f"count({child.type}({value} = {child.description})): ")
            else:
                ostream.write(f"count({child.type}({value})): ")
        else:
            ostream.write(f"count({child.type}): ")

        if statement.max == statement.min:
            ostream.write(f"{statement.min}")
        elif statement.min == 0:
            ostream.write(f"{statement.max} or fewer")
        elif statement.max == (1 << 64 - 1):
            ostream.write(f"{statement.min} or more")
        else:
            ostream.write(f"between {statement.min} and {statement.max}")

        if statement.description:
            ostream.write(f" = {statement.description}")
        render_locations(ostream, match.locations)
        ostream.writeln("")

    else:
        raise RuntimeError("unexpected match statement type: " + str(statement))


def render_string_value(s: str) -> str:
    return f'"{capa.features.common.escape_string(s)}"'


def render_feature(ostream, match: rd.Match, feature: frzf.Feature, indent=0):
    ostream.write("  " * indent)

    key = feature.type
    if isinstance(feature, frzf.BasicBlockFeature):
        # i don't think it makes sense to have standalone basic block features.
        # we don't parse them from rules, only things like: `count(basic block) > 1`
        raise ValueError("cannot render basic block feature directly")
    elif isinstance(feature, frzf.ImportFeature):
        # fixup access to Python reserved name
        value = feature.import_
    elif isinstance(feature, frzf.ClassFeature):
        value = feature.class_
    else:
        # convert attributes to dictionary using aliased names, if applicable
        value = feature.dict(by_alias=True).get(key, None)

    if value is None:
        raise ValueError(f"{key} contains None")

    if not isinstance(feature, (frzf.RegexFeature, frzf.SubstringFeature)):
        # like:
        #   number: 10 = SOME_CONSTANT @ 0x401000
        if isinstance(feature, frzf.StringFeature):
            value = render_string_value(value)

        elif isinstance(
            feature, (frzf.NumberFeature, frzf.OffsetFeature, frzf.OperandNumberFeature, frzf.OperandOffsetFeature)
        ):
            assert isinstance(value, int)
            value = capa.helpers.hex(value)

        if isinstance(feature, frzf.PropertyFeature) and feature.access is not None:
            key = f"property/{feature.access}"

        elif isinstance(feature, frzf.OperandNumberFeature):
            key = f"operand[{feature.index}].number"

        elif isinstance(feature, frzf.OperandOffsetFeature):
            key = f"operand[{feature.index}].offset"

        ostream.write(f"{key}: ")

        if value:
            ostream.write(rutils.bold2(value))

            if feature.description:
                ostream.write(capa.rules.DESCRIPTION_SEPARATOR)
                ostream.write(feature.description)

        if not isinstance(feature, (frzf.OSFeature, frzf.ArchFeature, frzf.FormatFeature)):
            render_locations(ostream, match.locations)
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

        for capture, locations in sorted(match.captures.items()):
            ostream.write("  " * (indent + 1))
            ostream.write("- ")
            ostream.write(rutils.bold2(render_string_value(capture)))
            render_locations(ostream, locations)
            ostream.write("\n")


def render_node(ostream, match: rd.Match, node: rd.Node, indent=0):
    if isinstance(node, rd.StatementNode):
        render_statement(ostream, match, node.statement, indent=indent)
    elif isinstance(node, rd.FeatureNode):
        render_feature(ostream, match, node.feature, indent=indent)
    else:
        raise RuntimeError("unexpected node type: " + str(node))


# display nodes that successfully evaluated against the sample.
MODE_SUCCESS = "success"

# display nodes that did not evaluate to True against the sample.
# this is useful when rendering the logic tree under a `not` node.
MODE_FAILURE = "failure"


def render_match(ostream, match: rd.Match, indent=0, mode=MODE_SUCCESS):
    child_mode = mode
    if mode == MODE_SUCCESS:
        # display only nodes that evaluated successfully.
        if not match.success:
            return

        # optional statement with no successful children is empty
        if isinstance(match.node, rd.StatementNode) and match.node.statement.type == rd.CompoundStatementType.OPTIONAL:
            if not any(map(lambda m: m.success, match.children)):
                return

        # not statement, so invert the child mode to show failed evaluations
        if isinstance(match.node, rd.StatementNode) and match.node.statement.type == rd.CompoundStatementType.NOT:
            child_mode = MODE_FAILURE

    elif mode == MODE_FAILURE:
        # display only nodes that did not evaluate to True
        if match.success:
            return

        # optional statement with successful children is not relevant
        if isinstance(match.node, rd.StatementNode) and match.node.statement.type == rd.CompoundStatementType.OPTIONAL:
            if any(map(lambda m: m.success, match.children)):
                return

        # not statement, so invert the child mode to show successful evaluations
        if isinstance(match.node, rd.StatementNode) and match.node.statement.type == rd.CompoundStatementType.NOT:
            child_mode = MODE_SUCCESS
    else:
        raise RuntimeError("unexpected mode: " + mode)

    render_node(ostream, match, match.node, indent=indent)

    for child in match.children:
        render_match(ostream, child, indent=indent + 1, mode=child_mode)


def render_rules(ostream, doc: rd.ResultDocument):
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
    functions_by_bb: Dict[capa.features.address.Address, capa.features.address.Address] = {}
    for finfo in doc.meta.analysis.layout.functions:
        faddress = finfo.address.to_capa()

        for bb in finfo.matched_basic_blocks:
            bbaddress = bb.address.to_capa()
            functions_by_bb[bbaddress] = faddress

    had_match = False

    for _, _, rule in sorted(map(lambda rule: (rule.meta.namespace or "", rule.meta.name, rule), doc.rules.values())):
        # default scope hides things like lib rules, malware-category rules, etc.
        # but in vverbose mode, we really want to show everything.
        #
        # still ignore subscope rules because they're stitched into the final document.
        if rule.meta.is_subscope_rule:
            continue

        lib_info = ""
        count = len(rule.matches)
        if count == 1:
            if rule.meta.lib:
                lib_info = " (library rule)"
            capability = f"{rutils.bold(rule.meta.name)}{lib_info}"
        else:
            if rule.meta.lib:
                lib_info = ", only showing first match of library rule"
            capability = f"{rutils.bold(rule.meta.name)} ({count} matches{lib_info})"

        ostream.writeln(capability)
        had_match = True

        rows = []
        if not rule.meta.lib:
            # library rules should not have a namespace
            rows.append(("namespace", rule.meta.namespace))

        if rule.meta.maec.analysis_conclusion or rule.meta.maec.analysis_conclusion_ov:
            rows.append(
                (
                    "maec/analysis-conclusion",
                    rule.meta.maec.analysis_conclusion or rule.meta.maec.analysis_conclusion_ov,
                )
            )

        if rule.meta.maec.malware_family:
            rows.append(("maec/malware-family", rule.meta.maec.malware_family))

        if rule.meta.maec.malware_category or rule.meta.maec.malware_category_ov:
            rows.append(
                ("maec/malware-category", rule.meta.maec.malware_category or rule.meta.maec.malware_category_ov)
            )

        rows.append(("author", ", ".join(rule.meta.authors)))

        rows.append(("scope", rule.meta.scope.value))

        if rule.meta.attack:
            rows.append(("att&ck", ", ".join([rutils.format_parts_id(v) for v in rule.meta.attack])))

        if rule.meta.mbc:
            rows.append(("mbc", ", ".join([rutils.format_parts_id(v) for v in rule.meta.mbc])))

        if rule.meta.references:
            rows.append(("references", ", ".join(rule.meta.references)))

        if rule.meta.description:
            rows.append(("description", rule.meta.description))

        ostream.writeln(tabulate.tabulate(rows, tablefmt="plain"))

        if rule.meta.scope == capa.rules.FILE_SCOPE:
            matches = doc.rules[rule.meta.name].matches
            if len(matches) != 1:
                # i think there should only ever be one match per file-scope rule,
                # because we do the file-scope evaluation a single time.
                # but i'm not 100% sure if this is/will always be true.
                # so, lets be explicit about our assumptions and raise an exception if they fail.
                raise RuntimeError(f"unexpected file scope match count: {len(matches)}")
            first_address, first_match = matches[0]
            render_match(ostream, first_match, indent=0)
        else:
            for location, match in sorted(doc.rules[rule.meta.name].matches):
                ostream.write(rule.meta.scope)
                ostream.write(" @ ")
                ostream.write(capa.render.verbose.format_address(location))

                if rule.meta.scope == capa.rules.BASIC_BLOCK_SCOPE:
                    ostream.write(
                        " in function "
                        + capa.render.verbose.format_address(frz.Address.from_capa(functions_by_bb[location.to_capa()]))
                    )

                ostream.write("\n")
                render_match(ostream, match, indent=1)
                if rule.meta.lib:
                    # only show first match
                    break

        ostream.write("\n")

    if not had_match:
        ostream.writeln(rutils.bold("no capabilities found"))


def render_vverbose(doc: rd.ResultDocument):
    ostream = rutils.StringIO()

    capa.render.verbose.render_meta(ostream, doc)
    ostream.write("\n")

    render_rules(ostream, doc)
    ostream.write("\n")

    return ostream.getvalue()


def render(meta, rules: RuleSet, capabilities: MatchResults) -> str:
    return render_vverbose(rd.ResultDocument.from_capa(meta, rules, capabilities))
