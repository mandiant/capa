# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import datetime
from typing import Any, Dict, Tuple, Union, Optional

from pydantic import Field, BaseModel

import capa.rules
import capa.engine
import capa.features.common
import capa.features.freeze as frz
import capa.features.address
from capa.rules import RuleSet
from capa.engine import MatchResults
from capa.helpers import assert_never


class FrozenModel(BaseModel):
    class Config:
        frozen = True


class Sample(FrozenModel):
    md5: str
    sha1: str
    sha256: str
    path: str


class BasicBlockLayout(FrozenModel):
    address: frz.Address


class FunctionLayout(FrozenModel):
    address: frz.Address
    matched_basic_blocks: Tuple[BasicBlockLayout, ...]


class Layout(FrozenModel):
    functions: Tuple[FunctionLayout, ...]


class LibraryFunction(FrozenModel):
    address: frz.Address
    name: str


class FunctionFeatureCount(FrozenModel):
    address: frz.Address
    count: int


class FeatureCounts(FrozenModel):
    file: int
    functions: Tuple[FunctionFeatureCount, ...]


class Analysis(FrozenModel):
    format: str
    arch: str
    os: str
    extractor: str
    rules: Tuple[str, ...]
    base_address: frz.Address
    layout: Layout
    feature_counts: FeatureCounts
    library_functions: Tuple[LibraryFunction, ...]


class Metadata(FrozenModel):
    timestamp: datetime.datetime
    version: str
    argv: Optional[Tuple[str, ...]]
    sample: Sample
    analysis: Analysis

    @classmethod
    def from_capa(cls, meta: Any) -> "Metadata":
        return cls(
            timestamp=meta["timestamp"],
            version=meta["version"],
            argv=meta["argv"] if "argv" in meta else None,
            sample=Sample(
                md5=meta["sample"]["md5"],
                sha1=meta["sample"]["sha1"],
                sha256=meta["sample"]["sha256"],
                path=meta["sample"]["path"],
            ),
            analysis=Analysis(
                format=meta["analysis"]["format"],
                arch=meta["analysis"]["arch"],
                os=meta["analysis"]["os"],
                extractor=meta["analysis"]["extractor"],
                rules=meta["analysis"]["rules"],
                base_address=frz.Address.from_capa(meta["analysis"]["base_address"]),
                layout=Layout(
                    functions=[
                        FunctionLayout(
                            address=frz.Address.from_capa(address),
                            matched_basic_blocks=[
                                BasicBlockLayout(address=frz.Address.from_capa(bb)) for bb in f["matched_basic_blocks"]
                            ],
                        )
                        for address, f in meta["analysis"]["layout"]["functions"].items()
                    ]
                ),
                feature_counts=FeatureCounts(
                    file=meta["analysis"]["feature_counts"]["file"],
                    functions=[
                        FunctionFeatureCount(address=frz.Address.from_capa(address), count=count)
                        for address, count in meta["analysis"]["feature_counts"]["functions"].items()
                    ],
                ),
                library_functions=[
                    LibraryFunction(address=frz.Address.from_capa(address), name=name)
                    for address, name in meta["analysis"]["library_functions"].items()
                ],
            ),
        )


class StatementModel(FrozenModel):
    ...


class AndStatement(StatementModel):
    type = "and"
    description: Optional[str]


class OrStatement(StatementModel):
    type = "or"
    description: Optional[str]


class NotStatement(StatementModel):
    type = "not"
    description: Optional[str]


class SomeStatement(StatementModel):
    type = "some"
    description: Optional[str]
    count: int


class OptionalStatement(StatementModel):
    type = "optional"
    description: Optional[str]


class RangeStatement(StatementModel):
    type = "range"
    description: Optional[str]
    min: int
    max: int
    child: frz.Feature


class SubscopeStatement(StatementModel):
    type = "subscope"
    description: Optional[str]
    scope = capa.rules.Scope


Statement = Union[
    OptionalStatement,
    AndStatement,
    OrStatement,
    NotStatement,
    SomeStatement,
    RangeStatement,
    SubscopeStatement,
]


class StatementNode(FrozenModel):
    type = "statement"
    statement: Statement


def statement_from_capa(node: capa.engine.Statement) -> Statement:
    if isinstance(node, capa.engine.And):
        return AndStatement(description=node.description)

    elif isinstance(node, capa.engine.Or):
        return OrStatement(description=node.description)

    elif isinstance(node, capa.engine.Not):
        return NotStatement(description=node.description)

    elif isinstance(node, capa.engine.Some):
        if node.count == 0:
            return OptionalStatement(description=node.description)

        else:
            return SomeStatement(
                description=node.description,
                count=node.count,
            )

    elif isinstance(node, capa.engine.Range):
        return RangeStatement(
            description=node.description,
            min=node.min,
            max=node.max,
            child=frz.feature_from_capa(node.child),
        )

    elif isinstance(node, capa.engine.Subscope):
        return SubscopeStatement(
            description=node.description,
            scope=capa.rules.Scope(node.scope),
        )

    else:
        raise NotImplementedError(f"statement_from_capa({type(node)}) not implemented")


class FeatureNode(FrozenModel):
    type = "feature"
    feature: frz.Feature


Node = Union[StatementNode, FeatureNode]


def node_from_capa(node: Union[capa.engine.Statement, capa.engine.Feature]) -> Node:
    if isinstance(node, capa.engine.Statement):
        return StatementNode(statement=statement_from_capa(node))

    elif isinstance(node, capa.engine.Feature):
        return FeatureNode(feature=frz.feature_from_capa(node))

    else:
        assert_never(node)


class Match(BaseModel):
    """
    args:
      success: did the node match?
      node: the logic node or feature node.
      children: any children of the logic node. not relevent for features, can be empty.
      locations: where the feature matched. not relevant for logic nodes (except range), can be empty.
      captures: captured values from the string/regex feature, and the locations of those values.
    """

    success: bool
    node: Node
    children: Tuple["Match", ...]
    locations: Tuple[frz.Address, ...]
    captures: Dict[str, Tuple[frz.Address, ...]]

    @classmethod
    def from_capa(
        cls,
        rules: RuleSet,
        capabilities: MatchResults,
        result: capa.engine.Result,
    ) -> "Match":
        success = bool(result)

        node = node_from_capa(result.statement)
        children = [Match.from_capa(rules, capabilities, child) for child in result.children]

        # logic expression, like `and`, don't have locations - their children do.
        # so only add `locations` to feature nodes.
        locations = []
        if isinstance(node, FeatureNode) and success:
            locations = list(map(frz.Address.from_capa, result.locations))
        elif isinstance(node, StatementNode) and isinstance(node.statement, RangeStatement) and success:
            locations = list(map(frz.Address.from_capa, result.locations))

        captures = {}
        if isinstance(result.statement, (capa.features.common._MatchedSubstring, capa.features.common._MatchedRegex)):
            captures = {
                capture: list(map(frz.Address.from_capa, locs)) for capture, locs in result.statement.matches.items()
            }

        # if we have a `match` statement, then we're referencing another rule or namespace.
        # this could an external rule (written by a human), or
        #  rule generated to support a subscope (basic block, etc.)
        # we still want to include the matching logic in this tree.
        #
        # so, we need to lookup the other rule results
        # and then filter those down to the address used here.
        # finally, splice that logic into this tree.
        if (
            isinstance(node, FeatureNode)
            and isinstance(node.feature, frz.features.MatchFeature)
            # only add subtree on success,
            # because there won't be results for the other rule on failure.
            and success
        ):
            name = node.feature.match

            if name in rules:
                # this is a rule that we're matching
                #
                # pull matches from the referenced rule into our tree here.
                rule_name = name
                rule = rules[rule_name]
                rule_matches = {address: result for (address, result) in capabilities[rule_name]}

                if rule.is_subscope_rule():
                    # for a subscope rule, fixup the node to be a scope node, rather than a match feature node.
                    #
                    # e.g. `contain loop/30c4c78e29bf4d54894fc74f664c62e8` -> `basic block`
                    #
                    # note! replace `node`
                    node = StatementNode(
                        statement=SubscopeStatement(
                            scope=rule.meta["scope"],
                        )
                    )

                for location in result.locations:
                    children.append(Match.from_capa(rules, capabilities, rule_matches[location]))
            else:
                # this is a namespace that we're matching
                #
                # check for all rules in the namespace,
                # seeing if they matched.
                # if so, pull their matches into our match tree here.
                ns_name = name
                ns_rules = rules.rules_by_namespace[ns_name]

                for rule in ns_rules:
                    if rule.name in capabilities:
                        # the rule matched, so splice results into our tree here.
                        #
                        # note, there's a shortcoming in our result document schema here:
                        # we lose the name of the rule that matched in a namespace.
                        # for example, if we have a statement: `match: runtime/dotnet`
                        # and we get matches, we can say the following:
                        #
                        #     match: runtime/dotnet @ 0x0
                        #       or:
                        #         import: mscoree._CorExeMain @ 0x402000
                        #
                        # however, we lose the fact that it was rule
                        #   "compiled to the .NET platform"
                        # that contained this logic and did the match.
                        #
                        # we could introduce an intermediate node here.
                        # this would be a breaking change and require updates to the renderers.
                        # in the meantime, the above might be sufficient.
                        rule_matches = {address: result for (address, result) in capabilities[rule.name]}
                        for location in result.locations:
                            # doc[locations] contains all matches for the given namespace.
                            # for example, the feature might be `match: anti-analysis/packer`
                            # which matches against "generic unpacker" and "UPX".
                            # in this case, doc[locations] contains locations for *both* of thse.
                            #
                            # rule_matches contains the matches for the specific rule.
                            # this is a subset of doc[locations].
                            #
                            # so, grab only the locations for current rule.
                            if location in rule_matches:
                                children.append(Match.from_capa(rules, capabilities, rule_matches[location]))

        return cls(
            success=success,
            node=node,
            children=children,
            locations=locations,
            captures=captures,
        )


def parse_parts_id(s: str):
    id = ""
    parts = s.split("::")
    if len(parts) > 0:
        last = parts.pop()
        last, _, id = last.rpartition(" ")
        id = id.lstrip("[").rstrip("]")
        parts.append(last)
    return parts, id


class AttackSpec(FrozenModel):
    """
    given an ATT&CK spec like: `Tactic::Technique::Subtechnique [Identifier]`
    e.g., `Execution::Command and Scripting Interpreter::Python [T1059.006]`

    args:
      tactic: like `Tactic` above, perhaps "Execution"
      technique: like `Technique` above, perhaps "Command and Scripting Interpreter"
      subtechnique: like `Subtechnique` above, perhaps "Python"
      id: like `Identifier` above, perhaps "T1059.006"
    """

    parts: Tuple[str, ...]
    tactic: str
    technique: str
    subtechnique: str
    id: str

    @classmethod
    def from_str(cls, s) -> "AttackSpec":
        tactic = ""
        technique = ""
        subtechnique = ""
        parts, id = parse_parts_id(s)
        if len(parts) > 0:
            tactic = parts[0]
        if len(parts) > 1:
            technique = parts[1]
        if len(parts) > 2:
            subtechnique = parts[2]

        return cls(
            parts=parts,
            tactic=tactic,
            technique=technique,
            subtechnique=subtechnique,
            id=id,
        )


class MBCSpec(FrozenModel):
    """
    given an MBC spec like: `Objective::Behavior::Method [Identifier]`
    e.g., `Collection::Input Capture::Mouse Events [E1056.m01]`

    args:
      objective: like `Objective` above, perhaps "Collection"
      behavior: like `Behavior` above, perhaps "Input Capture"
      method: like `Method` above, perhaps "Mouse Events"
      id: like `Identifier` above, perhaps "E1056.m01"
    """

    parts: Tuple[str, ...]
    objective: str
    behavior: str
    method: str
    id: str

    @classmethod
    def from_str(cls, s) -> "MBCSpec":
        objective = ""
        behavior = ""
        method = ""
        parts, id = parse_parts_id(s)
        if len(parts) > 0:
            objective = parts[0]
        if len(parts) > 1:
            behavior = parts[1]
        if len(parts) > 2:
            method = parts[2]

        return cls(
            parts=parts,
            objective=objective,
            behavior=behavior,
            method=method,
            id=id,
        )


class MaecMetadata(FrozenModel):
    analysis_conclusion: Optional[str] = Field(None, alias="analysis-conclusion")
    analysis_conclusion_ov: Optional[str] = Field(None, alias="analysis-conclusion-ov")
    malware_family: Optional[str] = Field(None, alias="malware-family")
    malware_category: Optional[str] = Field(None, alias="malware-category")
    malware_category_ov: Optional[str] = Field(None, alias="malware-category-ov")

    class Config:
        frozen = True
        allow_population_by_field_name = True


class RuleMetadata(FrozenModel):
    name: str
    namespace: Optional[str]
    authors: Tuple[str, ...]
    scope: capa.rules.Scope
    attack: Tuple[AttackSpec, ...] = Field(alias="att&ck")
    mbc: Tuple[MBCSpec, ...]
    references: Tuple[str, ...]
    examples: Tuple[str, ...]
    description: str

    lib: bool = Field(False, alias="lib")
    is_subscope_rule: bool = Field(False, alias="capa/subscope")
    maec: MaecMetadata

    @classmethod
    def from_capa(cls, rule: capa.rules.Rule) -> "RuleMetadata":
        return cls(
            name=rule.meta.get("name"),
            namespace=rule.meta.get("namespace"),
            authors=rule.meta.get("authors"),
            scope=capa.rules.Scope(rule.meta.get("scope")),
            attack=list(map(AttackSpec.from_str, rule.meta.get("att&ck", []))),
            mbc=list(map(MBCSpec.from_str, rule.meta.get("mbc", []))),
            references=rule.meta.get("references", []),
            examples=rule.meta.get("examples", []),
            description=rule.meta.get("description", ""),
            lib=rule.meta.get("lib", False),
            capa_subscope=rule.meta.get("capa/subscope", False),
            maec=MaecMetadata(
                analysis_conclusion=rule.meta.get("maec/analysis-conclusion"),
                analysis_conclusion_ov=rule.meta.get("maec/analysis-conclusion-ov"),
                malware_family=rule.meta.get("maec/malware-family"),
                malware_category=rule.meta.get("maec/malware-category"),
                malware_category_ov=rule.meta.get("maec/malware-category-ov"),
            ),
        )

    class Config:
        frozen = True
        allow_population_by_field_name = True


class RuleMatches(BaseModel):
    """
    args:
        meta: the metadata from the rule
        source: the raw rule text
    """

    meta: RuleMetadata
    source: str
    matches: Tuple[Tuple[frz.Address, Match], ...]


class ResultDocument(BaseModel):
    meta: Metadata
    rules: Dict[str, RuleMatches]

    @classmethod
    def from_capa(cls, meta, rules: RuleSet, capabilities: MatchResults) -> "ResultDocument":
        rule_matches: Dict[str, RuleMatches] = {}
        for rule_name, matches in capabilities.items():
            rule = rules[rule_name]

            if rule.meta.get("capa/subscope-rule"):
                continue

            rule_matches[rule_name] = RuleMatches(
                meta=RuleMetadata.from_capa(rule),
                source=rule.definition,
                matches=[
                    (frz.Address.from_capa(addr), Match.from_capa(rules, capabilities, match))
                    for addr, match in matches
                ],
            )

        return ResultDocument(meta=Metadata.from_capa(meta), rules=rule_matches)
