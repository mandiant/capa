# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import datetime
import collections
from typing import Any, Dict, List, Tuple, Union, Optional

from pydantic import Field, BaseModel

import capa.rules
import capa.engine
import capa.features.common
import capa.features.freeze as frz
import capa.features.address
import capa.features.freeze.features as frzf
from capa.rules import RuleSet
from capa.engine import MatchResults
from capa.helpers import assert_never


class FrozenModel(BaseModel):
    class Config:
        frozen = True
        extra = "forbid"


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
                    functions=tuple(
                        FunctionLayout(
                            address=frz.Address.from_capa(address),
                            matched_basic_blocks=tuple(
                                BasicBlockLayout(address=frz.Address.from_capa(bb)) for bb in f["matched_basic_blocks"]
                            ),
                        )
                        for address, f in meta["analysis"]["layout"]["functions"].items()
                    )
                ),
                feature_counts=FeatureCounts(
                    file=meta["analysis"]["feature_counts"]["file"],
                    functions=tuple(
                        FunctionFeatureCount(address=frz.Address.from_capa(address), count=count)
                        for address, count in meta["analysis"]["feature_counts"]["functions"].items()
                    ),
                ),
                library_functions=tuple(
                    LibraryFunction(address=frz.Address.from_capa(address), name=name)
                    for address, name in meta["analysis"]["library_functions"].items()
                ),
            ),
        )

    def to_capa(self) -> Dict[str, Any]:
        capa_meta = {
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
            "sample": {
                "md5": self.sample.md5,
                "sha1": self.sample.sha1,
                "sha256": self.sample.sha256,
                "path": self.sample.path,
            },
            "analysis": {
                "format": self.analysis.format,
                "arch": self.analysis.arch,
                "os": self.analysis.os,
                "extractor": self.analysis.extractor,
                "rules": self.analysis.rules,
                "base_address": self.analysis.base_address.to_capa(),
                "layout": {
                    "functions": {
                        f.address.to_capa(): {
                            "matched_basic_blocks": [bb.address.to_capa() for bb in f.matched_basic_blocks]
                        }
                        for f in self.analysis.layout.functions
                    }
                },
                "feature_counts": {
                    "file": self.analysis.feature_counts.file,
                    "functions": {fc.address.to_capa(): fc.count for fc in self.analysis.feature_counts.functions},
                },
                "library_functions": {lf.address.to_capa(): lf.name for lf in self.analysis.library_functions},
            },
        }

        return capa_meta


class CompoundStatementType:
    AND = "and"
    OR = "or"
    NOT = "not"
    OPTIONAL = "optional"


class StatementModel(FrozenModel):
    ...


class CompoundStatement(StatementModel):
    type: str
    description: Optional[str] = None


class SomeStatement(StatementModel):
    type = "some"
    description: Optional[str] = None
    count: int


class RangeStatement(StatementModel):
    type = "range"
    description: Optional[str] = None
    min: int
    max: int
    child: frz.Feature


class SubscopeStatement(StatementModel):
    type = "subscope"
    description: Optional[str] = None
    scope: capa.rules.Scope


Statement = Union[
    # Note! order matters, see #1161
    RangeStatement,
    SomeStatement,
    SubscopeStatement,
    CompoundStatement,
]


class StatementNode(FrozenModel):
    type = "statement"
    statement: Statement


def statement_from_capa(node: capa.engine.Statement) -> Statement:
    if isinstance(node, (capa.engine.And, capa.engine.Or, capa.engine.Not)):
        return CompoundStatement(type=node.__class__.__name__.lower(), description=node.description)

    elif isinstance(node, capa.engine.Some):
        if node.count == 0:
            return CompoundStatement(type=CompoundStatementType.OPTIONAL, description=node.description)

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


def node_to_capa(
    node: Node, children: List[Union[capa.engine.Statement, capa.engine.Feature]]
) -> Union[capa.engine.Statement, capa.engine.Feature]:
    if isinstance(node, StatementNode):
        if isinstance(node.statement, CompoundStatement):
            if node.statement.type == CompoundStatementType.AND:
                return capa.engine.And(description=node.statement.description, children=children)

            elif node.statement.type == CompoundStatementType.OR:
                return capa.engine.Or(description=node.statement.description, children=children)

            elif node.statement.type == CompoundStatementType.NOT:
                return capa.engine.Not(description=node.statement.description, child=children[0])

            elif node.statement.type == CompoundStatementType.OPTIONAL:
                return capa.engine.Some(description=node.statement.description, count=0, children=children)

            else:
                assert_never(node.statement.type)

        elif isinstance(node.statement, SomeStatement):
            return capa.engine.Some(
                description=node.statement.description, count=node.statement.count, children=children
            )

        elif isinstance(node.statement, RangeStatement):
            return capa.engine.Range(
                description=node.statement.description,
                min=node.statement.min,
                max=node.statement.max,
                child=node.statement.child.to_capa(),
            )

        elif isinstance(node.statement, SubscopeStatement):
            return capa.engine.Subscope(
                description=node.statement.description, scope=node.statement.scope, child=children[0]
            )

        else:
            assert_never(node.statement)

    elif isinstance(node, FeatureNode):
        return node.feature.to_capa()

    else:
        assert_never(node)


class Match(FrozenModel):
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
            and isinstance(node.feature, frzf.MatchFeature)
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
            children=tuple(children),
            locations=tuple(locations),
            captures={capture: tuple(captures[capture]) for capture in captures},
        )

    def to_capa(self, rules_by_name: Dict[str, capa.rules.Rule]) -> capa.engine.Result:
        children = [child.to_capa(rules_by_name) for child in self.children]
        statement = node_to_capa(self.node, [child.statement for child in children])

        if isinstance(self.node, FeatureNode):
            feature = self.node.feature

            if isinstance(feature, (frzf.SubstringFeature, frzf.RegexFeature)):
                matches = {capture: {loc.to_capa() for loc in locs} for capture, locs in self.captures.items()}

                if isinstance(feature, frzf.SubstringFeature):
                    assert isinstance(statement, capa.features.common.Substring)
                    statement = capa.features.common._MatchedSubstring(statement, matches)
                elif isinstance(feature, frzf.RegexFeature):
                    assert isinstance(statement, capa.features.common.Regex)
                    statement = capa.features.common._MatchedRegex(statement, matches)
                else:
                    assert_never(feature)

        # apparently we don't have to fixup match and subscope entries here.
        # at least, default, verbose, and vverbose renderers seem to work well without any special handling here.
        #
        # children contains a single tree of results, corresponding to the logic of the matched rule.
        # self.node.feature.match contains the name of the rule that was matched.
        # so its all available to reconstruct, if necessary.

        return capa.features.common.Result(
            success=self.success,
            statement=statement,
            locations={loc.to_capa() for loc in self.locations},
            children=children,
        )


def parse_parts_id(s: str):
    id_ = ""
    parts = s.split("::")
    if len(parts) > 0:
        last = parts.pop()
        last, _, id_ = last.rpartition(" ")
        id_ = id_.lstrip("[").rstrip("]")
        parts.append(last)
    return tuple(parts), id_


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
        parts, id_ = parse_parts_id(s)
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
            id=id_,
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
        parts, id_ = parse_parts_id(s)
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
            id=id_,
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
            attack=tuple(map(AttackSpec.from_str, rule.meta.get("att&ck", []))),
            mbc=tuple(map(MBCSpec.from_str, rule.meta.get("mbc", []))),
            references=rule.meta.get("references", []),
            examples=rule.meta.get("examples", []),
            description=rule.meta.get("description", ""),
            lib=rule.meta.get("lib", False),
            is_subscope_rule=rule.meta.get("capa/subscope", False),
            maec=MaecMetadata(
                analysis_conclusion=rule.meta.get("maec/analysis-conclusion"),
                analysis_conclusion_ov=rule.meta.get("maec/analysis-conclusion-ov"),
                malware_family=rule.meta.get("maec/malware-family"),
                malware_category=rule.meta.get("maec/malware-category"),
                malware_category_ov=rule.meta.get("maec/malware-category-ov"),
            ),  # type: ignore
            # Mypy is unable to recognise arguments due to alias
        )  # type: ignore
        # Mypy is unable to recognise arguments due to alias

    class Config:
        frozen = True
        allow_population_by_field_name = True


class RuleMatches(FrozenModel):
    """
    args:
        meta: the metadata from the rule
        source: the raw rule text
    """

    meta: RuleMetadata
    source: str
    matches: Tuple[Tuple[frz.Address, Match], ...]


class ResultDocument(FrozenModel):
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
                matches=tuple(
                    (frz.Address.from_capa(addr), Match.from_capa(rules, capabilities, match))
                    for addr, match in matches
                ),
            )

        return ResultDocument(meta=Metadata.from_capa(meta), rules=rule_matches)

    def to_capa(self) -> Tuple[Dict, Dict]:
        meta = self.meta.to_capa()
        capabilities: Dict[
            str, List[Tuple[capa.features.address.Address, capa.features.common.Result]]
        ] = collections.defaultdict(list)

        # this doesn't quite work because we don't have the rule source for rules that aren't matched.
        rules_by_name = {
            rule_name: capa.rules.Rule.from_yaml(rule_match.source) for rule_name, rule_match in self.rules.items()
        }

        for rule_name, rule_match in self.rules.items():
            for addr, match in rule_match.matches:
                result: capa.engine.Result = match.to_capa(rules_by_name)

                capabilities[rule_name].append((addr.to_capa(), result))

        return meta, capabilities
