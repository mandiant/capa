# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Convert capa results to protobuf format.
The functionality here is similar to the various *from_capa functions, e.g. ResultDocument.from_capa() or
feature_from_capa.

For few classes we can rely on the proto json parser (e.g. RuleMetadata).

For most classes (e.g. RuleMatches) conversion is tricky, because we use natively unsupported types (e.g. tuples),
several classes with unions, and more complex layouts. So, it's more straight forward to convert explicitly vs.
massaging the data so the protobuf json parser works.

Of note, the 3 in `syntax = "proto3"` has nothing to do with the 2 in capa_pb2.py;
see details in https://github.com/grpc/grpc/issues/15444#issuecomment-396442980.

First compile the protobuf to generate an API file and a mypy stub file
$ protoc.exe --python_out=. --mypy_out=. <path_to_proto> (e.g. capa/render/proto/capa.proto)

Alternatively, --pyi_out=. can be used to generate a Python Interface file that supports development
"""
import datetime
from typing import Any, Union

import google.protobuf.json_format

import capa.rules
import capa.features.freeze as frz
import capa.render.proto.capa_pb2 as capa_pb2
import capa.render.result_document as rd
import capa.features.freeze.features as frzf
from capa.helpers import assert_never
from capa.features.freeze import AddressType


def int_to_pb2(v: int) -> capa_pb2.Integer:
    if v < -2_147_483_648:
        raise ValueError(f"value underflow: {v}")
    if v > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"value overflow: {v}")

    if v < 0:
        return capa_pb2.Integer(i=v)
    else:
        return capa_pb2.Integer(u=v)


def number_to_pb2(v: Union[int, float]) -> capa_pb2.Number:
    if isinstance(v, float):
        return capa_pb2.Number(f=v)
    elif isinstance(v, int):
        i = int_to_pb2(v)
        if v < 0:
            return capa_pb2.Number(i=i.i)
        else:
            return capa_pb2.Number(u=i.u)
    else:
        assert_never(v)


def addr_to_pb2(addr: frz.Address) -> capa_pb2.Address:
    if addr.type is AddressType.ABSOLUTE:
        assert isinstance(addr.value, int)
        return capa_pb2.Address(type=capa_pb2.AddressType.ADDRESSTYPE_ABSOLUTE, v=int_to_pb2(addr.value))

    elif addr.type is AddressType.RELATIVE:
        assert isinstance(addr.value, int)
        return capa_pb2.Address(type=capa_pb2.AddressType.ADDRESSTYPE_RELATIVE, v=int_to_pb2(addr.value))

    elif addr.type is AddressType.FILE:
        assert isinstance(addr.value, int)
        return capa_pb2.Address(type=capa_pb2.AddressType.ADDRESSTYPE_FILE, v=int_to_pb2(addr.value))

    elif addr.type is AddressType.DN_TOKEN:
        assert isinstance(addr.value, int)
        return capa_pb2.Address(type=capa_pb2.AddressType.ADDRESSTYPE_DN_TOKEN, v=int_to_pb2(addr.value))

    elif addr.type is AddressType.DN_TOKEN_OFFSET:
        assert isinstance(addr.value, tuple)
        token, offset = addr.value
        assert isinstance(token, int)
        assert isinstance(offset, int)
        return capa_pb2.Address(
            type=capa_pb2.AddressType.ADDRESSTYPE_DN_TOKEN_OFFSET,
            token_offset=capa_pb2.Token_Offset(token=int_to_pb2(token), offset=offset),
        )

    elif addr.type is AddressType.PROCESS:
        assert isinstance(addr.value, tuple)
        ppid, pid = addr.value
        assert isinstance(ppid, int)
        assert isinstance(pid, int)
        return capa_pb2.Address(
            type=capa_pb2.AddressType.ADDRESSTYPE_PROCESS,
            ppid_pid=capa_pb2.Ppid_Pid(
                ppid=int_to_pb2(ppid),
                pid=int_to_pb2(pid),
            ),
        )

    elif addr.type is AddressType.THREAD:
        assert isinstance(addr.value, tuple)
        ppid, pid, tid = addr.value
        assert isinstance(ppid, int)
        assert isinstance(pid, int)
        assert isinstance(tid, int)
        return capa_pb2.Address(
            type=capa_pb2.AddressType.ADDRESSTYPE_THREAD,
            ppid_pid_tid=capa_pb2.Ppid_Pid_Tid(
                ppid=int_to_pb2(ppid),
                pid=int_to_pb2(pid),
                tid=int_to_pb2(tid),
            ),
        )

    elif addr.type is AddressType.CALL:
        assert isinstance(addr.value, tuple)
        ppid, pid, tid, id_ = addr.value
        assert isinstance(ppid, int)
        assert isinstance(pid, int)
        assert isinstance(tid, int)
        assert isinstance(id_, int)
        return capa_pb2.Address(
            type=capa_pb2.AddressType.ADDRESSTYPE_CALL,
            ppid_pid_tid_id=capa_pb2.Ppid_Pid_Tid_Id(
                ppid=int_to_pb2(ppid),
                pid=int_to_pb2(pid),
                tid=int_to_pb2(tid),
                id=int_to_pb2(id_),
            ),
        )

    elif addr.type is AddressType.NO_ADDRESS:
        # value == None, so only set type
        return capa_pb2.Address(type=capa_pb2.AddressType.ADDRESSTYPE_NO_ADDRESS)

    else:
        assert_never(addr)


def scope_to_pb2(scope: capa.rules.Scope) -> capa_pb2.Scope.ValueType:
    if scope == capa.rules.Scope.FILE:
        return capa_pb2.Scope.SCOPE_FILE
    elif scope == capa.rules.Scope.FUNCTION:
        return capa_pb2.Scope.SCOPE_FUNCTION
    elif scope == capa.rules.Scope.BASIC_BLOCK:
        return capa_pb2.Scope.SCOPE_BASIC_BLOCK
    elif scope == capa.rules.Scope.INSTRUCTION:
        return capa_pb2.Scope.SCOPE_INSTRUCTION
    elif scope == capa.rules.Scope.PROCESS:
        return capa_pb2.Scope.SCOPE_PROCESS
    elif scope == capa.rules.Scope.THREAD:
        return capa_pb2.Scope.SCOPE_THREAD
    elif scope == capa.rules.Scope.SPAN_OF_CALLS:
        return capa_pb2.Scope.SCOPE_SPAN_OF_CALLS
    elif scope == capa.rules.Scope.CALL:
        return capa_pb2.Scope.SCOPE_CALL
    else:
        assert_never(scope)


def scopes_to_pb2(scopes: capa.rules.Scopes) -> capa_pb2.Scopes:
    doc = {}
    if scopes.static:
        doc["static"] = scope_to_pb2(scopes.static)
    if scopes.dynamic:
        doc["dynamic"] = scope_to_pb2(scopes.dynamic)

    return google.protobuf.json_format.ParseDict(doc, capa_pb2.Scopes())


def flavor_to_pb2(flavor: rd.Flavor) -> capa_pb2.Flavor.ValueType:
    if flavor == rd.Flavor.STATIC:
        return capa_pb2.Flavor.FLAVOR_STATIC
    elif flavor == rd.Flavor.DYNAMIC:
        return capa_pb2.Flavor.FLAVOR_DYNAMIC
    else:
        assert_never(flavor)


def static_analysis_to_pb2(analysis: rd.StaticAnalysis) -> capa_pb2.StaticAnalysis:
    return capa_pb2.StaticAnalysis(
        format=analysis.format,
        arch=analysis.arch,
        os=analysis.os,
        extractor=analysis.extractor,
        rules=list(analysis.rules),
        base_address=addr_to_pb2(analysis.base_address),
        layout=capa_pb2.StaticLayout(
            functions=[
                capa_pb2.FunctionLayout(
                    address=addr_to_pb2(f.address),
                    matched_basic_blocks=[
                        capa_pb2.BasicBlockLayout(address=addr_to_pb2(bb.address)) for bb in f.matched_basic_blocks
                    ],
                )
                for f in analysis.layout.functions
            ]
        ),
        feature_counts=capa_pb2.StaticFeatureCounts(
            file=analysis.feature_counts.file,
            functions=[
                capa_pb2.FunctionFeatureCount(address=addr_to_pb2(f.address), count=f.count)
                for f in analysis.feature_counts.functions
            ],
        ),
        library_functions=[
            capa_pb2.LibraryFunction(address=addr_to_pb2(lf.address), name=lf.name) for lf in analysis.library_functions
        ],
    )


def dynamic_analysis_to_pb2(analysis: rd.DynamicAnalysis) -> capa_pb2.DynamicAnalysis:
    return capa_pb2.DynamicAnalysis(
        format=analysis.format,
        arch=analysis.arch,
        os=analysis.os,
        extractor=analysis.extractor,
        rules=list(analysis.rules),
        layout=capa_pb2.DynamicLayout(
            processes=[
                capa_pb2.ProcessLayout(
                    address=addr_to_pb2(p.address),
                    name=p.name,
                    matched_threads=[
                        capa_pb2.ThreadLayout(
                            address=addr_to_pb2(t.address),
                            matched_calls=[
                                capa_pb2.CallLayout(
                                    address=addr_to_pb2(c.address),
                                    name=c.name,
                                )
                                for c in t.matched_calls
                            ],
                        )
                        for t in p.matched_threads
                    ],
                )
                for p in analysis.layout.processes
            ]
        ),
        feature_counts=capa_pb2.DynamicFeatureCounts(
            file=analysis.feature_counts.file,
            processes=[
                capa_pb2.ProcessFeatureCount(address=addr_to_pb2(p.address), count=p.count)
                for p in analysis.feature_counts.processes
            ],
        ),
    )


def metadata_to_pb2(meta: rd.Metadata) -> capa_pb2.Metadata:
    if isinstance(meta.analysis, rd.StaticAnalysis):
        return capa_pb2.Metadata(
            timestamp=str(meta.timestamp),
            version=meta.version,
            argv=meta.argv,
            sample=google.protobuf.json_format.ParseDict(meta.sample.model_dump(), capa_pb2.Sample()),
            flavor=flavor_to_pb2(meta.flavor),
            static_analysis=static_analysis_to_pb2(meta.analysis),
        )
    elif isinstance(meta.analysis, rd.DynamicAnalysis):
        return capa_pb2.Metadata(
            timestamp=str(meta.timestamp),
            version=meta.version,
            argv=meta.argv,
            sample=google.protobuf.json_format.ParseDict(meta.sample.model_dump(), capa_pb2.Sample()),
            flavor=flavor_to_pb2(meta.flavor),
            dynamic_analysis=dynamic_analysis_to_pb2(meta.analysis),
        )
    else:
        assert_never(meta.analysis)


def statement_to_pb2(statement: rd.Statement) -> capa_pb2.StatementNode:
    if isinstance(statement, rd.RangeStatement):
        return capa_pb2.StatementNode(
            range=capa_pb2.RangeStatement(
                type="range",
                description=statement.description,
                min=statement.min,
                max=statement.max,
                child=feature_to_pb2(statement.child),
            ),
            type="statement",
        )

    elif isinstance(statement, rd.SomeStatement):
        return capa_pb2.StatementNode(
            some=capa_pb2.SomeStatement(type=statement.type, description=statement.description, count=statement.count),
            type="statement",
        )

    elif isinstance(statement, rd.SubscopeStatement):
        return capa_pb2.StatementNode(
            subscope=capa_pb2.SubscopeStatement(
                type=statement.type,
                description=statement.description,
                scope=scope_to_pb2(statement.scope),
            ),
            type="statement",
        )

    elif isinstance(statement, rd.CompoundStatement):
        return capa_pb2.StatementNode(
            compound=capa_pb2.CompoundStatement(type=statement.type, description=statement.description),
            type="statement",
        )

    else:
        assert_never(statement)


def feature_to_pb2(f: frzf.Feature) -> capa_pb2.FeatureNode:
    if isinstance(f, frzf.OSFeature):
        return capa_pb2.FeatureNode(
            type="feature", os=capa_pb2.OSFeature(type=f.type, os=f.os, description=f.description)
        )

    elif isinstance(f, frzf.ArchFeature):
        return capa_pb2.FeatureNode(
            type="feature", arch=capa_pb2.ArchFeature(type=f.type, arch=f.arch, description=f.description)
        )

    elif isinstance(f, frzf.FormatFeature):
        return capa_pb2.FeatureNode(
            type="feature", format=capa_pb2.FormatFeature(type=f.type, format=f.format, description=f.description)
        )

    elif isinstance(f, frzf.MatchFeature):
        return capa_pb2.FeatureNode(
            type="feature",
            match=capa_pb2.MatchFeature(
                type=f.type,
                match=f.match,
                description=f.description,
            ),
        )

    elif isinstance(f, frzf.CharacteristicFeature):
        return capa_pb2.FeatureNode(
            type="feature",
            characteristic=capa_pb2.CharacteristicFeature(
                type=f.type, characteristic=f.characteristic, description=f.description
            ),
        )

    elif isinstance(f, frzf.ExportFeature):
        return capa_pb2.FeatureNode(
            type="feature", export=capa_pb2.ExportFeature(type=f.type, export=f.export, description=f.description)
        )

    elif isinstance(f, frzf.ImportFeature):
        return capa_pb2.FeatureNode(
            type="feature", import_=capa_pb2.ImportFeature(type=f.type, import_=f.import_, description=f.description)
        )

    elif isinstance(f, frzf.SectionFeature):
        return capa_pb2.FeatureNode(
            type="feature", section=capa_pb2.SectionFeature(type=f.type, section=f.section, description=f.description)
        )

    elif isinstance(f, frzf.FunctionNameFeature):
        return capa_pb2.FeatureNode(
            type="function name",
            function_name=capa_pb2.FunctionNameFeature(
                type=f.type, function_name=f.function_name, description=f.description
            ),
        )

    elif isinstance(f, frzf.SubstringFeature):
        return capa_pb2.FeatureNode(
            type="feature",
            substring=capa_pb2.SubstringFeature(type=f.type, substring=f.substring, description=f.description),
        )

    elif isinstance(f, frzf.RegexFeature):
        return capa_pb2.FeatureNode(
            type="feature", regex=capa_pb2.RegexFeature(type=f.type, regex=f.regex, description=f.description)
        )

    elif isinstance(f, frzf.StringFeature):
        return capa_pb2.FeatureNode(
            type="feature",
            string=capa_pb2.StringFeature(
                type=f.type,
                string=f.string,
                description=f.description,
            ),
        )

    elif isinstance(f, frzf.ClassFeature):
        return capa_pb2.FeatureNode(
            type="feature", class_=capa_pb2.ClassFeature(type=f.type, class_=f.class_, description=f.description)
        )

    elif isinstance(f, frzf.NamespaceFeature):
        return capa_pb2.FeatureNode(
            type="feature",
            namespace=capa_pb2.NamespaceFeature(type=f.type, namespace=f.namespace, description=f.description),
        )

    elif isinstance(f, frzf.APIFeature):
        return capa_pb2.FeatureNode(
            type="feature", api=capa_pb2.APIFeature(type=f.type, api=f.api, description=f.description)
        )

    elif isinstance(f, frzf.PropertyFeature):
        return capa_pb2.FeatureNode(
            type="feature",
            property_=capa_pb2.PropertyFeature(
                type=f.type, access=f.access, property_=f.property, description=f.description
            ),
        )

    elif isinstance(f, frzf.NumberFeature):
        return capa_pb2.FeatureNode(
            type="feature",
            number=capa_pb2.NumberFeature(type=f.type, number=number_to_pb2(f.number), description=f.description),
        )

    elif isinstance(f, frzf.BytesFeature):
        return capa_pb2.FeatureNode(
            type="feature", bytes=capa_pb2.BytesFeature(type=f.type, bytes=f.bytes, description=f.description)
        )

    elif isinstance(f, frzf.OffsetFeature):
        return capa_pb2.FeatureNode(
            type="feature",
            offset=capa_pb2.OffsetFeature(type=f.type, offset=int_to_pb2(f.offset), description=f.description),
        )

    elif isinstance(f, frzf.MnemonicFeature):
        return capa_pb2.FeatureNode(
            type="feature",
            mnemonic=capa_pb2.MnemonicFeature(type=f.type, mnemonic=f.mnemonic, description=f.description),
        )

    elif isinstance(f, frzf.OperandNumberFeature):
        return capa_pb2.FeatureNode(
            type="feature",
            operand_number=capa_pb2.OperandNumberFeature(
                type=f.type, index=f.index, operand_number=int_to_pb2(f.operand_number), description=f.description
            ),
        )

    elif isinstance(f, frzf.OperandOffsetFeature):
        return capa_pb2.FeatureNode(
            type="feature",
            operand_offset=capa_pb2.OperandOffsetFeature(
                type=f.type, index=f.index, operand_offset=int_to_pb2(f.operand_offset), description=f.description
            ),
        )

    elif isinstance(f, frzf.BasicBlockFeature):
        return capa_pb2.FeatureNode(
            type="feature", basic_block=capa_pb2.BasicBlockFeature(type=f.type, description=f.description)
        )

    else:
        assert_never(f)


def node_to_pb2(node: rd.Node) -> Union[capa_pb2.FeatureNode, capa_pb2.StatementNode]:
    if isinstance(node, rd.StatementNode):
        return statement_to_pb2(node.statement)

    elif isinstance(node, rd.FeatureNode):
        return feature_to_pb2(node.feature)

    else:
        assert_never(node)


def match_to_pb2(match: rd.Match) -> capa_pb2.Match:
    node = node_to_pb2(match.node)
    children = list(map(match_to_pb2, match.children))
    locations = list(map(addr_to_pb2, match.locations))

    if isinstance(node, capa_pb2.StatementNode):
        return capa_pb2.Match(
            success=match.success,
            statement=node,
            children=children,
            locations=locations,
            captures={},
        )

    elif isinstance(node, capa_pb2.FeatureNode):
        return capa_pb2.Match(
            success=match.success,
            feature=node,
            children=children,
            locations=locations,
            captures={
                capture: capa_pb2.Addresses(address=list(map(addr_to_pb2, locs)))
                for capture, locs in match.captures.items()
            },
        )

    else:
        assert_never(match)


def attack_to_pb2(attack: rd.AttackSpec) -> capa_pb2.AttackSpec:
    return capa_pb2.AttackSpec(
        parts=list(attack.parts),
        tactic=attack.tactic,
        technique=attack.technique,
        subtechnique=attack.subtechnique,
        id=attack.id,
    )


def mbc_to_pb2(mbc: rd.MBCSpec) -> capa_pb2.MBCSpec:
    return capa_pb2.MBCSpec(
        parts=list(mbc.parts),
        objective=mbc.objective,
        behavior=mbc.behavior,
        method=mbc.method,
        id=mbc.id,
    )


def maec_to_pb2(maec: rd.MaecMetadata) -> capa_pb2.MaecMetadata:
    return capa_pb2.MaecMetadata(
        analysis_conclusion=maec.analysis_conclusion or "",
        analysis_conclusion_ov=maec.analysis_conclusion_ov or "",
        malware_family=maec.malware_family or "",
        malware_category=maec.malware_category or "",
        malware_category_ov=maec.malware_category_ov or "",
    )


def rule_metadata_to_pb2(rule_metadata: rd.RuleMetadata) -> capa_pb2.RuleMetadata:
    return capa_pb2.RuleMetadata(
        name=rule_metadata.name,
        namespace=rule_metadata.namespace or "",
        authors=rule_metadata.authors,
        attack=[attack_to_pb2(m) for m in rule_metadata.attack],
        mbc=[mbc_to_pb2(m) for m in rule_metadata.mbc],
        references=rule_metadata.references,
        examples=rule_metadata.examples,
        description=rule_metadata.description,
        lib=rule_metadata.lib,
        maec=maec_to_pb2(rule_metadata.maec),
        is_subscope_rule=rule_metadata.is_subscope_rule,
        scopes=scopes_to_pb2(rule_metadata.scopes),
    )


def doc_to_pb2(doc: rd.ResultDocument) -> capa_pb2.ResultDocument:
    rule_matches: dict[str, capa_pb2.RuleMatches] = {}
    for rule_name, matches in doc.rules.items():
        m = capa_pb2.RuleMatches(
            meta=rule_metadata_to_pb2(matches.meta),
            source=matches.source,
            matches=[
                capa_pb2.Pair_Address_Match(address=addr_to_pb2(addr), match=match_to_pb2(match))
                for addr, match in matches.matches
            ],
        )
        rule_matches[rule_name] = m

    r = capa_pb2.ResultDocument(meta=metadata_to_pb2(doc.meta), rules=rule_matches)

    return r


def int_from_pb2(v: capa_pb2.Integer) -> int:
    type = v.WhichOneof("value")
    if type == "u":
        return v.u
    elif type == "i":
        return v.i
    else:
        assert_never(type)


def number_from_pb2(v: capa_pb2.Number) -> Union[int, float]:
    type = v.WhichOneof("value")
    if type == "u":
        return v.u
    elif type == "i":
        return v.i
    elif type == "f":
        return v.f
    else:
        assert_never(type)


def addr_from_pb2(addr: capa_pb2.Address) -> frz.Address:
    if addr.type == capa_pb2.AddressType.ADDRESSTYPE_ABSOLUTE:
        return frz.Address(type=frz.AddressType.ABSOLUTE, value=int_from_pb2(addr.v))

    elif addr.type == capa_pb2.AddressType.ADDRESSTYPE_RELATIVE:
        return frz.Address(type=frz.AddressType.RELATIVE, value=int_from_pb2(addr.v))

    elif addr.type == capa_pb2.AddressType.ADDRESSTYPE_FILE:
        return frz.Address(type=frz.AddressType.FILE, value=int_from_pb2(addr.v))

    elif addr.type == capa_pb2.AddressType.ADDRESSTYPE_DN_TOKEN:
        return frz.Address(type=frz.AddressType.DN_TOKEN, value=int_from_pb2(addr.v))

    elif addr.type == capa_pb2.AddressType.ADDRESSTYPE_DN_TOKEN_OFFSET:
        token = int_from_pb2(addr.token_offset.token)
        offset = addr.token_offset.offset
        return frz.Address(type=frz.AddressType.DN_TOKEN_OFFSET, value=(token, offset))

    elif addr.type == capa_pb2.AddressType.ADDRESSTYPE_PROCESS:
        ppid = int_from_pb2(addr.ppid_pid.ppid)
        pid = int_from_pb2(addr.ppid_pid.pid)
        return frz.Address(type=frz.AddressType.PROCESS, value=(ppid, pid))

    elif addr.type == capa_pb2.AddressType.ADDRESSTYPE_THREAD:
        ppid = int_from_pb2(addr.ppid_pid_tid.ppid)
        pid = int_from_pb2(addr.ppid_pid_tid.pid)
        tid = int_from_pb2(addr.ppid_pid_tid.tid)
        return frz.Address(type=frz.AddressType.THREAD, value=(ppid, pid, tid))

    elif addr.type == capa_pb2.AddressType.ADDRESSTYPE_CALL:
        ppid = int_from_pb2(addr.ppid_pid_tid_id.ppid)
        pid = int_from_pb2(addr.ppid_pid_tid_id.pid)
        tid = int_from_pb2(addr.ppid_pid_tid_id.tid)
        id_ = int_from_pb2(addr.ppid_pid_tid_id.id)
        return frz.Address(type=frz.AddressType.CALL, value=(ppid, pid, tid, id_))

    elif addr.type == capa_pb2.AddressType.ADDRESSTYPE_NO_ADDRESS:
        return frz.Address(type=frz.AddressType.NO_ADDRESS, value=None)

    else:
        assert_never(addr)


def scope_from_pb2(scope: capa_pb2.Scope.ValueType) -> capa.rules.Scope:
    if scope == capa_pb2.Scope.SCOPE_FILE:
        return capa.rules.Scope.FILE
    elif scope == capa_pb2.Scope.SCOPE_FUNCTION:
        return capa.rules.Scope.FUNCTION
    elif scope == capa_pb2.Scope.SCOPE_BASIC_BLOCK:
        return capa.rules.Scope.BASIC_BLOCK
    elif scope == capa_pb2.Scope.SCOPE_INSTRUCTION:
        return capa.rules.Scope.INSTRUCTION
    elif scope == capa_pb2.Scope.SCOPE_PROCESS:
        return capa.rules.Scope.PROCESS
    elif scope == capa_pb2.Scope.SCOPE_THREAD:
        return capa.rules.Scope.THREAD
    elif scope == capa_pb2.Scope.SCOPE_SPAN_OF_CALLS:
        return capa.rules.Scope.SPAN_OF_CALLS
    elif scope == capa_pb2.Scope.SCOPE_CALL:
        return capa.rules.Scope.CALL
    else:
        assert_never(scope)


def scopes_from_pb2(scopes: capa_pb2.Scopes) -> capa.rules.Scopes:
    return capa.rules.Scopes(
        static=scope_from_pb2(scopes.static) if scopes.static else None,
        dynamic=scope_from_pb2(scopes.dynamic) if scopes.dynamic else None,
    )


def flavor_from_pb2(flavor: capa_pb2.Flavor.ValueType) -> rd.Flavor:
    if flavor == capa_pb2.Flavor.FLAVOR_STATIC:
        return rd.Flavor.STATIC
    elif flavor == capa_pb2.Flavor.FLAVOR_DYNAMIC:
        return rd.Flavor.DYNAMIC
    else:
        assert_never(flavor)


def static_analysis_from_pb2(analysis: capa_pb2.StaticAnalysis) -> rd.StaticAnalysis:
    return rd.StaticAnalysis(
        format=analysis.format,
        arch=analysis.arch,
        os=analysis.os,
        extractor=analysis.extractor,
        rules=tuple(analysis.rules),
        base_address=addr_from_pb2(analysis.base_address),
        layout=rd.StaticLayout(
            functions=tuple(
                [
                    rd.FunctionLayout(
                        address=addr_from_pb2(f.address),
                        matched_basic_blocks=tuple(
                            [rd.BasicBlockLayout(address=addr_from_pb2(bb.address)) for bb in f.matched_basic_blocks]
                        ),
                    )
                    for f in analysis.layout.functions
                ]
            )
        ),
        feature_counts=rd.StaticFeatureCounts(
            file=analysis.feature_counts.file,
            functions=tuple(
                [
                    rd.FunctionFeatureCount(address=addr_from_pb2(f.address), count=f.count)
                    for f in analysis.feature_counts.functions
                ]
            ),
        ),
        library_functions=tuple(
            [rd.LibraryFunction(address=addr_from_pb2(lf.address), name=lf.name) for lf in analysis.library_functions]
        ),
    )


def dynamic_analysis_from_pb2(analysis: capa_pb2.DynamicAnalysis) -> rd.DynamicAnalysis:
    return rd.DynamicAnalysis(
        format=analysis.format,
        arch=analysis.arch,
        os=analysis.os,
        extractor=analysis.extractor,
        rules=tuple(analysis.rules),
        layout=rd.DynamicLayout(
            processes=tuple(
                [
                    rd.ProcessLayout(
                        address=addr_from_pb2(p.address),
                        name=p.name,
                        matched_threads=tuple(
                            [
                                rd.ThreadLayout(
                                    address=addr_from_pb2(t.address),
                                    matched_calls=tuple(
                                        [
                                            rd.CallLayout(address=addr_from_pb2(c.address), name=c.name)
                                            for c in t.matched_calls
                                        ]
                                    ),
                                )
                                for t in p.matched_threads
                            ]
                        ),
                    )
                    for p in analysis.layout.processes
                ]
            )
        ),
        feature_counts=rd.DynamicFeatureCounts(
            file=analysis.feature_counts.file,
            processes=tuple(
                [
                    rd.ProcessFeatureCount(address=addr_from_pb2(p.address), count=p.count)
                    for p in analysis.feature_counts.processes
                ]
            ),
        ),
    )


def metadata_from_pb2(meta: capa_pb2.Metadata) -> rd.Metadata:
    analysis_type = meta.WhichOneof("analysis2")
    if analysis_type == "static_analysis":
        return rd.Metadata(
            timestamp=datetime.datetime.fromisoformat(meta.timestamp),
            version=meta.version,
            argv=tuple(meta.argv) if meta.argv else None,
            sample=rd.Sample(
                md5=meta.sample.md5,
                sha1=meta.sample.sha1,
                sha256=meta.sample.sha256,
                path=meta.sample.path,
            ),
            flavor=flavor_from_pb2(meta.flavor),
            analysis=static_analysis_from_pb2(meta.static_analysis),
        )
    elif analysis_type == "dynamic_analysis":
        return rd.Metadata(
            timestamp=datetime.datetime.fromisoformat(meta.timestamp),
            version=meta.version,
            argv=tuple(meta.argv) if meta.argv else None,
            sample=rd.Sample(
                md5=meta.sample.md5,
                sha1=meta.sample.sha1,
                sha256=meta.sample.sha256,
                path=meta.sample.path,
            ),
            flavor=flavor_from_pb2(meta.flavor),
            analysis=dynamic_analysis_from_pb2(meta.dynamic_analysis),
        )
    else:
        assert_never(analysis_type)


def statement_from_pb2(statement: capa_pb2.StatementNode) -> rd.Statement:
    type_ = statement.WhichOneof("statement")

    if type_ == "range":
        return rd.RangeStatement(
            min=statement.range.min,
            max=statement.range.max,
            child=feature_from_pb2(statement.range.child),
            description=statement.range.description or None,
        )
    elif type_ == "some":
        return rd.SomeStatement(
            count=statement.some.count,
            description=statement.some.description or None,
        )
    elif type_ == "subscope":
        return rd.SubscopeStatement(
            scope=scope_from_pb2(statement.subscope.scope),
            description=statement.subscope.description or None,
        )
    elif type_ == "compound":
        return rd.CompoundStatement(
            type=statement.compound.type,
            description=statement.compound.description or None,
        )
    else:
        assert_never(type_)


def feature_from_pb2(f: capa_pb2.FeatureNode) -> frzf.Feature:
    type_ = f.WhichOneof("feature")

    # mypy gets angry below because ff may have a different type in each branch,
    # even though we don't use ff outside each branch.
    # so we just let mypy know that ff might be any type to silence that warning.
    # upstream issue: https://github.com/python/mypy/issues/6233
    ff: Any

    if type_ == "os":
        ff = f.os
        return frzf.OSFeature(os=ff.os, description=ff.description or None)
    elif type_ == "arch":
        ff = f.arch
        return frzf.ArchFeature(arch=ff.arch, description=ff.description or None)
    elif type_ == "format":
        ff = f.format
        return frzf.FormatFeature(format=ff.format, description=ff.description or None)
    elif type_ == "match":
        ff = f.match
        return frzf.MatchFeature(match=ff.match, description=ff.description or None)
    elif type_ == "characteristic":
        ff = f.characteristic
        return frzf.CharacteristicFeature(characteristic=ff.characteristic, description=ff.description or None)
    elif type_ == "export":
        ff = f.export
        return frzf.ExportFeature(export=ff.export, description=ff.description or None)
    elif type_ == "import_":
        ff = f.import_
        return frzf.ImportFeature(import_=ff.import_, description=ff.description or None)  # type: ignore
        # Mypy is unable to recognize `import_` as an argument
    elif type_ == "section":
        ff = f.section
        return frzf.SectionFeature(section=ff.section, description=ff.description or None)
    elif type_ == "function_name":
        ff = f.function_name
        return frzf.FunctionNameFeature(function_name=ff.function_name, description=ff.description or None)  # type: ignore
    elif type_ == "substring":
        ff = f.substring
        return frzf.SubstringFeature(substring=ff.substring, description=ff.description or None)
    elif type_ == "regex":
        ff = f.regex
        return frzf.RegexFeature(regex=ff.regex, description=ff.description or None)
    elif type_ == "string":
        ff = f.string
        return frzf.StringFeature(string=ff.string, description=ff.description or None)
    elif type_ == "class_":
        ff = f.class_
        return frzf.ClassFeature(class_=ff.class_, description=ff.description or None)  # type: ignore
        # Mypy is unable to recognize `class_` as an argument due to aliasing
    elif type_ == "namespace":
        ff = f.namespace
        return frzf.NamespaceFeature(namespace=ff.namespace, description=ff.description or None)
    elif type_ == "api":
        ff = f.api
        return frzf.APIFeature(api=ff.api, description=ff.description or None)
    elif type_ == "property_":
        ff = f.property_
        return frzf.PropertyFeature(property=ff.property_, access=ff.access or None, description=ff.description or None)
    elif type_ == "number":
        ff = f.number
        return frzf.NumberFeature(number=number_from_pb2(ff.number), description=ff.description or None)
    elif type_ == "bytes":
        ff = f.bytes
        return frzf.BytesFeature(bytes=ff.bytes, description=ff.description or None)
    elif type_ == "offset":
        ff = f.offset
        return frzf.OffsetFeature(offset=int_from_pb2(ff.offset), description=ff.description or None)
    elif type_ == "mnemonic":
        ff = f.mnemonic
        return frzf.MnemonicFeature(mnemonic=ff.mnemonic, description=ff.description or None)
    elif type_ == "operand_number":
        ff = f.operand_number
        return frzf.OperandNumberFeature(
            index=ff.index, operand_number=number_from_pb2(ff.operand_number), description=ff.description or None
        )  # type: ignore
    elif type_ == "operand_offset":
        ff = f.operand_offset
        return frzf.OperandOffsetFeature(
            index=ff.index, operand_offset=int_from_pb2(ff.operand_offset), description=ff.description or None
        )  # type: ignore
        # Mypy is unable to recognize `operand_offset` as an argument due to aliasing
    elif type_ == "basic_block":
        ff = f.basic_block
        return frzf.BasicBlockFeature(description=ff.description or None)
    else:
        assert_never(type_)


def match_from_pb2(match: capa_pb2.Match) -> rd.Match:
    children = list(map(match_from_pb2, match.children))
    locations = list(map(addr_from_pb2, match.locations))

    node_type = match.WhichOneof("node")
    if node_type == "statement":
        return rd.Match(
            success=match.success,
            node=rd.StatementNode(statement=statement_from_pb2(match.statement)),
            children=tuple(children),
            locations=tuple(locations),
            captures={},
        )
    elif node_type == "feature":
        return rd.Match(
            success=match.success,
            node=rd.FeatureNode(feature=feature_from_pb2(match.feature)),
            children=tuple(children),
            locations=tuple(locations),
            captures={capture: tuple(map(addr_from_pb2, locs.address)) for capture, locs in match.captures.items()},
        )
    else:
        assert_never(node_type)


def attack_from_pb2(pb: capa_pb2.AttackSpec) -> rd.AttackSpec:
    return rd.AttackSpec(
        parts=tuple(pb.parts),
        tactic=pb.tactic,
        technique=pb.technique,
        subtechnique=pb.subtechnique,
        id=pb.id,
    )


def mbc_from_pb2(pb: capa_pb2.MBCSpec) -> rd.MBCSpec:
    return rd.MBCSpec(
        parts=tuple(pb.parts),
        objective=pb.objective,
        behavior=pb.behavior,
        method=pb.method,
        id=pb.id,
    )


def maec_from_pb2(pb: capa_pb2.MaecMetadata) -> rd.MaecMetadata:
    return rd.MaecMetadata(
        analysis_conclusion=pb.analysis_conclusion or None,
        analysis_conclusion_ov=pb.analysis_conclusion_ov or None,
        malware_family=pb.malware_family or None,
        malware_category=pb.malware_category or None,
        malware_category_ov=pb.malware_category_ov or None,
    )  # type: ignore
    # Mypy is unable to recognise arguments due to alias


def rule_metadata_from_pb2(pb: capa_pb2.RuleMetadata) -> rd.RuleMetadata:
    return rd.RuleMetadata(
        name=pb.name,
        namespace=pb.namespace or None,
        authors=tuple(pb.authors),
        scopes=scopes_from_pb2(pb.scopes),
        attack=tuple([attack_from_pb2(attack) for attack in pb.attack]),
        mbc=tuple([mbc_from_pb2(mbc) for mbc in pb.mbc]),
        references=tuple(pb.references),
        examples=tuple(pb.examples),
        description=pb.description,
        lib=pb.lib,
        is_subscope_rule=pb.is_subscope_rule,
        maec=maec_from_pb2(pb.maec),
    )  # type: ignore
    # Mypy is unable to recognise `attack` and `is_subscope_rule` as arguments due to alias


def doc_from_pb2(doc: capa_pb2.ResultDocument) -> rd.ResultDocument:
    rule_matches: dict[str, rd.RuleMatches] = {}
    for rule_name, matches in doc.rules.items():
        m = rd.RuleMatches(
            meta=rule_metadata_from_pb2(matches.meta),
            source=matches.source,
            matches=tuple([(addr_from_pb2(pair.address), match_from_pb2(pair.match)) for pair in matches.matches]),
        )
        rule_matches[rule_name] = m

    return rd.ResultDocument(meta=metadata_from_pb2(doc.meta), rules=rule_matches)
