# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import io
import os
import re
import uuid
import codecs
import logging
import binascii
import collections
from enum import Enum
from pathlib import Path

from capa.helpers import assert_never

try:
    from functools import lru_cache
except ImportError:
    # need to type ignore this due to mypy bug here (duplicate name):
    # https://github.com/python/mypy/issues/1153
    from backports.functools_lru_cache import lru_cache  # type: ignore

from typing import Any, Set, Dict, List, Tuple, Union, Callable, Iterator, Optional
from dataclasses import asdict, dataclass

import yaml
import pydantic
import yaml.parser

import capa.perf
import capa.engine as ceng
import capa.features
import capa.optimizer
import capa.features.com
import capa.features.file
import capa.features.insn
import capa.features.common
import capa.features.basicblock
from capa.engine import Statement, FeatureSet
from capa.features.com import ComType
from capa.features.common import MAX_BYTES_FEATURE_SIZE, Feature
from capa.features.address import Address

logger = logging.getLogger(__name__)

# these are the standard metadata fields, in the preferred order.
# when reformatted, any custom keys will come after these.
META_KEYS = (
    "name",
    "namespace",
    "maec/analysis-conclusion",
    "maec/analysis-conclusion-ov",
    "maec/malware-family",
    "maec/malware-category",
    "maec/malware-category-ov",
    "authors",
    "description",
    "lib",
    "scopes",
    "att&ck",
    "mbc",
    "references",
    "examples",
)
# these are meta fields that are internal to capa,
# and added during rule reading/construction.
# they may help use manipulate or index rules,
# but should not be exposed to clients.
HIDDEN_META_KEYS = ("capa/nursery", "capa/path")


class Scope(str, Enum):
    FILE = "file"
    PROCESS = "process"
    THREAD = "thread"
    CALL = "call"
    FUNCTION = "function"
    BASIC_BLOCK = "basic block"
    INSTRUCTION = "instruction"

    # used only to specify supported features per scope.
    # not used to validate rules.
    GLOBAL = "global"

    @classmethod
    def to_yaml(cls, representer, node):
        return representer.represent_str(f"{node.value}")


# these literals are used to check if the flavor
# of a rule is correct.
STATIC_SCOPES = {
    Scope.FILE,
    Scope.GLOBAL,
    Scope.FUNCTION,
    Scope.BASIC_BLOCK,
    Scope.INSTRUCTION,
}
DYNAMIC_SCOPES = {
    Scope.FILE,
    Scope.GLOBAL,
    Scope.PROCESS,
    Scope.THREAD,
    Scope.CALL,
}


@dataclass
class Scopes:
    # when None, the scope is not supported by a rule
    static: Optional[Scope] = None
    # when None, the scope is not supported by a rule
    dynamic: Optional[Scope] = None

    def __contains__(self, scope: Scope) -> bool:
        return (scope == self.static) or (scope == self.dynamic)

    def __repr__(self) -> str:
        if self.static and self.dynamic:
            return f"static-scope: {self.static}, dynamic-scope: {self.dynamic}"
        elif self.static:
            return f"static-scope: {self.static}"
        elif self.dynamic:
            return f"dynamic-scope: {self.dynamic}"
        else:
            raise ValueError("invalid rules class. at least one scope must be specified")

    @classmethod
    def from_dict(self, scopes: Dict[str, str]) -> "Scopes":
        # make local copy so we don't make changes outside of this routine.
        # we'll use the value None to indicate the scope is not supported.
        scopes_: Dict[str, Optional[str]] = dict(scopes)

        # mark non-specified scopes as invalid
        if "static" not in scopes_:
            raise InvalidRule("static scope must be provided")
        if "dynamic" not in scopes_:
            raise InvalidRule("dynamic scope must be provided")

        # check the syntax of the meta `scopes` field
        if sorted(scopes_) != ["dynamic", "static"]:
            raise InvalidRule("scope flavors can be either static or dynamic")

        if scopes_["static"] == "unsupported":
            scopes_["static"] = None
        if scopes_["dynamic"] == "unsupported":
            scopes_["dynamic"] = None

        # unspecified is used to indicate a rule is yet to be migrated.
        # TODO(williballenthin): this scope term should be removed once all rules have been migrated.
        # https://github.com/mandiant/capa/issues/1747
        if scopes_["static"] == "unspecified":
            scopes_["static"] = None
        if scopes_["dynamic"] == "unspecified":
            scopes_["dynamic"] = None

        if (not scopes_["static"]) and (not scopes_["dynamic"]):
            raise InvalidRule("invalid scopes value. At least one scope must be specified")

        # check that all the specified scopes are valid
        if scopes_["static"] and scopes_["static"] not in STATIC_SCOPES:
            raise InvalidRule(f"{scopes_['static']} is not a valid static scope")

        if scopes_["dynamic"] and scopes_["dynamic"] not in DYNAMIC_SCOPES:
            raise InvalidRule(f"{scopes_['dynamic']} is not a valid dynamic scope")

        return Scopes(
            static=Scope(scopes_["static"]) if scopes_["static"] else None,
            dynamic=Scope(scopes_["dynamic"]) if scopes_["dynamic"] else None,
        )


SUPPORTED_FEATURES: Dict[str, Set] = {
    Scope.GLOBAL: {
        # these will be added to other scopes, see below.
        capa.features.common.OS,
        capa.features.common.Arch,
        capa.features.common.Format,
    },
    Scope.FILE: {
        capa.features.common.MatchedRule,
        capa.features.file.Export,
        capa.features.file.Import,
        capa.features.file.Section,
        capa.features.file.FunctionName,
        capa.features.common.Characteristic("embedded pe"),
        capa.features.common.String,
        capa.features.common.Class,
        capa.features.common.Namespace,
        capa.features.common.Characteristic("mixed mode"),
        capa.features.common.Characteristic("forwarded export"),
    },
    Scope.PROCESS: {
        capa.features.common.MatchedRule,
    },
    Scope.THREAD: set(),
    Scope.CALL: {
        capa.features.common.MatchedRule,
        capa.features.common.Regex,
        capa.features.common.String,
        capa.features.common.Substring,
        capa.features.insn.API,
        capa.features.insn.Number,
    },
    Scope.FUNCTION: {
        capa.features.common.MatchedRule,
        capa.features.basicblock.BasicBlock,
        capa.features.common.Characteristic("calls from"),
        capa.features.common.Characteristic("calls to"),
        capa.features.common.Characteristic("loop"),
        capa.features.common.Characteristic("recursive call"),
        # plus basic block scope features, see below
    },
    Scope.BASIC_BLOCK: {
        capa.features.common.MatchedRule,
        capa.features.common.Characteristic("tight loop"),
        capa.features.common.Characteristic("stack string"),
        # plus instruction scope features, see below
    },
    Scope.INSTRUCTION: {
        capa.features.common.MatchedRule,
        capa.features.insn.API,
        capa.features.insn.Property,
        capa.features.insn.Number,
        capa.features.common.String,
        capa.features.common.Bytes,
        capa.features.insn.Offset,
        capa.features.insn.Mnemonic,
        capa.features.insn.OperandNumber,
        capa.features.insn.OperandOffset,
        capa.features.common.Characteristic("nzxor"),
        capa.features.common.Characteristic("peb access"),
        capa.features.common.Characteristic("fs access"),
        capa.features.common.Characteristic("gs access"),
        capa.features.common.Characteristic("indirect call"),
        capa.features.common.Characteristic("call $+5"),
        capa.features.common.Characteristic("cross section flow"),
        capa.features.common.Characteristic("unmanaged call"),
        capa.features.common.Class,
        capa.features.common.Namespace,
    },
}

# global scope features are available in all other scopes
SUPPORTED_FEATURES[Scope.INSTRUCTION].update(SUPPORTED_FEATURES[Scope.GLOBAL])
SUPPORTED_FEATURES[Scope.BASIC_BLOCK].update(SUPPORTED_FEATURES[Scope.GLOBAL])
SUPPORTED_FEATURES[Scope.FUNCTION].update(SUPPORTED_FEATURES[Scope.GLOBAL])
SUPPORTED_FEATURES[Scope.FILE].update(SUPPORTED_FEATURES[Scope.GLOBAL])
SUPPORTED_FEATURES[Scope.PROCESS].update(SUPPORTED_FEATURES[Scope.GLOBAL])
SUPPORTED_FEATURES[Scope.THREAD].update(SUPPORTED_FEATURES[Scope.GLOBAL])
SUPPORTED_FEATURES[Scope.CALL].update(SUPPORTED_FEATURES[Scope.GLOBAL])


# all call scope features are also thread features
SUPPORTED_FEATURES[Scope.THREAD].update(SUPPORTED_FEATURES[Scope.CALL])
# all thread scope features are also process features
SUPPORTED_FEATURES[Scope.PROCESS].update(SUPPORTED_FEATURES[Scope.THREAD])

# all instruction scope features are also basic block features
SUPPORTED_FEATURES[Scope.BASIC_BLOCK].update(SUPPORTED_FEATURES[Scope.INSTRUCTION])
# all basic block scope features are also function scope features
SUPPORTED_FEATURES[Scope.FUNCTION].update(SUPPORTED_FEATURES[Scope.BASIC_BLOCK])


class InvalidRule(ValueError):
    def __init__(self, msg):
        super().__init__()
        self.msg = msg

    def __str__(self):
        return f"invalid rule: {self.msg}"

    def __repr__(self):
        return str(self)


class InvalidRuleWithPath(InvalidRule):
    def __init__(self, path, msg):
        super().__init__(msg)
        self.path = path
        self.msg = msg
        self.__cause__ = None

    def __str__(self):
        return f"invalid rule: {self.path}: {self.msg}"


class InvalidRuleSet(ValueError):
    def __init__(self, msg):
        super().__init__()
        self.msg = msg

    def __str__(self):
        return f"invalid rule set: {self.msg}"

    def __repr__(self):
        return str(self)


def ensure_feature_valid_for_scopes(scopes: Scopes, feature: Union[Feature, Statement]):
    # construct a dict of all supported features
    supported_features: Set = set()
    if scopes.static:
        supported_features.update(SUPPORTED_FEATURES[scopes.static])
    if scopes.dynamic:
        supported_features.update(SUPPORTED_FEATURES[scopes.dynamic])

    # if the given feature is a characteristic,
    # check that is a valid characteristic for the given scope.
    if (
        isinstance(feature, capa.features.common.Characteristic)
        and isinstance(feature.value, str)
        and capa.features.common.Characteristic(feature.value) not in supported_features
    ):
        raise InvalidRule(f"feature {feature} not supported for scopes {scopes}")

    if not isinstance(feature, capa.features.common.Characteristic):
        # features of this scope that are not Characteristics will be Type instances.
        # check that the given feature is one of these types.
        types_for_scope = filter(lambda t: isinstance(t, type), supported_features)
        if not isinstance(feature, tuple(types_for_scope)):
            raise InvalidRule(f"feature {feature} not supported for scopes {scopes}")


def translate_com_feature(com_name: str, com_type: ComType) -> ceng.Statement:
    com_db = capa.features.com.load_com_database(com_type)
    guids: Optional[List[str]] = com_db.get(com_name)
    if not guids:
        logger.error(" %s doesn't exist in COM %s database", com_name, com_type)
        raise InvalidRule(f"'{com_name}' doesn't exist in COM {com_type} database")

    com_features: List[Feature] = []
    for guid in guids:
        hex_chars = guid.replace("-", "")
        h = [hex_chars[i : i + 2] for i in range(0, len(hex_chars), 2)]
        reordered_hex_pairs = [
            h[3],
            h[2],
            h[1],
            h[0],
            h[5],
            h[4],
            h[7],
            h[6],
            h[8],
            h[9],
            h[10],
            h[11],
            h[12],
            h[13],
            h[14],
            h[15],
        ]
        guid_bytes = bytes.fromhex("".join(reordered_hex_pairs))
        prefix = capa.features.com.COM_PREFIXES[com_type]
        symbol = prefix + com_name
        com_features.append(capa.features.common.String(guid, f"{symbol} as GUID string"))
        com_features.append(capa.features.common.Bytes(guid_bytes, f"{symbol} as bytes"))
    return ceng.Or(com_features)


def parse_int(s: str) -> int:
    if s.startswith("0x"):
        return int(s, 0x10)
    else:
        return int(s, 10)


def parse_range(s: str):
    """
    parse a string "(0, 1)" into a range (min, max).
    min and/or max may by None to indicate an unbound range.
    """
    # we want to use `{` characters, but this is a dict in yaml.
    if not s.startswith("("):
        raise InvalidRule(f"invalid range: {s}")

    if not s.endswith(")"):
        raise InvalidRule(f"invalid range: {s}")

    s = s[len("(") : -len(")")]
    min_spec, _, max_spec = s.partition(",")
    min_spec = min_spec.strip()
    max_spec = max_spec.strip()

    min_ = None
    if min_spec:
        min_ = parse_int(min_spec)
        if min_ < 0:
            raise InvalidRule("range min less than zero")

    max_ = None
    if max_spec:
        max_ = parse_int(max_spec)
        if max_ < 0:
            raise InvalidRule("range max less than zero")

    if min_ is not None and max_ is not None:
        if max_ < min_:
            raise InvalidRule("range max less than min")

    return min_, max_


def parse_feature(key: str):
    # keep this in sync with supported features
    if key == "api":
        return capa.features.insn.API
    elif key == "string":
        return capa.features.common.StringFactory
    elif key == "substring":
        return capa.features.common.Substring
    elif key == "bytes":
        return capa.features.common.Bytes
    elif key == "number":
        return capa.features.insn.Number
    elif key == "offset":
        return capa.features.insn.Offset
    elif key == "mnemonic":
        return capa.features.insn.Mnemonic
    elif key == "basic blocks":
        return capa.features.basicblock.BasicBlock
    elif key == "characteristic":
        return capa.features.common.Characteristic
    elif key == "export":
        return capa.features.file.Export
    elif key == "import":
        return capa.features.file.Import
    elif key == "section":
        return capa.features.file.Section
    elif key == "match":
        return capa.features.common.MatchedRule
    elif key == "function-name":
        return capa.features.file.FunctionName
    elif key == "os":
        return capa.features.common.OS
    elif key == "format":
        return capa.features.common.Format
    elif key == "arch":
        return capa.features.common.Arch
    elif key == "class":
        return capa.features.common.Class
    elif key == "namespace":
        return capa.features.common.Namespace
    elif key == "property":
        return capa.features.insn.Property
    else:
        raise InvalidRule(f"unexpected statement: {key}")


# this is the separator between a feature value and its description
# when using the inline description syntax, like:
#
#     number: 42 = ENUM_FAVORITE_NUMBER
DESCRIPTION_SEPARATOR = " = "


def parse_bytes(s: str) -> bytes:
    try:
        b = codecs.decode(s.replace(" ", "").encode("ascii"), "hex")
    except binascii.Error:
        raise InvalidRule(f'unexpected bytes value: must be a valid hex sequence: "{s}"')

    if len(b) > MAX_BYTES_FEATURE_SIZE:
        raise InvalidRule(
            f"unexpected bytes value: byte sequences must be no larger than {MAX_BYTES_FEATURE_SIZE} bytes"
        )

    return b


def parse_description(s: Union[str, int, bytes], value_type: str, description=None):
    if value_type == "string":
        # string features cannot have inline descriptions,
        # so we assume the entire value is the string,
        # like: `string: foo = bar` -> "foo = bar"
        value = s
    else:
        # other features can have inline descriptions, like `number: 10 = CONST_FOO`.
        # in this case, the RHS will be like `10 = CONST_FOO` or some other string
        if isinstance(s, str):
            if DESCRIPTION_SEPARATOR in s:
                if description:
                    # there is already a description passed in as a sub node, like:
                    #
                    #     - number: 10 = CONST_FOO
                    #       description: CONST_FOO
                    raise InvalidRule(
                        f'unexpected value: "{s}", only one description allowed (inline description with `{DESCRIPTION_SEPARATOR}`)'
                    )

                value, _, description = s.partition(DESCRIPTION_SEPARATOR)
                if description == "":
                    # sanity check:
                    # there is an empty description, like `number: 10 =`
                    raise InvalidRule(f'unexpected value: "{s}", description cannot be empty')
            else:
                # this is a string, but there is no description,
                # like: `api: CreateFileA`
                value = s

            # cast from the received string value to the appropriate type.
            #
            # without a description, this type would already be correct,
            # but since we parsed the description from a string,
            # we need to convert the value to the expected type.
            #
            # for example, from `number: 10 = CONST_FOO` we have
            # the string "10" that needs to become the number 10.
            if value_type == "bytes":
                value = parse_bytes(value)
            elif (
                value_type in ("number", "offset")
                or value_type.startswith(("number/", "offset/"))
                or (
                    value_type.startswith("operand[")
                    and (value_type.endswith("].number") or value_type.endswith("].offset"))
                )
            ):
                try:
                    value = parse_int(value)
                except ValueError:
                    raise InvalidRule(f'unexpected value: "{value}", must begin with numerical value')

        else:
            # the value might be a number, like: `number: 10`
            value = s

    return value, description


def pop_statement_description_entry(d):
    """
    extracts the description for statements and removes the description entry from the document
    a statement can only have one description

    example:
    the features definition
      - or:
        - description: statement description
        - number: 1
          description: feature description

    becomes
      <statement>: [
        { "description": "statement description" },  <-- extracted here
        { "number": 1, "description": "feature description" }
      ]
    """
    if not isinstance(d, list):
        return None

    # identify child of form '{ "description": <description> }'
    descriptions = list(filter(lambda c: isinstance(c, dict) and len(c) == 1 and "description" in c, d))
    if len(descriptions) > 1:
        raise InvalidRule("statements can only have one description")

    if not descriptions:
        return None

    description = descriptions[0]
    d.remove(description)

    return description["description"]


def trim_dll_part(api: str) -> str:
    # ordinal imports, like ws2_32.#1, keep dll
    if ".#" in api:
        return api

    # kernel32.CreateFileA
    if api.count(".") == 1:
        if "::" not in api:
            # skip System.Convert::FromBase64String
            api = api.split(".")[1]
    return api


def build_statements(d, scopes: Scopes):
    if len(d.keys()) > 2:
        raise InvalidRule("too many statements")

    key = list(d.keys())[0]
    description = pop_statement_description_entry(d[key])
    if key == "and":
        return ceng.And([build_statements(dd, scopes) for dd in d[key]], description=description)
    elif key == "or":
        return ceng.Or([build_statements(dd, scopes) for dd in d[key]], description=description)
    elif key == "not":
        if len(d[key]) != 1:
            raise InvalidRule("not statement must have exactly one child statement")
        return ceng.Not(build_statements(d[key][0], scopes), description=description)
    elif key.endswith(" or more"):
        count = int(key[: -len("or more")])
        return ceng.Some(count, [build_statements(dd, scopes) for dd in d[key]], description=description)
    elif key == "optional":
        # `optional` is an alias for `0 or more`
        # which is useful for documenting behaviors,
        # like with `write file`, we might say that `WriteFile` is optionally found alongside `CreateFileA`.
        return ceng.Some(0, [build_statements(dd, scopes) for dd in d[key]], description=description)

    elif key == "process":
        if Scope.FILE not in scopes:
            raise InvalidRule("process subscope supported only for file scope")

        if len(d[key]) != 1:
            raise InvalidRule("subscope must have exactly one child statement")

        return ceng.Subscope(
            Scope.PROCESS, build_statements(d[key][0], Scopes(dynamic=Scope.PROCESS)), description=description
        )

    elif key == "thread":
        if all(s not in scopes for s in (Scope.FILE, Scope.PROCESS)):
            raise InvalidRule("thread subscope supported only for the process scope")

        if len(d[key]) != 1:
            raise InvalidRule("subscope must have exactly one child statement")

        return ceng.Subscope(
            Scope.THREAD, build_statements(d[key][0], Scopes(dynamic=Scope.THREAD)), description=description
        )

    elif key == "call":
        if all(s not in scopes for s in (Scope.FILE, Scope.PROCESS, Scope.THREAD)):
            raise InvalidRule("call subscope supported only for the process and thread scopes")

        if len(d[key]) != 1:
            raise InvalidRule("subscope must have exactly one child statement")

        return ceng.Subscope(
            Scope.CALL, build_statements(d[key][0], Scopes(dynamic=Scope.CALL)), description=description
        )

    elif key == "function":
        if Scope.FILE not in scopes:
            raise InvalidRule("function subscope supported only for file scope")

        if len(d[key]) != 1:
            raise InvalidRule("subscope must have exactly one child statement")

        return ceng.Subscope(
            Scope.FUNCTION, build_statements(d[key][0], Scopes(static=Scope.FUNCTION)), description=description
        )

    elif key == "basic block":
        if Scope.FUNCTION not in scopes:
            raise InvalidRule("basic block subscope supported only for function scope")

        if len(d[key]) != 1:
            raise InvalidRule("subscope must have exactly one child statement")

        return ceng.Subscope(
            Scope.BASIC_BLOCK, build_statements(d[key][0], Scopes(static=Scope.BASIC_BLOCK)), description=description
        )

    elif key == "instruction":
        if all(s not in scopes for s in (Scope.FUNCTION, Scope.BASIC_BLOCK)):
            raise InvalidRule("instruction subscope supported only for function and basic block scope")

        if len(d[key]) == 1:
            statements = build_statements(d[key][0], Scopes(static=Scope.INSTRUCTION))
        else:
            # for instruction subscopes, we support a shorthand in which the top level AND is implied.
            # the following are equivalent:
            #
            #     - instruction:
            #       - and:
            #         - arch: i386
            #         - mnemonic: cmp
            #
            #     - instruction:
            #       - arch: i386
            #       - mnemonic: cmp
            #
            statements = ceng.And([build_statements(dd, Scopes(static=Scope.INSTRUCTION)) for dd in d[key]])

        return ceng.Subscope(Scope.INSTRUCTION, statements, description=description)

    elif key.startswith("count(") and key.endswith(")"):
        # e.g.:
        #
        #     count(basic block)
        #     count(mnemonic(mov))
        #     count(characteristic(nzxor))

        term = key[len("count(") : -len(")")]

        # when looking for the existence of such a feature, our rule might look like:
        #     - mnemonic: mov
        #
        # but here we deal with the form: `mnemonic(mov)`.
        term, _, arg = term.partition("(")
        Feature = parse_feature(term)

        if arg:
            arg = arg[: -len(")")]
            # can't rely on yaml parsing ints embedded within strings
            # like:
            #
            #     count(offset(0xC))
            #     count(number(0x11223344))
            #     count(number(0x100 = description))
            if term != "string":
                value, description = parse_description(arg, term)

                if term == "api":
                    value = trim_dll_part(value)

                feature = Feature(value, description=description)
            else:
                # arg is string (which doesn't support inline descriptions), like:
                #
                #     count(string(error))
                #
                # known problem that embedded newlines may not work here?
                # this may become a problem (or not), so address it when encountered.
                feature = Feature(arg)
        else:
            feature = Feature()
        ensure_feature_valid_for_scopes(scopes, feature)

        count = d[key]
        if isinstance(count, int):
            return ceng.Range(feature, min=count, max=count, description=description)
        elif count.endswith(" or more"):
            min = parse_int(count[: -len(" or more")])
            max = None
            return ceng.Range(feature, min=min, max=max, description=description)
        elif count.endswith(" or fewer"):
            min = None
            max = parse_int(count[: -len(" or fewer")])
            return ceng.Range(feature, min=min, max=max, description=description)
        elif count.startswith("("):
            min, max = parse_range(count)
            return ceng.Range(feature, min=min, max=max, description=description)
        else:
            raise InvalidRule(f"unexpected range: {count}")
    elif key == "string" and not isinstance(d[key], str):
        raise InvalidRule(f"ambiguous string value {d[key]}, must be defined as explicit string")

    elif key.startswith("operand[") and key.endswith("].number"):
        index = key[len("operand[") : -len("].number")]
        try:
            index = int(index)
        except ValueError as e:
            raise InvalidRule("operand index must be an integer") from e

        value, description = parse_description(d[key], key, d.get("description"))
        assert isinstance(value, int)
        try:
            feature = capa.features.insn.OperandNumber(index, value, description=description)
        except ValueError as e:
            raise InvalidRule(str(e)) from e
        ensure_feature_valid_for_scopes(scopes, feature)
        return feature

    elif key.startswith("operand[") and key.endswith("].offset"):
        index = key[len("operand[") : -len("].offset")]
        try:
            index = int(index)
        except ValueError as e:
            raise InvalidRule("operand index must be an integer") from e

        value, description = parse_description(d[key], key, d.get("description"))
        assert isinstance(value, int)
        try:
            feature = capa.features.insn.OperandOffset(index, value, description=description)
        except ValueError as e:
            raise InvalidRule(str(e)) from e
        ensure_feature_valid_for_scopes(scopes, feature)
        return feature

    elif (
        (key == "os" and d[key] not in capa.features.common.VALID_OS)
        or (key == "format" and d[key] not in capa.features.common.VALID_FORMAT)
        or (key == "arch" and d[key] not in capa.features.common.VALID_ARCH)
    ):
        raise InvalidRule(f"unexpected {key} value {d[key]}")

    elif key.startswith("property/"):
        access = key[len("property/") :]
        if access not in capa.features.common.VALID_FEATURE_ACCESS:
            raise InvalidRule(f"unexpected {key} access {access}")

        value, description = parse_description(d[key], key, d.get("description"))
        try:
            feature = capa.features.insn.Property(value, access=access, description=description)
        except ValueError as e:
            raise InvalidRule(str(e)) from e
        ensure_feature_valid_for_scopes(scopes, feature)
        return feature

    elif key.startswith("com/"):
        com_type_name = str(key[len("com/") :])
        try:
            com_type = ComType(com_type_name)
        except ValueError:
            raise InvalidRule(f"unexpected COM type: {com_type_name}")
        value, description = parse_description(d[key], key, d.get("description"))
        return translate_com_feature(value, com_type)

    else:
        Feature = parse_feature(key)
        value, description = parse_description(d[key], key, d.get("description"))

        if key == "api":
            value = trim_dll_part(value)

        try:
            feature = Feature(value, description=description)
        except ValueError as e:
            raise InvalidRule(str(e)) from e
        ensure_feature_valid_for_scopes(scopes, feature)
        return feature


def first(s: List[Any]) -> Any:
    return s[0]


def second(s: List[Any]) -> Any:
    return s[1]


class Rule:
    def __init__(self, name: str, scopes: Scopes, statement: Statement, meta, definition=""):
        super().__init__()
        self.name = name
        self.scopes = scopes
        self.statement = statement
        self.meta = meta
        self.definition = definition

    def __str__(self):
        return f"Rule(name={self.name})"

    def __repr__(self):
        return f"Rule(scope={self.scopes}, name={self.name})"

    def get_dependencies(self, namespaces):
        """
        fetch the names of rules this rule relies upon.
        these are only the direct dependencies; a user must
         compute the transitive dependency graph themself, if they want it.

        Args:
          namespaces(Dict[str, List[Rule]]): mapping from namespace name to rules in it.
            see `index_rules_by_namespace`.

        Returns:
          List[str]: names of rules upon which this rule depends.
        """
        deps: Set[str] = set()

        def rec(statement):
            if isinstance(statement, capa.features.common.MatchedRule):
                # we're not sure at this point if the `statement.value` is
                #  really a rule name or a namespace name (we use `MatchedRule` for both cases).
                # we'll give precedence to namespaces, and then assume if that does work,
                #  that it must be a rule name.
                #
                # we don't expect any collisions between namespaces and rule names, but its possible.
                # most likely would be collision between top level namespace (e.g. `host-interaction`) and rule name.
                # but, namespaces tend to use `-` while rule names use ` `. so, unlikely, but possible.
                if statement.value in namespaces:
                    # matches a namespace, so take precedence and don't even check rule names.
                    deps.update(r.name for r in namespaces[statement.value])
                else:
                    # not a namespace, assume its a rule name.
                    assert isinstance(statement.value, str)
                    deps.add(statement.value)

            elif isinstance(statement, ceng.Statement):
                for child in statement.get_children():
                    rec(child)

            # else: might be a Feature, etc.
            # which we don't care about here.

        rec(self.statement)
        return deps

    def _extract_subscope_rules_rec(self, statement):
        if isinstance(statement, ceng.Statement):
            # for each child that is a subscope,
            for child in statement.get_children():
                if not isinstance(child, ceng.Subscope):
                    continue

                subscope = child

                # create a new rule from it.
                # the name is a randomly generated, hopefully unique value.
                # ideally, this won't every be rendered to a user.
                name = self.name + "/" + uuid.uuid4().hex
                if subscope.scope in STATIC_SCOPES:
                    scopes = Scopes(static=subscope.scope)
                elif subscope.scope in DYNAMIC_SCOPES:
                    scopes = Scopes(dynamic=subscope.scope)
                else:
                    raise InvalidRule(f"scope {subscope.scope} is not a valid subscope")
                new_rule = Rule(
                    name,
                    scopes,
                    subscope.child,
                    {
                        "name": name,
                        "scopes": asdict(scopes),
                        # these derived rules are never meant to be inspected separately,
                        # they are dependencies for the parent rule,
                        # so mark it as such.
                        "lib": True,
                        # metadata that indicates this is derived from a subscope statement
                        "capa/subscope-rule": True,
                        # metadata that links the child rule the parent rule
                        "capa/parent": self.name,
                    },
                )

                # update the existing statement to `match` the new rule
                new_node = capa.features.common.MatchedRule(name)
                statement.replace_child(subscope, new_node)

                # and yield the new rule to our caller
                yield new_rule

            # now recurse to other nodes in the logic tree.
            # note: we cannot recurse into the subscope sub-tree,
            #  because its been replaced by a `match` statement.
            for child in statement.get_children():
                yield from self._extract_subscope_rules_rec(child)

    def is_file_limitation_rule(self) -> bool:
        return self.meta.get("namespace", "") == "internal/limitation/file"

    def is_subscope_rule(self):
        return bool(self.meta.get("capa/subscope-rule", False))

    def extract_subscope_rules(self):
        """
        scan through the statements of this rule,
        replacing subscope statements with `match` references to a newly created rule,
        which are yielded from this routine.

        note: this mutates the current rule.

        example::

            for derived_rule in rule.extract_subscope_rules():
                assert derived_rule.meta['capa/parent'] == rule.name
        """

        # recurse through statements
        # when encounter Subscope statement
        #   create new transient rule
        #   copy logic into the new rule
        #   replace old node with reference to new rule
        #   yield new rule

        yield from self._extract_subscope_rules_rec(self.statement)

    def _extract_all_features_rec(self, statement) -> Set[Feature]:
        feature_set: Set[Feature] = set()

        for child in statement.get_children():
            if isinstance(child, Statement):
                feature_set.update(self._extract_all_features_rec(child))
            else:
                feature_set.add(child)
        return feature_set

    def extract_all_features(self) -> Set[Feature]:
        """
        recursively extracts all feature statements in this rule.

        returns:
            set: A set of all feature statements contained within this rule.
        """
        if not isinstance(self.statement, ceng.Statement):
            # For rules with single feature like
            # anti-analysis\obfuscation\obfuscated-with-advobfuscator.yml
            # contains a single feature - substring , which is of type String
            return {
                self.statement,
            }

        return self._extract_all_features_rec(self.statement)

    def evaluate(self, features: FeatureSet, short_circuit=True):
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature.rule"] += 1
        return self.statement.evaluate(features, short_circuit=short_circuit)

    @classmethod
    def from_dict(cls, d: Dict[str, Any], definition: str) -> "Rule":
        meta = d["rule"]["meta"]
        name = meta["name"]

        # if scope is not specified, default to function scope.
        # this is probably the mode that rule authors will start with.
        # each rule has two scopes, a static-flavor scope, and a
        # dynamic-flavor one. which one is used depends on the analysis type.
        if "scope" in meta:
            raise InvalidRule(f"legacy rule detected (rule.meta.scope), please update to the new syntax: {name}")
        elif "scopes" in meta:
            scopes_ = meta.get("scopes")
        else:
            raise InvalidRule("please specify at least one of this rule's (static/dynamic) scopes")
        if not isinstance(scopes_, dict):
            raise InvalidRule("the scopes field must contain a dictionary specifying the scopes")

        scopes: Scopes = Scopes.from_dict(scopes_)
        statements = d["rule"]["features"]

        # the rule must start with a single logic node.
        # doing anything else is too implicit and difficult to remove (AND vs OR ???).
        if len(statements) != 1:
            raise InvalidRule("rule must begin with a single top level statement")

        if isinstance(statements[0], ceng.Subscope):
            raise InvalidRule("top level statement may not be a subscope")

        meta = d["rule"]["meta"]
        if not isinstance(meta.get("att&ck", []), list):
            raise InvalidRule("ATT&CK mapping must be a list")
        if not isinstance(meta.get("mbc", []), list):
            raise InvalidRule("MBC mapping must be a list")

        return cls(name, scopes, build_statements(statements[0], scopes), meta, definition)

    @staticmethod
    @lru_cache()
    def _get_yaml_loader():
        try:
            # prefer to use CLoader to be fast, see #306
            # on Linux, make sure you install libyaml-dev or similar
            # on Windows, get WHLs from pyyaml.org/pypi
            logger.debug("using libyaml CLoader.")
            return yaml.CLoader
        except Exception:
            logger.debug("unable to import libyaml CLoader, falling back to Python yaml parser.")
            logger.debug("this will be slower to load rules.")
            return yaml.Loader

    @staticmethod
    def _get_ruamel_yaml_parser():
        # we use lazy importing here to avoid eagerly loading dependencies
        # that some specialized environments may not have,
        # e.g., those that run capa without ruamel.
        import ruamel.yaml

        # use ruamel to enable nice formatting
        # we use the ruamel.yaml parser because it supports roundtripping of documents with comments.
        y = ruamel.yaml.YAML(typ="rt")

        # use block mode, not inline json-like mode
        y.default_flow_style = False

        # leave quotes unchanged.
        # manually verified this property exists, even if mypy complains.
        y.preserve_quotes = True

        # indent lists by two spaces below their parent
        #
        #     features:
        #       - or:
        #         - mnemonic: aesdec
        #         - mnemonic: vaesdec
        y.indent(sequence=2, offset=2)

        # avoid word wrapping
        # manually verified this property exists, even if mypy complains.
        y.width = 4096

        return y

    @classmethod
    def from_yaml(cls, s: str, use_ruamel=False) -> "Rule":
        if use_ruamel:
            # ruamel enables nice formatting and doc roundtripping with comments
            doc = cls._get_ruamel_yaml_parser().load(s)
        else:
            # use pyyaml because it can be much faster than ruamel (pure python)
            doc = yaml.load(s, Loader=cls._get_yaml_loader())
        return cls.from_dict(doc, s)

    @classmethod
    def from_yaml_file(cls, path, use_ruamel=False) -> "Rule":
        with Path(path).open("rb") as f:
            try:
                rule = cls.from_yaml(f.read().decode("utf-8"), use_ruamel=use_ruamel)
                # import here to avoid circular dependency
                from capa.render.result_document import RuleMetadata

                # validate meta data fields
                _ = RuleMetadata.from_capa(rule)
                return rule
            except InvalidRule as e:
                raise InvalidRuleWithPath(path, str(e)) from e
            except pydantic.ValidationError as e:
                raise InvalidRuleWithPath(path, str(e)) from e
            except yaml.parser.ParserError as e:
                raise InvalidRuleWithPath(path, str(e)) from e

    def to_yaml(self) -> str:
        # reformat the yaml document with a common style.
        # this includes:
        #  - ordering the meta elements
        #  - indenting the nested items with two spaces
        #
        # updates to the rule will be synced for meta fields,
        # but not for rule logic.
        # programmatic generation of rules is not yet supported.

        # use ruamel because it supports round tripping.
        # pyyaml will lose the existing ordering of rule statements.
        definition = self._get_ruamel_yaml_parser().load(self.definition)

        # we want to apply any updates that have been made to `meta`.
        # so we would like to assigned it like this:
        #
        #     definition["rule"]["meta"] = self.meta
        #
        # however, `self.meta` is not ordered, its just a dict, so subsequent formatting doesn't work.
        # so, we'll manually copy the keys over, re-using the existing ordereddict/CommentedMap
        meta = definition["rule"]["meta"]
        for k in meta.keys():
            if k not in self.meta:
                del meta[k]
        for k, v in self.meta.items():
            meta[k] = v
        # the name and scope of the rule instance overrides anything in meta.
        meta["name"] = self.name

        def move_to_end(m, k):
            # ruamel.yaml uses an ordereddict-like structure to track maps (CommentedMap).
            # here we refresh the insertion order of the given key.
            # this will move it to the end of the sequence.
            v = m[k]
            del m[k]
            m[k] = v

        move_to_end(definition["rule"], "meta")
        move_to_end(definition["rule"], "features")

        for key in META_KEYS:
            if key in meta:
                move_to_end(meta, key)

        for key in sorted(meta.keys()):
            if key in META_KEYS:
                continue
            move_to_end(meta, key)
        # save off the existing hidden meta values,
        # emit the document,
        # and re-add the hidden meta.
        hidden_meta = {}
        for key in HIDDEN_META_KEYS:
            value = meta.get(key)
            if value:
                hidden_meta[key] = value

        for key in hidden_meta.keys():
            del meta[key]

        ostream = io.BytesIO()
        self._get_ruamel_yaml_parser().dump(definition, ostream)

        for key, value in hidden_meta.items():
            if value is None:
                continue
            meta[key] = value

        doc = ostream.getvalue().decode("utf-8").rstrip("\n") + "\n"
        # when we have something like:
        #
        #     and:
        #       - string: foo
        #         description: bar
        #
        # we want the `description` horizontally aligned with the start of the `string` (like above).
        # however, ruamel will give us (which I don't think is even valid yaml):
        #
        #     and:
        #       - string: foo
        #      description: bar
        #
        # tweaking `ruamel.indent()` doesn't quite give us the control we want.
        # so, add the two extra spaces that we've determined we need through experimentation.
        # see #263
        # only do this for the features section, so the meta description doesn't get reformatted
        # assumes features section always exists
        features_offset = doc.find("features")
        doc = doc[:features_offset] + doc[features_offset:].replace("  description:", "    description:")

        # for negative hex numbers, yaml dump outputs:
        # - offset: !!int '0x-30'
        # we prefer:
        # - offset: -0x30
        # the below regex makes these adjustments and while ugly, we don't have to explore the ruamel.yaml insides
        doc = re.sub(r"!!int '0x-([0-9a-fA-F]+)'", r"-0x\1", doc)

        # normalize CRLF to LF
        doc = doc.replace("\r\n", "\n")
        return doc


def get_rules_with_scope(rules, scope: Scope) -> List[Rule]:
    """
    from the given collection of rules, select those with the given scope.
    """
    return [rule for rule in rules if scope in rule.scopes]


def get_rules_and_dependencies(rules: List[Rule], rule_name: str) -> Iterator[Rule]:
    """
    from the given collection of rules, select a rule and its dependencies (transitively).
    """
    # we evaluate `rules` multiple times, so if its a generator, realize it into a list.
    rules = list(rules)
    namespaces = index_rules_by_namespace(rules)
    rules_by_name = {rule.name: rule for rule in rules}
    wanted = {rule_name}

    def rec(rule):
        wanted.add(rule.name)
        for dep in rule.get_dependencies(namespaces):
            rec(rules_by_name[dep])

    rec(rules_by_name[rule_name])

    for rule in rules_by_name.values():
        if rule.name in wanted:
            yield rule


def ensure_rules_are_unique(rules: List[Rule]) -> None:
    seen = set()
    for rule in rules:
        if rule.name in seen:
            raise InvalidRule("duplicate rule name: " + rule.name)
        seen.add(rule.name)


def ensure_rule_dependencies_are_met(rules: List[Rule]) -> None:
    """
    raise an exception if a rule dependency does not exist.

    raises:
      InvalidRule: if a dependency is not met.
    """
    # we evaluate `rules` multiple times, so if its a generator, realize it into a list.
    rules = list(rules)
    namespaces = index_rules_by_namespace(rules)
    rules_by_name = {rule.name: rule for rule in rules}
    for rule in rules_by_name.values():
        for dep in rule.get_dependencies(namespaces):
            if dep not in rules_by_name:
                raise InvalidRule(f'rule "{rule.name}" depends on missing rule "{dep}"')


def index_rules_by_namespace(rules: List[Rule]) -> Dict[str, List[Rule]]:
    """
    compute the rules that fit into each namespace found within the given rules.

    for example, given:

      - c2/shell :: create reverse shell
      - c2/file-transfer :: download and write a file

    return the index:

      c2/shell: [create reverse shell]
      c2/file-transfer: [download and write a file]
      c2: [create reverse shell, download and write a file]
    """
    namespaces = collections.defaultdict(list)

    for rule in rules:
        namespace = rule.meta.get("namespace")
        if not namespace:
            continue

        while namespace:
            namespaces[namespace].append(rule)
            namespace, _, _ = namespace.rpartition("/")

    return dict(namespaces)


def topologically_order_rules(rules: List[Rule]) -> List[Rule]:
    """
    order the given rules such that dependencies show up before dependents.
    this means that as we match rules, we can add features for the matches, and these
     will be matched by subsequent rules if they follow this order.

    assumes that the rule dependency graph is a DAG.
    """
    # we evaluate `rules` multiple times, so if its a generator, realize it into a list.
    rules = list(rules)
    namespaces = index_rules_by_namespace(rules)
    rules_by_name = {rule.name: rule for rule in rules}
    seen = set()
    ret = []

    def rec(rule):
        if rule.name in seen:
            return

        for dep in rule.get_dependencies(namespaces):
            rec(rules_by_name[dep])

        ret.append(rule)
        seen.add(rule.name)

    for rule in rules_by_name.values():
        rec(rule)

    return ret


class RuleSet:
    """
    a ruleset is initialized with a collection of rules, which it verifies and sorts into scopes.
    each set of scoped rules is sorted topologically, which enables rules to match on past rule matches.

    example:

        ruleset = RuleSet([
          Rule(...),
          Rule(...),
          ...
        ])
        capa.engine.match(ruleset.file_rules, ...)
    """

    def __init__(
        self,
        rules: List[Rule],
    ):
        super().__init__()

        ensure_rules_are_unique(rules)

        # in the next step we extract subscope rules,
        # which may inflate the number of rules tracked in this ruleset.
        # so record number of rules initially provided to this ruleset.
        #
        # this number is really only meaningful to the user,
        # who may compare it against the number of files on their file system.
        self.source_rule_count = len(rules)

        rules = self._extract_subscope_rules(rules)

        ensure_rule_dependencies_are_met(rules)

        if len(rules) == 0:
            raise InvalidRuleSet("no rules selected")

        rules = capa.optimizer.optimize_rules(rules)

        self.file_rules = self._get_rules_for_scope(rules, Scope.FILE)
        self.process_rules = self._get_rules_for_scope(rules, Scope.PROCESS)
        self.thread_rules = self._get_rules_for_scope(rules, Scope.THREAD)
        self.call_rules = self._get_rules_for_scope(rules, Scope.CALL)
        self.function_rules = self._get_rules_for_scope(rules, Scope.FUNCTION)
        self.basic_block_rules = self._get_rules_for_scope(rules, Scope.BASIC_BLOCK)
        self.instruction_rules = self._get_rules_for_scope(rules, Scope.INSTRUCTION)
        self.rules = {rule.name: rule for rule in rules}
        self.rules_by_namespace = index_rules_by_namespace(rules)

        # unstable
        (self._easy_file_rules_by_feature, self._hard_file_rules) = self._index_rules_by_feature(self.file_rules)
        (self._easy_process_rules_by_feature, self._hard_process_rules) = self._index_rules_by_feature(
            self.process_rules
        )
        (self._easy_thread_rules_by_feature, self._hard_thread_rules) = self._index_rules_by_feature(self.thread_rules)
        (self._easy_call_rules_by_feature, self._hard_call_rules) = self._index_rules_by_feature(self.call_rules)
        (self._easy_function_rules_by_feature, self._hard_function_rules) = self._index_rules_by_feature(
            self.function_rules
        )
        (self._easy_basic_block_rules_by_feature, self._hard_basic_block_rules) = self._index_rules_by_feature(
            self.basic_block_rules
        )
        (self._easy_instruction_rules_by_feature, self._hard_instruction_rules) = self._index_rules_by_feature(
            self.instruction_rules
        )

    def __len__(self):
        return len(self.rules)

    def __getitem__(self, rulename):
        return self.rules[rulename]

    def __contains__(self, rulename):
        return rulename in self.rules

    @staticmethod
    def _index_rules_by_feature(rules) -> Tuple[Dict[Feature, Set[str]], List[str]]:
        """
        split the given rules into two structures:
          - "easy rules" are indexed by feature,
            such that you can quickly find the rules that contain a given feature.
          - "hard rules" are those that contain substring/regex/bytes features or match statements.
            these continue to be ordered topologically.

        a rule evaluator can use the "easy rule" index to restrict the
        candidate rules that might match a given set of features.

        at this time, a rule evaluator can't do anything special with
        the "hard rules". it must still do a full top-down match of each
        rule, in topological order.

        this does not index global features, because these are not selective, and
        won't be used as the sole feature used to match.
        """

        # we'll do a couple phases:
        #
        #  1. recursively visit all nodes in all rules,
        #    a. indexing all features
        #    b. recording the types of features found per rule
        #  2. compute the easy and hard rule sets
        #  3. remove hard rules from the rules-by-feature index
        #  4. construct the topologically ordered list of hard rules
        rules_with_easy_features: Set[str] = set()
        rules_with_hard_features: Set[str] = set()
        rules_by_feature: Dict[Feature, Set[str]] = collections.defaultdict(set)

        def rec(rule_name: str, node: Union[Feature, Statement]):
            """
            walk through a rule's logic tree, indexing the easy and hard rules,
            and the features referenced by easy rules.
            """
            if isinstance(
                node,
                (
                    # these are the "hard features"
                    # substring: scanning feature
                    capa.features.common.Substring,
                    # regex: scanning feature
                    capa.features.common.Regex,
                    # bytes: scanning feature
                    capa.features.common.Bytes,
                    # match: dependency on another rule,
                    # which we have to evaluate first,
                    # and is therefore tricky.
                    capa.features.common.MatchedRule,
                ),
            ):
                # hard feature: requires scan or match lookup
                rules_with_hard_features.add(rule_name)
            elif isinstance(node, capa.features.common.Feature):
                if capa.features.common.is_global_feature(node):
                    # we don't want to index global features
                    # because they're not very selective.
                    #
                    # they're global, so if they match at one location in a file,
                    # they'll match at every location in a file.
                    # so thats not helpful to decide how to downselect.
                    #
                    # and, a global rule will never be the sole selector in a rule.
                    pass
                else:
                    # easy feature: hash lookup
                    rules_with_easy_features.add(rule_name)
                    rules_by_feature[node].add(rule_name)
            elif isinstance(node, (ceng.Not)):
                # `not:` statements are tricky to deal with.
                #
                # first, features found under a `not:` should not be indexed,
                # because they're not wanted to be found.
                # second, `not:` can be nested under another `not:`, or two, etc.
                # third, `not:` at the root or directly under an `or:`
                # means the rule will match against *anything* not specified there,
                # which is a difficult set of things to compute and index.
                #
                # so, if a rule has a `not:` statement, its hard.
                # as of writing, this is an uncommon statement, with only 6 instances in 740 rules.
                rules_with_hard_features.add(rule_name)
            elif isinstance(node, (ceng.Some)) and node.count == 0:
                # `optional:` and `0 or more:` are tricky to deal with.
                #
                # when a subtree is optional, it may match, but not matching
                # doesn't have any impact either.
                # now, our rule authors *should* not put this under `or:`
                # and this is checked by the linter,
                # but this could still happen (e.g. private rule set without linting)
                # and would be hard to trace down.
                #
                # so better to be safe than sorry and consider this a hard case.
                rules_with_hard_features.add(rule_name)
            elif isinstance(node, (ceng.Range)) and node.min == 0:
                # `count(foo): 0 or more` are tricky to deal with.
                # because the min is 0,
                # this subtree *can* match just about any feature
                # (except the given one)
                # which is a difficult set of things to compute and index.
                rules_with_hard_features.add(rule_name)
            elif isinstance(node, (ceng.Range)):
                rec(rule_name, node.child)
            elif isinstance(node, (ceng.And, ceng.Or, ceng.Some)):
                for child in node.children:
                    rec(rule_name, child)
            elif isinstance(node, ceng.Statement):
                # unhandled type of statement.
                # this should only happen if a new subtype of `Statement`
                # has since been added to capa.
                #
                # ideally, we'd like to use mypy for exhaustiveness checking
                # for all the subtypes of `Statement`.
                # but, as far as i can tell, mypy does not support this type
                # of checking.
                #
                # in a way, this makes some intuitive sense:
                # the set of subtypes of type A is unbounded,
                # because any user might come along and create a new subtype B,
                # so mypy can't reason about this set of types.
                assert_never(node)
            else:
                # programming error
                assert_never(node)

        for rule in rules:
            rule_name = rule.meta["name"]
            root = rule.statement
            rec(rule_name, root)

        # if a rule has a hard feature,
        # dont consider it easy, and therefore,
        # don't index any of its features.
        #
        # otherwise, its an easy rule, and index its features
        for rules_with_feature in rules_by_feature.values():
            rules_with_feature.difference_update(rules_with_hard_features)
        easy_rules_by_feature = rules_by_feature

        # `rules` is already topologically ordered,
        # so extract our hard set into the topological ordering.
        hard_rules = []
        for rule in rules:
            if rule.meta["name"] in rules_with_hard_features:
                hard_rules.append(rule.meta["name"])

        return (easy_rules_by_feature, hard_rules)

    @staticmethod
    def _get_rules_for_scope(rules, scope) -> List[Rule]:
        """
        given a collection of rules, collect the rules that are needed at the given scope.
        these rules are ordered topologically.

        don't include auto-generated "subscope" rules.
        we want to include general "lib" rules here - even if they are not dependencies of other rules, see #398
        """
        scope_rules: Set[Rule] = set()

        # we need to process all rules, not just rules with the given scope.
        # this is because rules with a higher scope, e.g. file scope, may have subscope rules
        #  at lower scope, e.g. function scope.
        # so, we find all dependencies of all rules, and later will filter them down.
        for rule in rules:
            if rule.is_subscope_rule():
                continue

            scope_rules.update(get_rules_and_dependencies(rules, rule.name))
        return get_rules_with_scope(topologically_order_rules(list(scope_rules)), scope)

    @staticmethod
    def _extract_subscope_rules(rules) -> List[Rule]:
        """
        process the given sequence of rules.
        for each one, extract any embedded subscope rules into their own rule.
        process these recursively.
        then return a list of the refactored rules.

        note: this operation mutates the rules passed in - they may now have `match` statements
         for the extracted subscope rules.
        """
        done = []

        # use a queue of rules, because we'll be modifying the list (appending new items) as we go.
        while rules:
            rule = rules.pop(0)
            for subscope_rule in rule.extract_subscope_rules():
                rules.append(subscope_rule)
            done.append(rule)

        return done

    def filter_rules_by_meta(self, tag: str) -> "RuleSet":
        """
        return new rule set with rules filtered based on all meta field values, adds all dependency rules
        apply tag-based rule filter assuming that all required rules are loaded
        can be used to specify selected rules vs. providing a rules child directory where capa cannot resolve
        dependencies from unknown paths
        TODO handle circular dependencies?
        TODO support -t=metafield <k>
        """
        rules = list(self.rules.values())
        rules_filtered = set()
        for rule in rules:
            for k, v in rule.meta.items():
                if isinstance(v, str) and tag in v:
                    logger.debug('using rule "%s" and dependencies, found tag in meta.%s: %s', rule.name, k, v)
                    rules_filtered.update(set(get_rules_and_dependencies(rules, rule.name)))
                    break
                if isinstance(v, list):
                    for vv in v:
                        if tag in vv:
                            logger.debug('using rule "%s" and dependencies, found tag in meta.%s: %s', rule.name, k, vv)
                            rules_filtered.update(set(get_rules_and_dependencies(rules, rule.name)))
                            break
        return RuleSet(list(rules_filtered))

    def match(self, scope: Scope, features: FeatureSet, addr: Address) -> Tuple[FeatureSet, ceng.MatchResults]:
        """
        match rules from this ruleset at the given scope against the given features.

        this routine should act just like `capa.engine.match`,
        except that it may be more performant.
        """
        easy_rules_by_feature = {}
        if scope == Scope.FILE:
            easy_rules_by_feature = self._easy_file_rules_by_feature
            hard_rule_names = self._hard_file_rules
        elif scope == Scope.PROCESS:
            easy_rules_by_feature = self._easy_process_rules_by_feature
            hard_rule_names = self._hard_process_rules
        elif scope == Scope.THREAD:
            easy_rules_by_feature = self._easy_thread_rules_by_feature
            hard_rule_names = self._hard_thread_rules
        elif scope == Scope.CALL:
            easy_rules_by_feature = self._easy_call_rules_by_feature
            hard_rule_names = self._hard_call_rules
        elif scope == Scope.FUNCTION:
            easy_rules_by_feature = self._easy_function_rules_by_feature
            hard_rule_names = self._hard_function_rules
        elif scope == Scope.BASIC_BLOCK:
            easy_rules_by_feature = self._easy_basic_block_rules_by_feature
            hard_rule_names = self._hard_basic_block_rules
        elif scope == Scope.INSTRUCTION:
            easy_rules_by_feature = self._easy_instruction_rules_by_feature
            hard_rule_names = self._hard_instruction_rules
        else:
            assert_never(scope)

        candidate_rule_names = set()
        for feature in features:
            easy_rule_names = easy_rules_by_feature.get(feature)
            if easy_rule_names:
                candidate_rule_names.update(easy_rule_names)

        # first, match against the set of rules that have at least one
        # feature shared with our feature set.
        candidate_rules = [self.rules[name] for name in candidate_rule_names]
        features2, easy_matches = ceng.match(candidate_rules, features, addr)

        # note that we've stored the updated feature set in `features2`.
        # this contains a superset of the features in `features`;
        # it contains additional features for any easy rule matches.
        # we'll pass this feature set to hard rule matching, since one
        # of those rules might rely on an easy rule match.
        #
        # the updated feature set from hard matching will go into `features3`.
        # this is a superset of `features2` is a superset of `features`.
        # ultimately, this is what we'll return to the caller.
        #
        # in each case, we could have assigned the updated feature set back to `features`,
        # but this is slightly more explicit how we're tracking the data.

        # now, match against (topologically ordered) list of rules
        # that we can't really make any guesses about.
        # these are rules with hard features, like substring/regex/bytes and match statements.
        hard_rules = [self.rules[name] for name in hard_rule_names]
        features3, hard_matches = ceng.match(hard_rules, features2, addr)

        # note that above, we probably are skipping matching a bunch of
        # rules that definitely would never hit.
        # specifically, "easy rules" that don't share any features with
        # feature set.

        # MatchResults doesn't technically have an .update() method
        # but a dict does.
        matches = {}  # type: ignore
        matches.update(easy_matches)
        matches.update(hard_matches)

        return (features3, matches)


def is_nursery_rule_path(path: Path) -> bool:
    """
    The nursery is a spot for rules that have not yet been fully polished.
    For example, they may not have references to public example of a technique.
    Yet, we still want to capture and report on their matches.
    The nursery is currently a subdirectory of the rules directory with that name.

    When nursery rules are loaded, their metadata section should be updated with:
      `nursery=True`.
    """
    return "nursery" in path.parts


def collect_rule_file_paths(rule_paths: List[Path]) -> List[Path]:
    """
    collect all rule file paths, including those in subdirectories.
    """
    rule_file_paths = []
    for rule_path in rule_paths:
        if not rule_path.exists():
            raise IOError(f"rule path {rule_path} does not exist or cannot be accessed")

        if rule_path.is_file():
            rule_file_paths.append(rule_path)
        elif rule_path.is_dir():
            logger.debug("reading rules from directory %s", rule_path)
            for root, _, files in os.walk(rule_path):
                if ".git" in root:
                    # the .github directory contains CI config in capa-rules
                    # this includes some .yml files
                    # these are not rules
                    # additionally, .git has files that are not .yml and generate the warning
                    # skip those too
                    continue
                for file in files:
                    if not file.endswith(".yml"):
                        if not (file.startswith(".git") or file.endswith((".git", ".md", ".txt"))):
                            # expect to see .git* files, readme.md, format.md, and maybe a .git directory
                            # other things maybe are rules, but are mis-named.
                            logger.warning("skipping non-.yml file: %s", file)
                        continue
                    rule_file_paths.append(Path(root) / file)
    return rule_file_paths


# TypeAlias. note: using `foo: TypeAlias = bar` is Python 3.10+
RulePath = Path


def on_load_rule_default(_path: RulePath, i: int, _total: int) -> None:
    return


def get_rules(
    rule_paths: List[RulePath],
    cache_dir=None,
    on_load_rule: Callable[[RulePath, int, int], None] = on_load_rule_default,
) -> RuleSet:
    """
    args:
      rule_paths: list of paths to rules files or directories containing rules files
      cache_dir: directory to use for caching rules, or will use the default detected cache directory if None
      on_load_rule: callback to invoke before a rule is loaded, use for progress or cancellation
    """
    if cache_dir is None:
        cache_dir = capa.rules.cache.get_default_cache_directory()
    # rule_paths may contain directory paths,
    # so search for file paths recursively.
    rule_file_paths = collect_rule_file_paths(rule_paths)

    # this list is parallel to `rule_file_paths`:
    # rule_file_paths[i] corresponds to rule_contents[i].
    rule_contents = [file_path.read_bytes() for file_path in rule_file_paths]

    ruleset = capa.rules.cache.load_cached_ruleset(cache_dir, rule_contents)
    if ruleset is not None:
        return ruleset

    rules: List[Rule] = []

    total_rule_count = len(rule_file_paths)
    for i, (path, content) in enumerate(zip(rule_file_paths, rule_contents)):
        on_load_rule(path, i, total_rule_count)

        try:
            rule = capa.rules.Rule.from_yaml(content.decode("utf-8"))
        except capa.rules.InvalidRule:
            raise
        else:
            rule.meta["capa/path"] = path.as_posix()
            rule.meta["capa/nursery"] = is_nursery_rule_path(path)

            rules.append(rule)
            logger.debug("loaded rule: '%s' with scope: %s", rule.name, rule.scopes)

    ruleset = capa.rules.RuleSet(rules)

    capa.rules.cache.cache_ruleset(cache_dir, ruleset)

    return ruleset
