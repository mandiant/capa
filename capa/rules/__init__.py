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


import io
import os
import re
import copy
import uuid
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

from typing import Any, Union, Callable, Iterator, Optional, cast
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
    def from_dict(self, scopes: dict[str, str]) -> "Scopes":
        # make local copy so we don't make changes outside of this routine.
        # we'll use the value None to indicate the scope is not supported.
        scopes_: dict[str, Optional[str]] = dict(scopes)

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


SUPPORTED_FEATURES: dict[str, set] = {
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
    supported_features: set = set()
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
    guids: Optional[list[str]] = com_db.get(com_name)
    if not guids:
        logger.error(" %s doesn't exist in COM %s database", com_name, com_type)
        raise InvalidRule(f"'{com_name}' doesn't exist in COM {com_type} database")

    com_features: list[Feature] = []
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
        b = bytes.fromhex(s.replace(" ", ""))
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


def unique(sequence):
    """deduplicate the items in the given sequence, returning a list with the same order.

    via: https://stackoverflow.com/a/58666031
    """
    seen = set()
    return [x for x in sequence if not (x in seen or seen.add(x))]  # type: ignore [func-returns-value]


def build_statements(d, scopes: Scopes):
    if len(d.keys()) > 2:
        raise InvalidRule("too many statements")

    key = list(d.keys())[0]
    description = pop_statement_description_entry(d[key])
    if key == "and":
        return ceng.And(unique(build_statements(dd, scopes) for dd in d[key]), description=description)
    elif key == "or":
        return ceng.Or(unique(build_statements(dd, scopes) for dd in d[key]), description=description)
    elif key == "not":
        if len(d[key]) != 1:
            raise InvalidRule("not statement must have exactly one child statement")
        return ceng.Not(build_statements(d[key][0], scopes), description=description)
    elif key.endswith(" or more"):
        count = int(key[: -len("or more")])
        return ceng.Some(count, unique(build_statements(dd, scopes) for dd in d[key]), description=description)
    elif key == "optional":
        # `optional` is an alias for `0 or more`
        # which is useful for documenting behaviors,
        # like with `write file`, we might say that `WriteFile` is optionally found alongside `CreateFileA`.
        return ceng.Some(0, unique(build_statements(dd, scopes) for dd in d[key]), description=description)

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
        if all(s not in scopes for s in (Scope.FILE, Scope.PROCESS, Scope.THREAD, Scope.CALL)):
            raise InvalidRule("call subscope supported only for the process, thread, and call scopes")

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
            statements = ceng.And(unique(build_statements(dd, Scopes(static=Scope.INSTRUCTION)) for dd in d[key]))

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


def first(s: list[Any]) -> Any:
    return s[0]


def second(s: list[Any]) -> Any:
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
          namespaces(dict[str, list[Rule]]): mapping from namespace name to rules in it.
            see `index_rules_by_namespace`.

        Returns:
          list[str]: names of rules upon which this rule depends.
        """
        deps: set[str] = set()

        def rec(statement):
            if isinstance(statement, capa.features.common.MatchedRule):
                # we're not sure at this point if the `statement.value` is
                #  really a rule name or a namespace name (we use `MatchedRule` for both cases).
                # we'll give precedence to namespaces, and then assume if that does work,
                #  that it must be a rule name.
                #
                # we don't expect any collisions between namespaces and rule names, but it's possible.
                # most likely would be collision between top level namespace (e.g. `host-interaction`) and rule name.
                # but, namespaces tend to use `-` while rule names use ` `. so, unlikely, but possible.
                if statement.value in namespaces:
                    # matches a namespace, so take precedence and don't even check rule names.
                    deps.update(r.name for r in namespaces[statement.value])
                else:
                    # not a namespace, assume it's a rule name.
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

    def _extract_all_features_rec(self, statement) -> set[Feature]:
        feature_set: set[Feature] = set()

        for child in statement.get_children():
            if isinstance(child, Statement):
                feature_set.update(self._extract_all_features_rec(child))
            else:
                feature_set.add(child)
        return feature_set

    def extract_all_features(self) -> set[Feature]:
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
    def from_dict(cls, d: dict[str, Any], definition: str) -> "Rule":
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


def get_rules_with_scope(rules, scope: Scope) -> list[Rule]:
    """
    from the given collection of rules, select those with the given scope.
    """
    return [rule for rule in rules if scope in rule.scopes]


def get_rules_and_dependencies(rules: list[Rule], rule_name: str) -> Iterator[Rule]:
    """
    from the given collection of rules, select a rule and its dependencies (transitively).
    """
    # we evaluate `rules` multiple times, so if it's a generator, realize it into a list.
    rules = list(rules)
    namespaces = index_rules_by_namespace(rules)
    rules_by_name = {rule.name: rule for rule in rules}
    wanted = {rule_name}
    visited = set()

    def rec(rule: Rule):
        wanted.add(rule.name)
        visited.add(rule.name)

        for dep in rule.get_dependencies(namespaces):
            if dep in visited:
                raise InvalidRule(f'rule "{dep}" has a circular dependency')
            rec(rules_by_name[dep])
        visited.remove(rule.name)

    rec(rules_by_name[rule_name])

    for rule in rules_by_name.values():
        if rule.name in wanted:
            yield rule


def ensure_rules_are_unique(rules: list[Rule]) -> None:
    seen = set()
    for rule in rules:
        if rule.name in seen:
            raise InvalidRule("duplicate rule name: " + rule.name)
        seen.add(rule.name)


def ensure_rule_dependencies_are_met(rules: list[Rule]) -> None:
    """
    raise an exception if a rule dependency does not exist.

    raises:
      InvalidRule: if a dependency is not met.
    """
    # we evaluate `rules` multiple times, so if it's a generator, realize it into a list.
    rules = list(rules)
    namespaces = index_rules_by_namespace(rules)
    rules_by_name = {rule.name: rule for rule in rules}
    for rule in rules_by_name.values():
        for dep in rule.get_dependencies(namespaces):
            if dep not in rules_by_name:
                raise InvalidRule(f'rule "{rule.name}" depends on missing rule "{dep}"')


def index_rules_by_namespace(rules: list[Rule]) -> dict[str, list[Rule]]:
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


def topologically_order_rules(rules: list[Rule]) -> list[Rule]:
    """
    order the given rules such that dependencies show up before dependents.
    this means that as we match rules, we can add features for the matches, and these
     will be matched by subsequent rules if they follow this order.

    assumes that the rule dependency graph is a DAG.
    """
    # we evaluate `rules` multiple times, so if it's a generator, realize it into a list.
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
        rules: list[Rule],
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

        scopes = (
            Scope.CALL,
            Scope.THREAD,
            Scope.PROCESS,
            Scope.INSTRUCTION,
            Scope.BASIC_BLOCK,
            Scope.FUNCTION,
            Scope.FILE,
        )

        self.rules = {rule.name: rule for rule in rules}
        self.rules_by_namespace = index_rules_by_namespace(rules)
        self.rules_by_scope = {scope: self._get_rules_for_scope(rules, scope) for scope in scopes}

        # these structures are unstable and may change before the next major release.
        scores_by_rule: dict[str, int] = {}
        self._feature_indexes_by_scopes = {
            scope: self._index_rules_by_feature(scope, self.rules_by_scope[scope], scores_by_rule) for scope in scopes
        }

    @property
    def file_rules(self):
        return self.rules_by_scope[Scope.FILE]

    @property
    def process_rules(self):
        return self.rules_by_scope[Scope.PROCESS]

    @property
    def thread_rules(self):
        return self.rules_by_scope[Scope.THREAD]

    @property
    def call_rules(self):
        return self.rules_by_scope[Scope.CALL]

    @property
    def function_rules(self):
        return self.rules_by_scope[Scope.FUNCTION]

    @property
    def basic_block_rules(self):
        return self.rules_by_scope[Scope.BASIC_BLOCK]

    @property
    def instruction_rules(self):
        return self.rules_by_scope[Scope.INSTRUCTION]

    def __len__(self):
        return len(self.rules)

    def __getitem__(self, rulename):
        return self.rules[rulename]

    def __contains__(self, rulename):
        return rulename in self.rules

    # this routine is unstable and may change before the next major release.
    @staticmethod
    def _score_feature(scores_by_rule: dict[str, int], node: capa.features.common.Feature) -> int:
        """
        Score the given feature by how "uncommon" we think it will be.
        Features that we expect to be very selective (ie. uniquely identify a rule and be required to match),
         or "uncommon", should get a high score.
        Features that are not good for indexing will have a low score, or 0.

        The range of values doesn't really matter, but here we use 0-10, where
          - 10 is very uncommon, very selective, good for indexing a rule, and
          - 0 is a very common, not selective, bad for indexing a rule.

        You shouldn't try to interpret the scores, beyond to compare features to pick one or the other.

        Today, these scores are assigned manually, by the capa devs, who use their intuition and experience.
        We *could* do a large scale analysis of all features emitted by capa across many samples to
        make this more data driven. If the current approach doesn't work well, consider that.
        """

        #
        # Today, these scores are manually assigned by intuition/experience/guesswork.
        # We could do a large-scale feature collection and use the results to assign scores.
        #

        if isinstance(
            node,
            capa.features.common.MatchedRule,
        ):
            # The other rule must match before this one, in same scope or smaller.
            # Because we process the rules small->large scope and topologically,
            # then we can rely on dependencies being processed first.
            #
            # If logic changes and you see issues here, ensure that `scores_by_rule` is correctly provided.
            rule_name = node.value
            assert isinstance(rule_name, str)

            if rule_name not in scores_by_rule:
                # Its possible that we haven't scored the rule that is being requested here.
                # This means that it won't ever match (because it won't be evaluated before this one).
                # Still, we need to provide a default value here.
                # So we give it 9, because it won't match, so its very selective.
                #
                # But how could this dependency not exist?
                # Consider a rule that supports both static and dynamic analysis, but also has
                # a `instruction: ` block. This block gets translated into a derived rule that only
                # matches in static mode. Therefore, when the parent rule is run in dynamic mode, it
                # won't be able to find the derived rule. This is the case we have to handle here.
                #
                # A better solution would be to prune this logic based on static/dynamic mode, but
                # that takes more work and isn't in scope of this feature.
                #
                # See discussion in: https://github.com/mandiant/capa/pull/2080/#discussion_r1624783396
                return 9

            return scores_by_rule[rule_name]

        elif isinstance(node, (capa.features.insn.Number, capa.features.insn.OperandNumber)):
            v = node.value
            assert isinstance(v, int)

            if -0x8000 <= v <= 0x8000:
                # Small numbers are probably pretty common, like structure offsets, etc.
                return 3

            if 0xFFFF_FF00 <= v <= 0xFFFF_FFFF:
                # Numbers close to u32::max_int are also probably pretty common,
                # like signed numbers close to 0 that are stored as unsigned ints.
                return 3

            if 0xFFFF_FFFF_FFFF_FF00 <= v <= 0xFFFF_FFFF_FFFF_FFFF:
                # Like signed numbers closed to 0 that are stored as unsigned long ints.
                return 3

            # Other numbers are assumed to be uncommon.
            return 7

        elif isinstance(node, (capa.features.common.Substring, capa.features.common.Regex, capa.features.common.Bytes)):
            # Scanning features (non-hashable), which we can't use for quick matching/filtering.
            return 0

        C = node.__class__
        return {
            # The range of values doesn't really matter, but here we use 0-10, where
            #   - 10 is very uncommon, very selective, good for indexing a rule, and
            #   - 0 is a very common, not selective, bad for indexing a rule.
            #
            # You shouldn't try to interpret the scores, beyond to compare features to pick one or the other.
            # -----------------------------------------------------------------
            #
            # Very uncommon features that are probably very selective in capa's domain.
            # When possible, we want rules to be indexed by these features.
            #
            capa.features.common.String: 9,
            capa.features.insn.API: 8,
            capa.features.file.Export: 7,
            # "uncommon numbers": 7 (placeholder for logic above)
            #
            # -----------------------------------------------------------------
            #
            # Features that are probably somewhat common, and/or rarely used within capa.
            # Its ok to index rules by these.
            #
            capa.features.common.Class: 5,
            capa.features.common.Namespace: 5,
            capa.features.insn.Property: 5,
            capa.features.file.Import: 5,
            capa.features.file.Section: 5,
            capa.features.file.FunctionName: 5,
            #
            # -----------------------------------------------------------------
            #
            # Features that are pretty common and we'd prefer not to index, but can if we have to.
            #
            capa.features.common.Characteristic: 4,
            capa.features.insn.Offset: 4,
            capa.features.insn.OperandOffset: 4,
            # "common numbers": 3 (placeholder for logic above)
            #
            # -----------------------------------------------------------------
            #
            # Very common features, which we'd only prefer instead of non-hashable features, like Regex/Substring/Bytes.
            #
            capa.features.insn.Mnemonic: 2,
            capa.features.basicblock.BasicBlock: 1,
            #
            #
            # We don't *want* to index global features because they're not very selective.
            # They also don't usually stand on their own - there's always some other logic.
            #
            capa.features.common.OS: 0,
            capa.features.common.Arch: 0,
            capa.features.common.Format: 0,
            # -----------------------------------------------------------------
            #
            # Non-hashable features, which will require a scan to evaluate, and are therefore quite expensive.
            #
            # substring: 0 (placeholder for logic above)
            # regex: 0 (placeholder for logic above)
            # bytes: 0 (placeholder for logic above)
        }[C]

    # this class is unstable and may change before the next major release.
    @dataclass
    class _RuleFeatureIndex:
        # Mapping from hashable feature to a list of rules that might have this feature.
        rules_by_feature: dict[Feature, set[str]]
        # Mapping from rule name to list of Regex/Substring features that have to match.
        # All these features will be evaluated whenever a String feature is encountered.
        string_rules: dict[str, list[Feature]]
        # Mapping from rule name to list of Bytes features that have to match.
        # All these features will be evaluated whenever a Bytes feature is encountered.
        bytes_rules: dict[str, list[Feature]]

    # this routine is unstable and may change before the next major release.
    @staticmethod
    def _index_rules_by_feature(scope: Scope, rules: list[Rule], scores_by_rule: dict[str, int]) -> _RuleFeatureIndex:
        """
        Index the given rules by their minimal set of most "uncommon" features required to match.

        If absolutely necessary, provide the Regex/Substring/Bytes features
        (which are not hashable and require a scan) that have to match, too.
        """

        rules_by_feature: dict[Feature, set[str]] = collections.defaultdict(set)

        def rec(
            rule_name: str,
            node: Union[Feature, Statement],
        ) -> Optional[tuple[int, set[Feature]]]:
            """
            Walk through a rule's logic tree, picking the features to use for indexing,
            returning the feature and an associated score.
            The higher the score, the more selective the feature is expected to be.
            The score is only used internally, to pick the best feature from within AND blocks.

            Note closure over `scores_by_rule`.
            """

            if isinstance(node, (ceng.Not)):
                # We don't index features within NOT blocks, because we're only looking for
                # features that should be present.
                #
                # Technically we could have a rule that does `not: not: foo` and we'd want to
                # index `foo`. But this is not seen today.
                return None

            elif isinstance(node, (ceng.Some)) and node.count == 0:
                # When a subtree is optional, it may match, but not matching
                # doesn't have any impact either.
                # Now, our rule authors *should* not put this under `or:`
                # and this is checked by the linter,
                return None

            elif isinstance(node, (ceng.Range)) and node.min == 0 and node.max != 0:
                # `count(foo): 0 or more` is just like an optional block,
                # because the min is 0, this subtree *can* match just about any feature.
                return None

            elif isinstance(node, (ceng.Range)) and node.min == 0 and node.max == 0:
                # `count(foo): 0` is like a not block, which we don't index.
                return None

            elif isinstance(node, capa.features.common.Feature):
                return (RuleSet._score_feature(scores_by_rule, node), {node})

            elif isinstance(node, (ceng.Range)):
                # feature is found N times
                return rec(rule_name, node.child)

            elif isinstance(node, ceng.And):
                # When evaluating an AND block, all of the children need to match.
                #
                # So when we index rules, we want to pick the most uncommon feature(s)
                # for each AND block. If the AND block matches, that feature must be there.
                # We recursively explore children, computing their
                # score, and pick the child with the greatest score.
                #
                # For example, given the rule:
                #
                #     and:
                #       - mnemonic: mov
                #       - api: CreateFile
                #
                # we prefer to pick `api: CreateFile` because we expect it to be more uncommon.
                #
                # Note that the children nodes might be complex, like:
                #
                #     and:
                #       - mnemonic: mov
                #       - or:
                #         - api: CreateFile
                #         - api: DeleteFile
                #
                # In this case, we prefer to pick the pair of API features since each is expected
                # to be more common than the mnemonic.
                scores: list[tuple[int, set[Feature]]] = []
                for child in node.children:
                    score = rec(rule_name, child)

                    if not score:
                        # maybe an optional block or similar
                        continue

                    scores.append(score)

                # otherwise we can't index this rule
                assert len(scores) > 0

                def and_score_key(item):
                    # order by score, then fewest number of features.
                    score, features = item
                    return (score, -len(features))

                scores.sort(key=and_score_key, reverse=True)

                # pick the best feature
                return scores[0]

            elif isinstance(node, (ceng.Or, ceng.Some)):
                # When evaluating an OR block, any of the children need to match.
                # It could be any of them, so we can't decide to only index some of them.
                #
                # For example, given the rule:
                #
                #     or:
                #       - mnemonic: mov
                #       - api: CreateFile
                #
                # we have to pick both `mnemonic` and `api` features.
                #
                # Note that the children nodes might be complex, like:
                #
                #     or:
                #       - mnemonic: mov
                #       - and:
                #         - api: CreateFile
                #         - api: DeleteFile
                #
                # In this case, we have to pick both the `mnemonic` and one of the `api` features.
                #
                # When computing the score of an OR branch, we have to use the min value encountered.
                # While many of the children might be very specific, there might be a branch that is common
                # and we need to handle that correctly.
                min_score = 10000000  # assume this is larger than any score
                features = set()

                for child in node.children:
                    item = rec(rule_name, child)
                    assert item is not None, "can't index OR branch"

                    _score, _features = item
                    min_score = min(min_score, _score)
                    features.update(_features)

                return min_score, features

            else:
                # programming error
                assert_never(node)

        # These are the Regex/Substring/Bytes features that we have to use for filtering.
        # Ideally we find a way to get rid of all of these, eventually.
        string_rules: dict[str, list[Feature]] = {}
        bytes_rules: dict[str, list[Feature]] = {}

        for rule in rules:
            rule_name = rule.meta["name"]

            root = rule.statement
            item = rec(rule_name, root)
            assert item is not None
            score, features = item

            string_features = [
                feature
                for feature in features
                if isinstance(feature, (capa.features.common.Substring, capa.features.common.Regex))
            ]
            bytes_features = [feature for feature in features if isinstance(feature, capa.features.common.Bytes)]
            hashable_features = [
                feature
                for feature in features
                if not isinstance(
                    feature, (capa.features.common.Substring, capa.features.common.Regex, capa.features.common.Bytes)
                )
            ]

            logger.debug("indexing: features: %d, score: %d, rule: %s", len(features), score, rule_name)
            scores_by_rule[rule_name] = score
            for feature in features:
                logger.debug("        : [%d] %s", RuleSet._score_feature(scores_by_rule, feature), feature)

            if string_features:
                string_rules[rule_name] = cast(list[Feature], string_features)

            if bytes_features:
                bytes_rules[rule_name] = cast(list[Feature], bytes_features)

            for feature in hashable_features:
                rules_by_feature[feature].add(rule_name)

        logger.debug("indexing: %d features indexed for scope %s", len(rules_by_feature), scope)
        logger.debug(
            "indexing: %d indexed features are shared by more than 3 rules",
            len([feature for feature, rules in rules_by_feature.items() if len(rules) > 3]),
        )
        logger.debug(
            "indexing: %d scanning string features, %d scanning bytes features", len(string_rules), len(bytes_rules)
        )

        return RuleSet._RuleFeatureIndex(rules_by_feature, string_rules, bytes_rules)

    @staticmethod
    def _get_rules_for_scope(rules, scope) -> list[Rule]:
        """
        given a collection of rules, collect the rules that are needed at the given scope.
        these rules are ordered topologically.

        don't include auto-generated "subscope" rules.
        we want to include general "lib" rules here - even if they are not dependencies of other rules, see #398
        """
        scope_rules: set[Rule] = set()

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
    def _extract_subscope_rules(rules) -> list[Rule]:
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

    # this routine is unstable and may change before the next major release.
    @staticmethod
    def _sort_rules_by_index(rule_index_by_rule_name: dict[str, int], rules: list[Rule]):
        """
        Sort (in place) the given rules by their index provided by the given dict.
        This mapping is intended to represent the topologic index of the given rule;
         that is, rules with a lower index should be evaluated first, since their dependencies
         will be evaluated later.
        """
        rules.sort(key=lambda r: rule_index_by_rule_name[r.name])

    def _match(self, scope: Scope, features: FeatureSet, addr: Address) -> tuple[FeatureSet, ceng.MatchResults]:
        """
        Match rules from this ruleset at the given scope against the given features.

        This routine should act just like `capa.engine.match`, except that it may be more performant.
        It uses its knowledge of all the rules to evaluate a minimal set of candidate rules for the given features.
        """

        feature_index: RuleSet._RuleFeatureIndex = self._feature_indexes_by_scopes[scope]
        rules: list[Rule] = self.rules_by_scope[scope]
        # Topologic location of rule given its name.
        # That is, rules with a lower index should be evaluated first, since their dependencies
        # will be evaluated later.
        rule_index_by_rule_name = {rule.name: i for i, rule in enumerate(rules)}

        # This algorithm is optimized to evaluate as few rules as possible,
        # because the less work we do, the faster capa can run.
        #
        # It relies on the observation that most rules don't match,
        # and that most rules have an uncommon feature that *must* be present for the rule to match.
        #
        # Therefore, we record which uncommon feature(s) is required for each rule to match,
        # and then only inspect these few candidates when a feature is seen in some scope.
        # Ultimately, the exact same rules are matched with precisely the same results,
        # its just done faster, because we ignore most of the rules that never would have matched anyways.
        #
        # In `_index_rules_by_feature`, we do the hard work of computing the minimal set of
        # uncommon features for each rule. While its a little expensive, its a single pass
        # that gets reused at every scope instance (read: thousands or millions of times).
        #
        # In the current routine, we collect all the rules that might match, given the presence
        # of any uncommon feature. We sort the rules topographically, so that rule dependencies work out,
        # and then we evaluate the candidate rules. In practice, this saves 20-50x the work!
        #
        # Recall that some features cannot be matched quickly via hash lookup: Regex, Bytes, etc.
        # When these features are the uncommon features used to filter rules, we have to evaluate the
        # feature frequently whenever a string/bytes feature is encountered. Its slow, but we can't
        # get around it. Reducing our reliance on regex/bytes feature and/or finding a way to
        # index these can futher improve performance.
        #
        # See the corresponding unstable tests in `test_match.py::test_index_features_*`.

        # Find all the rules that could match the given feature set.
        # Ideally we want this set to be as small and focused as possible,
        # and we can tune it by tweaking `_index_rules_by_feature`.
        candidate_rule_names: set[str] = set()
        for feature in features:
            candidate_rule_names.update(feature_index.rules_by_feature.get(feature, ()))

        # Some rules rely totally on regex features, like the HTTP User-Agent rules.
        # In these cases, when we encounter any string feature, we have to scan those
        # regexes to find the candidate rules.
        # As mentioned above, this is not good for performance, but its required for correctness.
        #
        # We may want to try to pre-evaluate these strings, based on their presence in the file,
        # to reduce the number of evaluations we do here.
        # See: https://github.com/mandiant/capa/issues/2126
        #
        # We may also want to specialize case-insensitive strings, which would enable them to
        # be indexed, and therefore skip the scanning here, improving performance.
        # This strategy is described here:
        # https://github.com/mandiant/capa/issues/2129
        if feature_index.string_rules:
            # This is a FeatureSet that contains only String features.
            # Since we'll only be evaluating String/Regex features below, we don't care about
            # other sorts of features (Mnemonic, Number, etc.) and therefore can save some time
            # during evaluation.
            #
            # Specifically, we can address the issue described here:
            # https://github.com/mandiant/capa/issues/2063#issuecomment-2095397884
            # That we spend a lot of time collecting String instances within `Regex.evaluate`.
            # We don't have to address that issue further as long as we pre-filter the features here.
            string_features: FeatureSet = {}
            for feature, locations in features.items():
                if isinstance(feature, capa.features.common.String):
                    string_features[feature] = locations

            if string_features:
                for rule_name, wanted_strings in feature_index.string_rules.items():
                    for wanted_string in wanted_strings:
                        if wanted_string.evaluate(string_features):
                            candidate_rule_names.add(rule_name)

        # Like with String/Regex features above, we have to scan for Bytes to find candidate rules.
        #
        # We may want to index bytes when they have a common length, like 16 or 32.
        # This would help us avoid the scanning here, which would improve performance.
        # The strategy is described here:
        # https://github.com/mandiant/capa/issues/2128
        if feature_index.bytes_rules:
            bytes_features: FeatureSet = {}
            for feature, locations in features.items():
                if isinstance(feature, capa.features.common.Bytes):
                    bytes_features[feature] = locations

            if bytes_features:
                for rule_name, wanted_bytess in feature_index.bytes_rules.items():
                    for wanted_bytes in wanted_bytess:
                        if wanted_bytes.evaluate(bytes_features):
                            candidate_rule_names.add(rule_name)

        # No rules can possibly match, so quickly return.
        if not candidate_rule_names:
            return (features, {})

        # Here are the candidate rules (before we just had their names).
        candidate_rules = [self.rules[name] for name in candidate_rule_names]

        # Order rules topologically, so that rules with dependencies work correctly.
        RuleSet._sort_rules_by_index(rule_index_by_rule_name, candidate_rules)

        #
        # The following is derived from ceng.match
        # extended to interact with candidate_rules upon rule match.
        #

        results: ceng.MatchResults = collections.defaultdict(list)

        # If we match a rule, then we'll add a MatchedRule to the features that will be returned,
        # but we want to do that in a copy. We'll lazily create the copy below, once a match has
        # actually been found.
        augmented_features = features

        while candidate_rules:
            rule = candidate_rules.pop(0)
            res = rule.evaluate(augmented_features, short_circuit=True)
            if res:
                # we first matched the rule with short circuiting enabled.
                # this is much faster than without short circuiting.
                # however, we want to collect all results thoroughly,
                # so once we've found a match quickly,
                # go back and capture results without short circuiting.
                res = rule.evaluate(augmented_features, short_circuit=False)

                # sanity check
                assert bool(res) is True

                results[rule.name].append((addr, res))
                # We need to update the current features because subsequent iterations may use newly added features,
                # such as rule or namespace matches.
                if augmented_features is features:
                    # lazily create the copy of features only when a rule matches, since it could be expensive.
                    augmented_features = collections.defaultdict(set, copy.copy(features))

                ceng.index_rule_matches(augmented_features, rule, [addr])

                # Its possible that we're relying on a MatchedRule (or namespace) feature to be the
                # uncommon feature used to filter other rules. So, extend the candidate
                # rules with any of these dependencies. If we find any, also ensure they're
                # evaluated in the correct topologic order, so that further dependencies work.
                new_features = [capa.features.common.MatchedRule(rule.name)]
                for namespace in ceng.get_rule_namespaces(rule):
                    new_features.append(capa.features.common.MatchedRule(namespace))

                if new_features:
                    new_candidates: list[str] = []
                    for new_feature in new_features:
                        new_candidates.extend(feature_index.rules_by_feature.get(new_feature, ()))

                    if new_candidates:
                        candidate_rule_names.update(new_candidates)
                        candidate_rules.extend([self.rules[rule_name] for rule_name in new_candidates])
                        RuleSet._sort_rules_by_index(rule_index_by_rule_name, candidate_rules)

        return (augmented_features, results)

    def match(
        self, scope: Scope, features: FeatureSet, addr: Address, paranoid=False
    ) -> tuple[FeatureSet, ceng.MatchResults]:
        """
        Match rules from this ruleset at the given scope against the given features.

        This wrapper around _match exists so that we can assert it matches precisely
        the same as `capa.engine.match`, just faster.

        This matcher does not handle some edge cases:
          - top level NOT statements
              - also top level counted features with zero occurances, like: `count(menmonic(mov)): 0`
          - nested NOT statements (NOT: NOT: foo)

        We should discourage/forbid these constructs from our rules and add lints for them.
        TODO(williballenthin): add lints for logic edge cases

        Args:
          paranoid: when true, demonstrate that the naive matcher agrees with this
           optimized matcher (much slower! around 10x slower).
        """
        features, matches = self._match(scope, features, addr)

        if paranoid:
            rules: list[Rule] = self.rules_by_scope[scope]
            paranoid_features, paranoid_matches = capa.engine.match(rules, features, addr)

            if features != paranoid_features:
                logger.warning("paranoid: %s: %s", scope, addr)
                for feature in sorted(set(features.keys()) & set(paranoid_features.keys())):
                    logger.warning("paranoid:   %s", feature)

                for feature in sorted(set(features.keys()) - set(paranoid_features.keys())):
                    logger.warning("paranoid: + %s", feature)

                for feature in sorted(set(paranoid_features.keys()) - set(features.keys())):
                    logger.warning("paranoid: - %s", feature)

            assert features == paranoid_features
            assert set(matches.keys()) == set(paranoid_matches.keys())

        return features, matches


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


def collect_rule_file_paths(rule_paths: list[Path]) -> list[Path]:
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
    rule_paths: list[RulePath],
    cache_dir=None,
    on_load_rule: Callable[[RulePath, int, int], None] = on_load_rule_default,
    enable_cache: bool = True,
) -> RuleSet:
    """
    args:
      rule_paths: list of paths to rules files or directories containing rules files
      cache_dir: directory to use for caching rules, or will use the default detected cache directory if None
      on_load_rule: callback to invoke before a rule is loaded, use for progress or cancellation
      enable_cache: enable loading of a cached ruleset (default: True)
    """
    if cache_dir is None:
        cache_dir = capa.rules.cache.get_default_cache_directory()
    # rule_paths may contain directory paths,
    # so search for file paths recursively.
    rule_file_paths = collect_rule_file_paths(rule_paths)

    # this list is parallel to `rule_file_paths`:
    # rule_file_paths[i] corresponds to rule_contents[i].
    rule_contents = [file_path.read_bytes() for file_path in rule_file_paths]

    if enable_cache:
        ruleset = capa.rules.cache.load_cached_ruleset(cache_dir, rule_contents)
        if ruleset is not None:
            return ruleset

    rules: list[Rule] = []

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
