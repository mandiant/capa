# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import re
import abc
import codecs
import typing
import logging
import collections
from typing import TYPE_CHECKING, Set, Dict, List, Union, Optional

if TYPE_CHECKING:
    # circular import, otherwise
    import capa.engine

import capa.perf
import capa.features
import capa.features.extractors.elf
from capa.features.address import Address

logger = logging.getLogger(__name__)
MAX_BYTES_FEATURE_SIZE = 0x100

# thunks may be chained so we specify a delta to control the depth to which these chains are explored
THUNK_CHAIN_DEPTH_DELTA = 5


class FeatureAccess:
    READ = "read"
    WRITE = "write"


VALID_FEATURE_ACCESS = (FeatureAccess.READ, FeatureAccess.WRITE)


def bytes_to_str(b: bytes) -> str:
    return str(codecs.encode(b, "hex").decode("utf-8"))


def hex_string(h: str) -> str:
    """render hex string e.g. "0a40b1" as "0A 40 B1" """
    return " ".join(h[i : i + 2] for i in range(0, len(h), 2)).upper()


def escape_string(s: str) -> str:
    """escape special characters"""
    s = repr(s)
    if not s.startswith(('"', "'")):
        # u'hello\r\nworld' -> hello\\r\\nworld
        s = s[2:-1]
    else:
        # 'hello\r\nworld' -> hello\\r\\nworld
        s = s[1:-1]
    s = s.replace("\\'", "'")  # repr() may escape "'" in some edge cases, remove
    s = s.replace('"', '\\"')  # repr() does not escape '"', add
    return s


class Result:
    """
    represents the results of an evaluation of statements against features.

    instances of this class should behave like a bool,
    e.g. `assert Result(True, ...) == True`

    instances track additional metadata about evaluation results.
    they contain references to the statement node (e.g. an And statement),
     as well as the children Result instances.

    we need this so that we can render the tree of expressions and their results.
    """

    def __init__(
        self,
        success: bool,
        statement: Union["capa.engine.Statement", "Feature"],
        children: List["Result"],
        locations: Optional[Set[Address]] = None,
    ):
        super().__init__()
        self.success = success
        self.statement = statement
        self.children = children
        self.locations = locations if locations is not None else set()

    def __eq__(self, other):
        if isinstance(other, bool):
            return self.success == other
        return False

    def __bool__(self):
        return self.success

    def __nonzero__(self):
        return self.success


class Feature(abc.ABC):
    def __init__(
        self,
        value: Union[str, int, float, bytes],
        description: Optional[str] = None,
    ):
        """
        Args:
          value (any): the value of the feature, such as the number or string.
          description (str): a human-readable description that explains the feature value.
        """
        super().__init__()

        self.name = self.__class__.__name__.lower()
        self.value = value
        self.description = description

    def __hash__(self):
        return hash((self.name, self.value))

    def __eq__(self, other):
        return self.name == other.name and self.value == other.value

    def __lt__(self, other):
        # TODO: this is a huge hack!
        import capa.features.freeze.features

        return (
            capa.features.freeze.features.feature_from_capa(self).json()
            < capa.features.freeze.features.feature_from_capa(other).json()
        )

    def get_name_str(self) -> str:
        """
        render the name of this feature, for use by `__str__` and friends.
        subclasses should override to customize the rendering.
        """
        return self.name

    def get_value_str(self) -> str:
        """
        render the value of this feature, for use by `__str__` and friends.
        subclasses should override to customize the rendering.
        """
        return str(self.value)

    def __str__(self):
        if self.value is not None:
            if self.description:
                return f"{self.get_name_str()}({self.get_value_str()} = {self.description})"
            else:
                return f"{self.get_name_str()}({self.get_value_str()})"
        else:
            return f"{self.get_name_str()}"

    def __repr__(self):
        return str(self)

    def evaluate(self, ctx: Dict["Feature", Set[Address]], **kwargs) -> Result:
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature." + self.name] += 1
        return Result(self in ctx, self, [], locations=ctx.get(self, set()))


class MatchedRule(Feature):
    def __init__(self, value: str, description=None):
        super().__init__(value, description=description)
        self.name = "match"


class Characteristic(Feature):
    def __init__(self, value: str, description=None):
        super().__init__(value, description=description)


class String(Feature):
    def __init__(self, value: str, description=None):
        super().__init__(value, description=description)

    def get_value_str(self) -> str:
        assert isinstance(self.value, str)
        return escape_string(self.value)


class Class(Feature):
    def __init__(self, value: str, description=None):
        super().__init__(value, description=description)


class Namespace(Feature):
    def __init__(self, value: str, description=None):
        super().__init__(value, description=description)


class Substring(String):
    def __init__(self, value: str, description=None):
        super().__init__(value, description=description)
        self.value = value

    def evaluate(self, ctx, short_circuit=True):
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature.substring"] += 1

        # mapping from string value to list of locations.
        # will unique the locations later on.
        matches: typing.DefaultDict[str, Set[Address]] = collections.defaultdict(set)

        assert isinstance(self.value, str)
        for feature, locations in ctx.items():
            if not isinstance(feature, (String,)):
                continue

            if not isinstance(feature.value, str):
                # this is a programming error: String should only contain str
                raise ValueError("unexpected feature value type")

            if self.value in feature.value:
                matches[feature.value].update(locations)
                if short_circuit:
                    # we found one matching string, thats sufficient to match.
                    # don't collect other matching strings in this mode.
                    break

        if matches:
            # collect all locations
            locations = set()
            for locs in matches.values():
                locations.update(locs)

            # unlike other features, we cannot return put a reference to `self` directly in a `Result`.
            # this is because `self` may match on many strings, so we can't stuff the matched value into it.
            # instead, return a new instance that has a reference to both the substring and the matched values.
            return Result(True, _MatchedSubstring(self, dict(matches)), [], locations=locations)
        else:
            return Result(False, _MatchedSubstring(self, {}), [])

    def get_value_str(self) -> str:
        assert isinstance(self.value, str)
        return escape_string(self.value)

    def __str__(self):
        assert isinstance(self.value, str)
        return f"substring({escape_string(self.value)})"


class _MatchedSubstring(Substring):
    """
    this represents specific match instances of a substring feature.
    treat it the same as a `Substring` except it has the `matches` field that contains the complete strings that matched.

    note: this type should only ever be constructed by `Substring.evaluate()`. it is not part of the public API.
    """

    def __init__(self, substring: Substring, matches: Dict[str, Set[Address]]):
        """
        args:
          substring: the substring feature that matches.
          match: mapping from matching string to its locations.
        """
        super().__init__(str(substring.value), description=substring.description)
        # we want this to collide with the name of `Substring` above,
        # so that it works nicely with the renderers.
        self.name = "substring"
        # this may be None if the substring doesn't match
        self.matches = matches

    def __str__(self):
        matches = ", ".join(map(lambda s: '"' + s + '"', (self.matches or {}).keys()))
        assert isinstance(self.value, str)
        return f'substring("{self.value}", matches = {matches})'


class Regex(String):
    def __init__(self, value: str, description=None):
        super().__init__(value, description=description)
        self.value = value

        pat = self.value[len("/") : -len("/")]
        flags = re.DOTALL
        if value.endswith("/i"):
            pat = self.value[len("/") : -len("/i")]
            flags |= re.IGNORECASE
        try:
            self.re = re.compile(pat, flags)
        except re.error as exc:
            if value.endswith("/i"):
                value = value[: -len("i")]
            raise ValueError(
                f"invalid regular expression: {value} it should use Python syntax, try it at https://pythex.org"
            ) from exc

    def evaluate(self, ctx, short_circuit=True):
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature.regex"] += 1

        # mapping from string value to list of locations.
        # will unique the locations later on.
        matches: typing.DefaultDict[str, Set[Address]] = collections.defaultdict(set)

        for feature, locations in ctx.items():
            if not isinstance(feature, (String,)):
                continue

            if not isinstance(feature.value, str):
                # this is a programming error: String should only contain str
                raise ValueError("unexpected feature value type")

            # `re.search` finds a match anywhere in the given string
            # which implies leading and/or trailing whitespace.
            # using this mode cleans is more convenient for rule authors,
            # so that they don't have to prefix/suffix their terms like: /.*foo.*/.
            if self.re.search(feature.value):
                matches[feature.value].update(locations)
                if short_circuit:
                    # we found one matching string, thats sufficient to match.
                    # don't collect other matching strings in this mode.
                    break

        if matches:
            # collect all locations
            locations = set()
            for locs in matches.values():
                locations.update(locs)

            # unlike other features, we cannot return put a reference to `self` directly in a `Result`.
            # this is because `self` may match on many strings, so we can't stuff the matched value into it.
            # instead, return a new instance that has a reference to both the regex and the matched values.
            # see #262.
            return Result(True, _MatchedRegex(self, dict(matches)), [], locations=locations)
        else:
            return Result(False, _MatchedRegex(self, {}), [])

    def __str__(self):
        assert isinstance(self.value, str)
        return f"regex(string =~ {self.value})"


class _MatchedRegex(Regex):
    """
    this represents specific match instances of a regular expression feature.
    treat it the same as a `Regex` except it has the `matches` field that contains the complete strings that matched.

    note: this type should only ever be constructed by `Regex.evaluate()`. it is not part of the public API.
    """

    def __init__(self, regex: Regex, matches: Dict[str, Set[Address]]):
        """
        args:
          regex: the regex feature that matches.
          matches: mapping from matching string to its locations.
        """
        super().__init__(str(regex.value), description=regex.description)
        # we want this to collide with the name of `Regex` above,
        # so that it works nicely with the renderers.
        self.name = "regex"
        # this may be None if the regex doesn't match
        self.matches = matches

    def __str__(self):
        matches = ", ".join(map(lambda s: '"' + s + '"', (self.matches or {}).keys()))
        assert isinstance(self.value, str)
        return f"regex(string =~ {self.value}, matches = {matches})"


class StringFactory:
    def __new__(cls, value: str, description=None):
        if value.startswith("/") and (value.endswith("/") or value.endswith("/i")):
            return Regex(value, description=description)
        return String(value, description=description)


class Bytes(Feature):
    def __init__(self, value: bytes, description=None):
        super().__init__(value, description=description)
        self.value = value

    def evaluate(self, ctx, **kwargs):
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature.bytes"] += 1

        assert isinstance(self.value, bytes)
        for feature, locations in ctx.items():
            if not isinstance(feature, (Bytes,)):
                continue

            assert isinstance(feature.value, bytes)
            if feature.value.startswith(self.value):
                return Result(True, self, [], locations=locations)

        return Result(False, self, [])

    def get_value_str(self):
        assert isinstance(self.value, bytes)
        return hex_string(bytes_to_str(self.value))


# other candidates here: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
ARCH_I386 = "i386"
ARCH_AMD64 = "amd64"
# dotnet
ARCH_ANY = "any"
VALID_ARCH = (ARCH_I386, ARCH_AMD64, ARCH_ANY)


class Arch(Feature):
    def __init__(self, value: str, description=None):
        super().__init__(value, description=description)
        self.name = "arch"


OS_WINDOWS = "windows"
OS_LINUX = "linux"
OS_MACOS = "macos"
# dotnet
OS_ANY = "any"
VALID_OS = {os.value for os in capa.features.extractors.elf.OS}
VALID_OS.update({OS_WINDOWS, OS_LINUX, OS_MACOS, OS_ANY})
# internal only, not to be used in rules
OS_AUTO = "auto"


class OS(Feature):
    def __init__(self, value: str, description=None):
        super().__init__(value, description=description)
        self.name = "os"

    def evaluate(self, ctx, **kwargs):
        capa.perf.counters["evaluate.feature"] += 1
        capa.perf.counters["evaluate.feature." + self.name] += 1

        for feature, locations in ctx.items():
            if not isinstance(feature, (OS,)):
                continue

            assert isinstance(feature.value, str)
            if OS_ANY in (self.value, feature.value) or self.value == feature.value:
                return Result(True, self, [], locations=locations)

        return Result(False, self, [])


FORMAT_PE = "pe"
FORMAT_ELF = "elf"
FORMAT_DOTNET = "dotnet"
VALID_FORMAT = (FORMAT_PE, FORMAT_ELF, FORMAT_DOTNET)
# internal only, not to be used in rules
FORMAT_AUTO = "auto"
FORMAT_SC32 = "sc32"
FORMAT_SC64 = "sc64"
FORMAT_FREEZE = "freeze"
FORMAT_RESULT = "result"
FORMAT_UNKNOWN = "unknown"


class Format(Feature):
    def __init__(self, value: str, description=None):
        super().__init__(value, description=description)
        self.name = "format"


def is_global_feature(feature):
    """
    is this a feature that is extracted at every scope?
    today, these are OS and arch features.
    """
    return isinstance(feature, (OS, Arch))
