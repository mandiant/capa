# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import re
import codecs
import logging
import collections
from typing import Set, Dict, Union

import capa.engine
import capa.features

logger = logging.getLogger(__name__)
MAX_BYTES_FEATURE_SIZE = 0x100

# thunks may be chained so we specify a delta to control the depth to which these chains are explored
THUNK_CHAIN_DEPTH_DELTA = 5

# identifiers for supported architectures names that tweak a feature
# for example, offset/x32
ARCH_X32 = "x32"
ARCH_X64 = "x64"
VALID_ARCH = (ARCH_X32, ARCH_X64)


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


class Feature:
    def __init__(self, value: Union[str, int, bytes], arch=None, description=None):
        """
        Args:
          value (any): the value of the feature, such as the number or string.
          arch (str): one of the VALID_ARCH values, or None.
            When None, then the feature applies to any architecture.
            Modifies the feature name from `feature` to `feature/arch`, like `offset/x32`.
          description (str): a human-readable description that explains the feature value.
        """
        super(Feature, self).__init__()

        if arch is not None:
            if arch not in VALID_ARCH:
                raise ValueError("arch '%s' must be one of %s" % (arch, VALID_ARCH))
            self.name = self.__class__.__name__.lower() + "/" + arch
        else:
            self.name = self.__class__.__name__.lower()

        self.value = value
        self.arch = arch
        self.description = description

    def __hash__(self):
        return hash((self.name, self.value, self.arch))

    def __eq__(self, other):
        return self.name == other.name and self.value == other.value and self.arch == other.arch

    def get_value_str(self) -> str:
        """
        render the value of this feature, for use by `__str__` and friends.
        subclasses should override to customize the rendering.

        Returns: any
        """
        return str(self.value)

    def __str__(self):
        if self.value is not None:
            if self.description:
                return "%s(%s = %s)" % (self.name, self.get_value_str(), self.description)
            else:
                return "%s(%s)" % (self.name, self.get_value_str())
        else:
            return "%s" % self.name

    def __repr__(self):
        return str(self)

    def evaluate(self, ctx: Dict["Feature", Set[int]]) -> "capa.engine.Result":
        return capa.engine.Result(self in ctx, self, [], locations=ctx.get(self, []))

    def freeze_serialize(self):
        if self.arch is not None:
            return (self.__class__.__name__, [self.value, {"arch": self.arch}])
        else:
            return (self.__class__.__name__, [self.value])

    @classmethod
    def freeze_deserialize(cls, args):
        # as you can see below in code,
        # if the last argument is a dictionary,
        # consider it to be kwargs passed to the feature constructor.
        if len(args) == 1:
            return cls(*args)
        elif isinstance(args[-1], dict):
            kwargs = args[-1]
            args = args[:-1]
            return cls(*args, **kwargs)


class MatchedRule(Feature):
    def __init__(self, value: str, description=None):
        super(MatchedRule, self).__init__(value, description=description)
        self.name = "match"


class Characteristic(Feature):
    def __init__(self, value: str, description=None):
        super(Characteristic, self).__init__(value, description=description)


class String(Feature):
    def __init__(self, value: str, description=None):
        super(String, self).__init__(value, description=description)


class Regex(String):
    def __init__(self, value: str, description=None):
        super(Regex, self).__init__(value, description=description)
        self.value = value

        pat = self.value[len("/") : -len("/")]
        flags = re.DOTALL
        if value.endswith("/i"):
            pat = self.value[len("/") : -len("/i")]
            flags |= re.IGNORECASE
        try:
            self.re = re.compile(pat, flags)
        except re.error:
            if value.endswith("/i"):
                value = value[: -len("i")]
            raise ValueError(
                "invalid regular expression: %s it should use Python syntax, try it at https://pythex.org" % value
            )

    def evaluate(self, ctx):
        # mapping from string value to list of locations.
        # will unique the locations later on.
        matches = collections.defaultdict(list)

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
                matches[feature.value].extend(locations)

        if matches:
            # finalize: defaultdict -> dict
            # which makes json serialization easier
            matches = dict(matches)

            # collect all locations
            locations = set()
            for s in matches.keys():
                matches[s] = list(set(matches[s]))
                locations.update(matches[s])

            # unlike other features, we cannot return put a reference to `self` directly in a `Result`.
            # this is because `self` may match on many strings, so we can't stuff the matched value into it.
            # instead, return a new instance that has a reference to both the regex and the matched values.
            # see #262.
            return capa.engine.Result(True, _MatchedRegex(self, matches), [], locations=locations)
        else:
            return capa.engine.Result(False, _MatchedRegex(self, None), [])

    def __str__(self):
        return "regex(string =~ %s)" % self.value


class _MatchedRegex(Regex):
    """
    this represents specific match instances of a regular expression feature.
    treat it the same as a `Regex` except it has the `matches` field that contains the complete strings that matched.

    note: this type should only ever be constructed by `Regex.evaluate()`. it is not part of the public API.
    """

    def __init__(self, regex: Regex, matches):
        """
        args:
          regex (Regex): the regex feature that matches.
          match (Dict[string, List[int]]|None): mapping from matching string to its locations.
        """
        super(_MatchedRegex, self).__init__(str(regex.value), description=regex.description)
        # we want this to collide with the name of `Regex` above,
        # so that it works nicely with the renderers.
        self.name = "regex"
        # this may be None if the regex doesn't match
        self.matches = matches

    def __str__(self):
        return "regex(string =~ %s, matches = %s)" % (
            self.value,
            ", ".join(map(lambda s: '"' + s + '"', (self.matches or {}).keys())),
        )


class StringFactory:
    def __new__(cls, value: str, description=None):
        if value.startswith("/") and (value.endswith("/") or value.endswith("/i")):
            return Regex(value, description=description)
        return String(value, description=description)


class Bytes(Feature):
    def __init__(self, value: bytes, description=None):
        super(Bytes, self).__init__(value, description=description)
        self.value = value

    def evaluate(self, ctx):
        for feature, locations in ctx.items():
            if not isinstance(feature, (Bytes,)):
                continue

            if feature.value.startswith(self.value):
                return capa.engine.Result(True, self, [], locations=locations)

        return capa.engine.Result(False, self, [])

    def get_value_str(self):
        return hex_string(bytes_to_str(self.value))

    def freeze_serialize(self):
        return (self.__class__.__name__, [bytes_to_str(self.value).upper()])

    @classmethod
    def freeze_deserialize(cls, args):
        return cls(*[codecs.decode(x, "hex") for x in args])
