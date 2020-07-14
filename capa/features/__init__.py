import sys
import codecs
import logging

import capa.engine

logger = logging.getLogger(__name__)
MAX_BYTES_FEATURE_SIZE = 0x100


def bytes_to_str(b):
    if sys.version_info[0] >= 3:
        return str(codecs.encode(b, "hex").decode("utf-8"))
    else:
        return codecs.encode(b, "hex")


def hex_string(h):
    """ render hex string e.g. "0a40b1" as "0A 40 B1" """
    return " ".join(h[i : i + 2] for i in range(0, len(h), 2)).upper()


class Feature(object):
    def __init__(self, value, description=None):
        super(Feature, self).__init__()
        self.name = self.__class__.__name__.lower()
        self.value = value
        self.description = description

    def __hash__(self):
        return hash((self.name, self.value))

    def __eq__(self, other):
        return self.name == other.name and self.value == other.value

    # Used to overwrite the rendering of the feature value in `__str__` and the
    # json output
    def get_value_str(self):
        return self.value

    def __str__(self):
        if self.description:
            return "%s(%s = %s)" % (self.name, self.get_value_str(), self.description)
        else:
            return "%s(%s)" % (self.name, self.get_value_str())

    def __repr__(self):
        return str(self)

    def evaluate(self, ctx):
        return capa.engine.Result(self in ctx, self, [], locations=ctx.get(self, []))

    def serialize(self):
        return self.__dict__

    def freeze_serialize(self):
        return (self.__class__.__name__, [self.value])

    @classmethod
    def freeze_deserialize(cls, args):
        return cls(*args)


class MatchedRule(Feature):
    def __init__(self, value, description=None):
        super(MatchedRule, self).__init__(value, description)
        self.name = "match"


class Characteristic(Feature):
    def __init__(self, value, description=None):
        super(Characteristic, self).__init__(value, description)


class String(Feature):
    def __init__(self, value, description=None):
        super(String, self).__init__(value, description)


class Bytes(Feature):
    def __init__(self, value, description=None):
        super(Bytes, self).__init__(value, description)

    def evaluate(self, ctx):
        for feature, locations in ctx.items():
            if not isinstance(feature, (capa.features.Bytes,)):
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
