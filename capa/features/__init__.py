import codecs
import logging
import sys

import capa.engine


logger = logging.getLogger(__name__)
MAX_BYTES_FEATURE_SIZE = 0x100


def bytes_to_str(b):
    if sys.version_info[0] >= 3:
        return str(codecs.encode(b, 'hex').decode('utf-8'))
    else:
        return codecs.encode(b, 'hex')


class Feature(object):
    def __init__(self, args):
        super(Feature, self).__init__()
        self.name = self.__class__.__name__
        self.args = args

    def __hash__(self):
        return hash((self.name, tuple(self.args)))

    def __eq__(self, other):
        return self.name == other.name and self.args == other.args

    def __str__(self):
        return '%s(%s)' % (self.name.lower(), ','.join(self.args))

    def __repr__(self):
        return str(self)

    def evaluate(self, ctx):
        return capa.engine.Result(self in ctx, self, [], locations=ctx.get(self, []))

    def serialize(self):
        return self.__dict__

    def freeze_serialize(self):
        return (self.__class__.__name__,
                self.args)

    @classmethod
    def freeze_deserialize(cls, args):
        return cls(*args)


class MatchedRule(Feature):
    def __init__(self, rule_name):
        super(MatchedRule, self).__init__([rule_name])
        self.rule_name = rule_name

    def __str__(self):
        return 'match(%s)' % (self.rule_name)


class Characteristic(Feature):
    def __init__(self, name):
        super(Characteristic, self).__init__([name])
        self.name = name

    def freeze_serialize(self):
        # in an older version of capa, characteristics could theoretically match non-existence (value=False).
        # but we found this was never used (and better expressed with `not: characteristic: ...`).
        # this was represented using an additional parameter, called `value`, for Characteristic.
        # its been removed, but we keep it around in the freeze format to maintain backwards compatibility.
        # this value is ignored, however.
        return (self.__class__.__name__, [self.name, True])

    @classmethod
    def freeze_deserialize(cls, args):
        # see above. we ignore the second element in the 2-tuple here.
        return cls(args[0])


class String(Feature):
    def __init__(self, value):
        super(String, self).__init__([value])
        self.value = value

    def __str__(self):
        return 'string("%s")' % (self.value)


class Bytes(Feature):
    def __init__(self, value, symbol=None):
        super(Bytes, self).__init__([value])
        self.value = value
        self.symbol = symbol

    def evaluate(self, ctx):
        for feature, locations in ctx.items():
            if not isinstance(feature, (capa.features.Bytes, )):
                continue

            if feature.value.startswith(self.value):
                return capa.engine.Result(True, self, [], locations=locations)

        return capa.engine.Result(False, self, [])

    def __str__(self):
        if self.symbol:
            return 'bytes(0x%s = %s)' % (bytes_to_str(self.value).upper(), self.symbol)
        else:
            return 'bytes(0x%s)' % (bytes_to_str(self.value).upper())

    def freeze_serialize(self):
        return (self.__class__.__name__,
                [bytes_to_str(x).upper() for x in self.args])

    @classmethod
    def freeze_deserialize(cls, args):
        return cls(*[codecs.decode(x, 'hex') for x in args])
