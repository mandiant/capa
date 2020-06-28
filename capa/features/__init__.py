import codecs
import logging

import capa.engine


logger = logging.getLogger(__name__)
MAX_BYTES_FEATURE_SIZE = 0x100


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
    def __init__(self, name, value=None):
        '''
        when `value` is not provided, this serves as descriptor for a class of characteristics.
        this is only used internally, such as in `rules.py` when checking if a statement is
          supported by a given scope.
        '''
        super(Characteristic, self).__init__([name, value])
        self.name = name
        self.value = value

    def evaluate(self, ctx):
        if self.value is None:
            raise ValueError('cannot evaluate characteristc %s with empty value' % (str(self)))
        return super(Characteristic, self).evaluate(ctx)

    def __str__(self):
        if self.value is None:
            return 'characteristic(%s)' % (self.name)
        else:
            return 'characteristic(%s(%s))' % (self.name, self.value)


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
            return 'bytes(0x%s = %s)' % (codecs.encode(self.value, 'hex').upper(), self.symbol)
        else:
            return 'bytes(0x%s)' % (codecs.encode(self.value, 'hex').upper())

    def freeze_serialize(self):
        return (self.__class__.__name__,
                map(lambda x: codecs.encode(x, 'hex').upper(), self.args))

    @classmethod
    def freeze_deserialize(cls, args):
        return cls(*map(lambda x: codecs.decode(x, 'hex'), args))
