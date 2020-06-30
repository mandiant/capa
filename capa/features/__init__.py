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
    def __init__(self, args, description=None):
        super(Feature, self).__init__()
        self.name = self.__class__.__name__.lower()
        self.args = args
        self.description = description

    def __hash__(self):
        return hash((self.name, tuple(self.args)))

    def __eq__(self, other):
        return self.name == other.name and self.args == other.args

    # Used to overwrite the rendering of the feature args in `__str__` and the
    # json output
    def get_args_str(self):
        return ','.join(self.args)

    def __str__(self):
        if self.description:
            return '%s(%s = %s)' % (self.name, self.get_args_str(), self.description)
        else:
            return '%s(%s)' % (self.name, self.get_args_str())

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
    def __init__(self, rule_name, description=None):
        super(MatchedRule, self).__init__([rule_name], description)
        self.name = 'match'
        self.rule_name = rule_name


class Characteristic(Feature):
    def __init__(self, attribute, value=None, description=None):
        '''
        when `value` is not provided, this serves as descriptor for a class of characteristics.
        this is only used internally, such as in `rules.py` when checking if a statement is
          supported by a given scope.
        '''
        super(Characteristic, self).__init__([attribute, value], description)
        self.attribute = attribute
        self.value = value

    def evaluate(self, ctx):
        if self.value is None:
            raise ValueError('cannot evaluate characteristc %s with empty value' % (str(self)))
        return super(Characteristic, self).evaluate(ctx)

    def get_args_str(self):
        if self.value is None:
            return self.attribute
        else:
            return '%s(%s)' % (self.attribute, self.value)


class String(Feature):
    def __init__(self, value, description=None):
        super(String, self).__init__([value], description)
        self.value = value


class Bytes(Feature):
    def __init__(self, value, description=None):
        super(Bytes, self).__init__([value], description)
        self.value = value

    def evaluate(self, ctx):
        for feature, locations in ctx.items():
            if not isinstance(feature, (capa.features.Bytes, )):
                continue

            if feature.value.startswith(self.value):
                return capa.engine.Result(True, self, [], locations=locations)

        return capa.engine.Result(False, self, [])

    def get_args_str(self):
        return bytes_to_str(self.value).upper()

    def freeze_serialize(self):
        return (self.__class__.__name__,
                [bytes_to_str(x).upper() for x in self.args])

    @classmethod
    def freeze_deserialize(cls, args):
        return cls(*[codecs.decode(x, 'hex') for x in args])
