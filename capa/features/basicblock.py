from capa.features import Feature


class BasicBlock(Feature):
    def __init__(self):
        super(BasicBlock, self).__init__(None)

    def __str__(self):
        return "basic block"

    def freeze_serialize(self):
        return (self.__class__.__name__, [])

    @classmethod
    def freeze_deserialize(cls, args):
        return cls()
