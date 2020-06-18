from capa.features import Feature


class BasicBlock(Feature):
    def __init__(self):
        super(BasicBlock, self).__init__([])

    def __str__(self):
        return 'basic block'
