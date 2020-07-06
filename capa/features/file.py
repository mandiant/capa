from capa.features import Feature


class Export(Feature):
    def __init__(self, value, description=None):
        # value is export name
        super(Export, self).__init__(value, description)


class Import(Feature):
    def __init__(self, value, description=None):
        # value is import name
        super(Import, self).__init__(value, description)


class Section(Feature):
    def __init__(self, value, description=None):
        # value is section name
        super(Section, self).__init__(value, description)
