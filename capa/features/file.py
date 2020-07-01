from capa.features import Feature


class Export(Feature):
    def __init__(self, value):
        # value is export name
        super(Export, self).__init__([value])
        self.value = value

    def __str__(self):
        return "Export(%s)" % (self.value)


class Import(Feature):
    def __init__(self, value):
        # value is import name
        super(Import, self).__init__([value])
        self.value = value

    def __str__(self):
        return "Import(%s)" % (self.value)


class Section(Feature):
    def __init__(self, value):
        # value is section name
        super(Section, self).__init__([value])
        self.value = value

    def __str__(self):
        return "Section(%s)" % (self.value)
