from capa.features import Feature


class API(Feature):
    def __init__(self, name):
        # Downcase library name if given
        if "." in name:
            modname, impname = name.split(".")
            name = modname.lower() + "." + impname

        super(API, self).__init__([name])


class Number(Feature):
    def __init__(self, value, symbol=None):
        super(Number, self).__init__([value])
        self.value = value
        self.symbol = symbol

    def __str__(self):
        if self.symbol:
            return "number(0x%x = %s)" % (self.value, self.symbol)
        else:
            return "number(0x%x)" % (self.value)


class Offset(Feature):
    def __init__(self, value, symbol=None):
        super(Offset, self).__init__([value])
        self.value = value
        self.symbol = symbol

    def __str__(self):
        if self.symbol:
            return "offset(0x%x = %s)" % (self.value, self.symbol)
        else:
            return "offset(0x%x)" % (self.value)


class Mnemonic(Feature):
    def __init__(self, value):
        super(Mnemonic, self).__init__([value])
        self.value = value

    def __str__(self):
        return "mnemonic(%s)" % (self.value)
