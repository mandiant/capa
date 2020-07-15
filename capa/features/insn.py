# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

from capa.features import Feature


class API(Feature):
    def __init__(self, name, description=None):
        # Downcase library name if given
        if "." in name:
            modname, impname = name.split(".")
            name = modname.lower() + "." + impname

        super(API, self).__init__(name, description)


class Number(Feature):
    def __init__(self, value, description=None):
        super(Number, self).__init__(value, description)

    def get_value_str(self):
        return "0x%X" % self.value


class Offset(Feature):
    def __init__(self, value, description=None):
        super(Offset, self).__init__(value, description)

    def get_value_str(self):
        return "0x%X" % self.value


class Mnemonic(Feature):
    def __init__(self, value, description=None):
        super(Mnemonic, self).__init__(value, description)
