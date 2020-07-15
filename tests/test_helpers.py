# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import codecs

from capa.features.extractors import helpers


def test_all_zeros():
    # Python 2: <str>
    # Python 3: <bytes>
    a = b"\x00\x00\x00\x00"
    b = codecs.decode("00000000", "hex")
    c = b"\x01\x00\x00\x00"
    d = codecs.decode("01000000", "hex")
    assert helpers.all_zeros(a) is True
    assert helpers.all_zeros(b) is True
    assert helpers.all_zeros(c) is False
    assert helpers.all_zeros(d) is False
