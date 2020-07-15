# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import os

_hex = hex


def hex(i):
    # under py2.7, long integers get formatted with a trailing `L`
    # and this is not pretty. so strip it out.
    return _hex(oint(i)).rstrip("L")


def oint(i):
    # there seems to be some trouble with using `int(viv_utils.Function)`
    # with the black magic we do with binding the `__int__()` routine.
    # i haven't had a chance to debug this yet (and i have no hotel wifi).
    # so in the meantime, detect this, and call the method directly.
    try:
        return int(i)
    except TypeError:
        return i.__int__()


def get_file_taste(sample_path):
    if not os.path.exists(sample_path):
        raise IOError("sample path %s does not exist or cannot be accessed" % sample_path)
    with open(sample_path, "rb") as f:
        taste = f.read(8)
    return taste
