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
