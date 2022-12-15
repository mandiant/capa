import typing
import collections

# this structure is unstable and may change before the next major release.
counters: typing.Counter[str] = collections.Counter()


def reset():
    global counters
    counters = collections.Counter()
