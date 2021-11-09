import collections
from typing import Dict

# this structure is unstable and may change before the next major release.
counters: Dict[str, int] = collections.Counter()


def reset():
    global counters
    counters = collections.Counter()
