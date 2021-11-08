import collections
from typing import Dict

counters: Dict[str, int] = collections.Counter()


def reset():
    global counters
    counters = collections.Counter()
