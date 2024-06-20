import logging
from typing import Tuple, Iterator

from capa.helpers import assert_never
from capa.features.insn import API, Number
from capa.features.common import String, Feature
from capa.features.address import Address
from capa.features.extractors.base_extractor import CallHandle, ThreadHandle, ProcessHandle

logger = logging.getLogger(__name__)


def extract_call_features(ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    this method extracts the given call's features (such as API name and arguments),
    and returns them as API, Number, and String features.

    args:
      call: FunctionCall object representing the XML fncall element

      yields: Feature, address; where Feature is either: API, Number, or String.
    """

    # TODO update for new models
    # print(ch)
    return

    # Extract API name
    yield API(ch.inner.name), ch.inner.address

    # Extract arguments from <in>
    for param in ch.inner.in_:
        value = param.value
        if isinstance(value, str):
            yield String(value), ch.inner.address

        elif isinstance(value, int):
            yield Number(value), ch.inner.address

        else:
            assert_never(value)

    # Extract return value from <out>
    if ch.inner.out is not None:
        value = ch.inner.out.value
        if isinstance(value, str):
            yield String(value), ch.inner.address

        elif isinstance(value, int):
            yield Number(value), ch.inner.address

        else:
            assert_never(value)


def extract_features(ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> Iterator[Tuple[Feature, Address]]:
    for handler in CALL_HANDLERS:
        for feature, addr in handler(ph, th, ch):
            yield feature, addr


CALL_HANDLERS = (extract_call_features,)
