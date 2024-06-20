import logging
from typing import Tuple, Iterator

from capa.helpers import assert_never
from capa.features.insn import API, Number
from capa.features.common import String, Feature
from capa.features.address import Address
from capa.features.extractors.vmray.models import Analysis, FunctionCall, Param, In, Out

logger = logging.getLogger(__name__)


def extract_function_calls(fncall: FunctionCall) -> Iterator[Tuple[Feature, Address]]:
    """
    this method extracts the given call's features (such as API name and arguments),
    and returns them as API, Number, and String features.

    args:
      call: FunctionCall object representing the XML fncall element

      yields: Feature, address; where Feature is either: API, Number, or String.
    """

    # Extract API name
    yield API(fncall.name), Address(fncall.address)

    # Extract arguments from <in>
    if fncall.in_ is not None:
        for param in fncall.in_.params:
            value = param.value
            if value is not None:
                if isinstance(value, str):
                    yield String(value), Address(fncall.address)
                elif isinstance(value, int):
                    yield Number(value), Address(fncall.address)
                else:
                    assert_never(value)

    # Extract return value from <out>
    if fncall.out_ is not None:
        for param in fncall.out_.params:
            value = param.value
            if value is not None:
                if isinstance(value, str):
                    yield String(value), Address(fncall.address)
                elif isinstance(value, int):
                    yield Number(value), Address(fncall.address)
                else:
                    assert_never(value)


def extract_features(analysis: Analysis) -> Iterator[Tuple[Feature, Address]]:
    """
    Extract features from the Analysis object in models.py
    """
    for fncall in analysis.fncalls:
        yield from extract_function_calls(fncall)
