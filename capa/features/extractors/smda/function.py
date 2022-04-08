from typing import Tuple, Iterator

from capa.features.common import Feature, Characteristic
from capa.features.address import Address, AbsoluteVirtualAddress
from capa.features.extractors import loops
from capa.features.extractors.base_extractor import FunctionHandle


def extract_function_calls_to(f: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
    for inref in f.inner.inrefs:
        yield Characteristic("calls to"), AbsoluteVirtualAddress(inref)


def extract_function_loop(f: FunctionHandle) -> Iterator[Tuple[Feature, Address]]:
    """
    parse if a function has a loop
    """
    edges = []
    for bb_from, bb_tos in f.inner.blockrefs.items():
        for bb_to in bb_tos:
            edges.append((bb_from, bb_to))

    if edges and loops.has_loop(edges):
        yield Characteristic("loop"), f.address


def extract_features(f: FunctionHandle):
    """
    extract features from the given function.

    args:
      f: the function from which to extract features

    yields:
      Tuple[Feature, Address]: the features and their location found in this function.
    """
    for func_handler in FUNCTION_HANDLERS:
        for feature, addr in func_handler(f):
            yield feature, addr


FUNCTION_HANDLERS = (extract_function_calls_to, extract_function_loop)
