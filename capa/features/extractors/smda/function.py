from capa.features.common import Characteristic
from capa.features.extractors import loops


def extract_function_calls_to(f):
    for inref in f.inrefs:
        yield Characteristic("calls to"), inref


def extract_function_loop(f):
    """
    parse if a function has a loop
    """
    edges = []
    for bb_from, bb_tos in f.blockrefs.items():
        for bb_to in bb_tos:
            edges.append((bb_from, bb_to))

    if edges and loops.has_loop(edges):
        yield Characteristic("loop"), f.offset


def extract_features(f):
    """
    extract features from the given function.

    args:
      f (smda.common.SmdaFunction): the function from which to extract features

    yields:
      Tuple[Feature, int]: the features and their location found in this function.
    """
    for func_handler in FUNCTION_HANDLERS:
        for feature, va in func_handler(f):
            yield feature, va


FUNCTION_HANDLERS = (extract_function_calls_to, extract_function_loop)
