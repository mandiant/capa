# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

import idaapi
import idautils

import capa.features.extractors.ida.helpers
from capa.features import Characteristic
from capa.features.extractors import loops


def extract_function_switch(f):
    """ extract switch indicators from a function

        arg:
            f (IDA func_t)
    """
    if capa.features.extractors.ida.helpers.is_function_switch_statement(f):
        yield Characteristic("switch"), f.start_ea


def extract_function_calls_to(f):
    """ extract callers to a function

        args:
            f (IDA func_t)
    """
    for ea in idautils.CodeRefsTo(f.start_ea, True):
        yield Characteristic("calls to"), ea


def extract_function_loop(f):
    """ extract loop indicators from a function

        args:
            f (IDA func_t)
    """
    edges = []

    # construct control flow graph
    for bb in idaapi.FlowChart(f):
        for succ in bb.succs():
            edges.append((bb.start_ea, succ.start_ea))

    if loops.has_loop(edges):
        yield Characteristic("loop"), f.start_ea


def extract_recursive_call(f):
    """ extract recursive function call

        args:
            f (IDA func_t)
    """
    if capa.features.extractors.ida.helpers.is_function_recursive(f):
        yield Characteristic("recursive call"), f.start_ea


def extract_features(f):
    """ extract function features

        arg:
            f (IDA func_t)
    """
    for func_handler in FUNCTION_HANDLERS:
        for (feature, ea) in func_handler(f):
            yield feature, ea


FUNCTION_HANDLERS = (extract_function_calls_to, extract_function_switch, extract_function_loop, extract_recursive_call)


def main():
    """ """
    features = []
    for f in capa.features.extractors.ida.get_functions(skip_thunks=True, skip_libs=True):
        features.extend(list(extract_features(f)))

    import pprint

    pprint.pprint(features)


if __name__ == "__main__":
    main()
