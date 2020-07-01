import idautils
import idaapi

from capa.features import Characteristic
from capa.features.extractors import loops


def _ida_function_contains_switch(f):
    """ check a function for switch statement indicators

        adapted from:
        https://reverseengineering.stackexchange.com/questions/17548/calc-switch-cases-in-idapython-cant-iterate-over-results?rq=1

        arg:
            f (IDA func_t)
    """
    for start, end in idautils.Chunks(f.start_ea):
        for head in idautils.Heads(start, end):
            if idaapi.get_switch_info(head):
                return True

    return False


def extract_function_switch(f):
    """ extract switch indicators from a function

        arg:
            f (IDA func_t)
    """
    if _ida_function_contains_switch(f):
        yield Characteristic("switch", True), f.start_ea


def extract_function_calls_to(f):
    """ extract callers to a function

        args:
            f (IDA func_t)
    """
    for ea in idautils.CodeRefsTo(f.start_ea, True):
        yield Characteristic("calls to", True), ea


def extract_function_loop(f):
    """ extract loop indicators from a function

        args:
            f (IDA func_t)
    """
    edges = []
    for bb in idaapi.FlowChart(f):
        map(lambda s: edges.append((bb.start_ea, s.start_ea)), bb.succs())

    if edges and loops.has_loop(edges):
        yield Characteristic("loop", True), f.start_ea


def extract_recursive_call(f):
    """ extract recursive function call

        args:
            f (IDA func_t)
    """
    for ref in idautils.CodeRefsTo(f.start_ea, True):
        if f.contains(ref):
            yield Characteristic("recursive call", True), f.start_ea
            break


def extract_features(f):
    """ extract function features

        arg:
            f (IDA func_t)
    """
    for func_handler in FUNCTION_HANDLERS:
        for feature, va in func_handler(f):
            yield feature, va


FUNCTION_HANDLERS = (extract_function_calls_to, extract_function_switch, extract_function_loop, extract_recursive_call)


def main():
    features = []

    for f in helpers.get_functions(ignore_thunks=True, ignore_libs=True):
        features.extend(list(extract_features(f)))

    pprint.pprint(features)


if __name__ == "__main__":
    main()
