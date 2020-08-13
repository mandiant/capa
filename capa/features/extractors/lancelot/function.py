import logging

try:
    from functools import lru_cache
except ImportError:
    from backports.functools_lru_cache import lru_cache

from lancelot import (
    FLOW_VA,
    FLOW_TYPE,
    FLOW_TYPE_CONDITIONAL_JUMP,
    FLOW_TYPE_CONDITIONAL_MOVE,
    FLOW_TYPE_UNCONDITIONAL_JUMP,
)

from capa.features import Characteristic
from capa.features.extractors import loops

logger = logging.getLogger(__name__)


@lru_cache
def get_call_graph(ws):
    return ws.build_call_graph()


def extract_function_calls_to(ws, f):
    cg = get_call_graph(ws)

    for caller in cg.calls_to.get(f, []):
        yield Characteristic("calls to"), caller


def extract_function_loop(ws, f):
    edges = []
    for bb in ws.build_cfg(f).basic_blocks.values():
        for flow in bb.successors:
            if flow[FLOW_TYPE] in (
                FLOW_TYPE_UNCONDITIONAL_JUMP,
                FLOW_TYPE_CONDITIONAL_JUMP,
                FLOW_TYPE_CONDITIONAL_MOVE,
            ):
                edges.append((bb.address, flow[FLOW_VA]))
                continue

    if edges and loops.has_loop(edges):
        yield Characteristic("loop"), f


FUNCTION_HANDLERS = (extract_function_calls_to, extract_function_loop)


_not_implemented = set([])


def extract_function_features(ws, f):
    for func_handler in FUNCTION_HANDLERS:
        try:
            for feature, va in func_handler(ws, f):
                yield feature, va
        except NotImplementedError:
            if func_handler.__name__ not in _not_implemented:
                logger.warning("not implemented: %s", func_handler.__name__)
                _not_implemented.add(func_handler.__name__)
