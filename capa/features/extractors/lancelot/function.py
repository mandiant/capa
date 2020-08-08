import logging

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


def extract_function_switch(ws, f):
    return []


def extract_function_calls_to(ws, f):
    return []


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


FUNCTION_HANDLERS = (extract_function_switch, extract_function_calls_to, extract_function_loop)


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
