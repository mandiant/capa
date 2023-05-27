import logging

import fixtures
from fixtures import *

import capa.main

logger = logging.getLogger(__file__)

# We need to skip the ghidra test if we cannot import ghidra modules, e.g., in GitHub CI.
ghidra_present: bool = False
try:
    import ghidra.program.flatapi as flatapi
    ghidraapi = flatapi.FlatProgramAPI(currentProgram) 

    try:
        current_program_test = ghidraapi.getCurrentProgram()
    except RuntimeError as e:
        logger.warning("Ghidra runtime not detected")
    else:
        ghidra_present = True
except ImportError:
    pass


