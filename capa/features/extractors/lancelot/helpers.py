from lancelot import (
    OPERAND_TYPE,
    MEMORY_OPERAND_BASE,
    MEMORY_OPERAND_DISP,
    OPERAND_TYPE_MEMORY,
    OPERAND_TYPE_IMMEDIATE,
    IMMEDIATE_OPERAND_VALUE,
    IMMEDIATE_OPERAND_IS_RELATIVE,
)


def get_operand_target(insn, op):
    if op[OPERAND_TYPE] == OPERAND_TYPE_MEMORY:
        # call direct, x64
        # rip relative
        # kernel32-64:180001041    call    cs:__imp_RtlVirtualUnwind_0
        if op[MEMORY_OPERAND_BASE] == "rip":
            return op[MEMORY_OPERAND_DISP] + insn.address + insn.length

        # call direct, x32
        # mimikatz:0x403BD3  call    ds:CryptAcquireContextW
        elif op[MEMORY_OPERAND_BASE] == None:
            return op[MEMORY_OPERAND_DISP]

    # call via thunk
    # mimikatz:0x455A41  call    LsaQueryInformationPolicy
    elif op[OPERAND_TYPE] == OPERAND_TYPE_IMMEDIATE and op[IMMEDIATE_OPERAND_IS_RELATIVE]:
        return op[IMMEDIATE_OPERAND_VALUE] + insn.address + insn.length

    elif op[OPERAND_TYPE] == OPERAND_TYPE_IMMEDIATE:
        return op[IMMEDIATE_OPERAND_VALUE]

    raise ValueError("memory operand has no target")
