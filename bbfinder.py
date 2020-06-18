import sys
from capstone import *
from capstone.x86 import *
from itertools import tee

"""List of basic blocks.

They are denoted as their starting address (leaders).

Example: BASIC_BLOCKS = [0x0, 0x12, 0x40]
"""
BASIC_BLOCKS = []


def getJumpTargets(disas):
    """Get the targets to jump and call instructions.

    Takes a list of Capstone disassembled instructions.
    Returns a list of jump target addresses
    Example: [0x0, 0x1, 0x3] <- getJumpTargets(disas)
    """
    targets = []
    for op in disas:
        if op.group(CS_GRP_JUMP):
            # op is of semantic JUMP group
            targets.append(op.operands[0].value.imm)

        if op.group(CS_GRP_CALL):
            # op is of semantic CALL group
            targets.append(op.operands[0].value.imm)
    return targets


def getJumpSuccessors(disas):
    """Get all instructions that follow a jump or call instruction.

    Takes a list of Capstone disassembled instructions.
    Returns a list of instructions that succeed a jump instruction.
    Example:  [0x0, 0xC1, 0xFF] <- def getJumpSuccessors(disas):
    """
    successors = []
    for op in disas:
        if op.group(CS_GRP_JUMP):
            # op is of semantic JUMP group
            successors.append(next(disas).address)
        if op.group(CS_GRP_CALL):
            # op is of semantic CALL group
            successors.append(next(disas).address)
    return successors


if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} FILE")
    sys.exit(-1)

CODE = open(sys.argv[1], "rb").read()
try:
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = True
    disas = md.disasm(CODE, 0x0)
except CsError as e:
    print("ERROR: %s" % e)
    sys.exit(-1)

# Preserve original of generator
disas, frshDisas = tee(disas)

# add start address as basic block
BASIC_BLOCKS.append(0x0)

jumpTargets = getJumpTargets(disas)
# All jump targets are leaders
BASIC_BLOCKS += jumpTargets

# Reset generator
disas = frshDisas

succJump = getJumpSuccessors(disas)
# All instructions following jumps are leaders
BASIC_BLOCKS += succJump


# Remove duplicates and sort by address
BASIC_BLOCKS = sorted(list(set(BASIC_BLOCKS)))

for b in BASIC_BLOCKS:
    print("0x%x" % b)