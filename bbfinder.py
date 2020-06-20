import sys
from capstone import *
from capstone.x86 import *
from itertools import tee
# from unittest import assertIn

"""List of basic blocks.

They are denoted as their starting address (leaders).

Example: BASIC_BLOCKS = [0x0, 0x12, 0x40]
"""
BASIC_BLOCKS = []


def getJumpTargets(disas):
    """Get the targets to jump and call instructions.

    Takes a interator of Capstone disassembled instructions.
    Returns a list of jump target addresses
    Example: [0x0, 0x1, 0x3] <- getJumpTargets(disas)
    """
    targets = []
    for op in disas:
        if op.group(CS_GRP_JUMP):
            # op is of semantic JUMP group
            targets.append(op.operands[0].value.imm)
        # Uncomment if call targets are considered basic blocks
        # if op.group(CS_GRP_CALL):
        #   # op is of semantic CALL group
        #    targets.append(op.operands[0].value.imm)
    return targets


def getJumpSuccessors(disas):
    """Get all instructions that follow a jump or call instruction.

    Takes an iterator of Capstone disassembled instructions.
    Returns a list of instructions that succeed a jump instruction.
    Example:  [0x0, 0xC1, 0xFF] <- getJumpSuccessors(disas):
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


def writeDOT(adjacency):
    """Write the graph as a DOT file.

    Expects an adjacency dictionary as returned by makeEdges().
    Writes its output to cfg.dot on the filesystem.
    """
    with open("cfg.dot", "w") as fd:
        fd.write('digraph basic_blocks {\n')
        for B in adjacency:
            for adj in adjacency[B]:
                fd.write(f'\t"0x{B:x}" -> "0x{adj:x}"\n')
        fd.write('}\n')


def endsBasicBlock(op, BASIC_BLOCKS):
    """Return whether an op ends a basic block."""
    return op.group(CS_GRP_JUMP) or op.group(CS_GRP_CALL) or op.group(CS_GRP_RET)


def makeEdges(disas, BASIC_BLOCKS):
    """Connect the BASIC_BLOCKS by edges.

    Takes a generator of Capstone disassembled instructions and a list of basic blocks.
    Returns an adjacency matrix[i][j] (Python dict) of a directed graph where i->j are edges.
    Example: {0x0: [0x2], 0x1: [0x0], 0x2: [0x0, 0x1]}<- makeEdges(disas, BASIC_BLOCKS)
    In the example 0x0->0x2, 0x1->0x0, 0x2->0x0, 0x2->0x1 are the directed edges.
    """
    disas, frshDisas = tee(disas)
    adjacency = {}
    for B in BASIC_BLOCKS:
        disas, frshDisas = tee(frshDisas)
        adjB = []
        # walk the code up to the block
        # assumes first basic block is the lowest address of course
        op = next(disas)
        while op.address < B:
            op = next(disas)
        op = next(disas)
        while op.address not in BASIC_BLOCKS:
            # walk up to the next block
            if(endsBasicBlock(op, BASIC_BLOCKS)):
                # block ends with jump or call
                # the original block thus has an edge to the leader
                if op.group(CS_GRP_JUMP):
                    adjB.append(op.operands[0].value.imm)
                    if not op.mnemonic == "jmp":
                        # conditional jump, next block is also a succeeding block
                        try:
                            op = next(disas)
                            adjB.append(op.address)
                        except StopIteration:
                            raise
                    break
                # Uncomment if called functions are considered a basic block
                # elif op.group(CS_GRP_CALL):
                #    adjB.append(op.operands[0].value.imm)
                #    break
                elif op.group(CS_GRP_RET):
                    break
            try:
                op = next(disas)
            except StopIteration:
                break
        else:
            # For single instructions that are immediately succeeded by another basic block
            adjB.append(op.address)
        adjacency[B] = adjB
    return adjacency


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
disas, frshDisas = tee(frshDisas)

succJump = getJumpSuccessors(disas)
# All instructions following jumps are leaders
BASIC_BLOCKS += succJump

# Remove duplicates and sort by address
BASIC_BLOCKS = sorted(list(set(BASIC_BLOCKS)))

print("# Basic blocks identified by their starting address:")
for b in BASIC_BLOCKS:
    print("0x%x" % b)

# Reset generator
disas, frshDisas = tee(frshDisas)

print("\n# Basic blocks and their connected basic blocks:")
adjacency = makeEdges(disas, BASIC_BLOCKS)
for B in adjacency:
    nodes = ', '.join('0x%x' % i for i in adjacency[B])
    print(f"0x{B:x}: {nodes}")

writeDOT(adjacency)
