#!/usr/bin/python2
from lifter import *

# def usage():
#     print("{} BIN_FILE".format(sys.argv[0]))
#     exit(1)

if __name__ == '__main__':
    # import sys
    # if len(sys.argv) < 2:
    #     usage()

    BIN_FILE = "correct-argv1.bin"
    START_ADDR = 0x4000a5

    with open(BIN_FILE, 'rb') as f:
        insn_bytes = f.read()[0x25:]

    insns = Lift(insn_bytes, START_ADDR)
    for x in insns:
        # print(x)
        pass