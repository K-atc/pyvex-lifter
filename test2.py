#!/usr/bin/python2
from lifter import *

test_insns = [
(0x400000, "\x48\x8b\x05\xb8\x13\x00\x00",),
(0x400007, "\x48\x8d\x34\xc3",),
(0x40000b, "\x67\x48\x8D\x74\xC3\x0A",),
(0x40000b, "\x67\x8D\x74\xC3\x0A",),
(0x40000b, "\x48\x8D\x74\xDB\x0A",),
(0x40000b, "\x48\x8D\x74\xC3\x0A",),
(0x40000b, "\x48\x8D\x73\x0A",),
(0x400011, "\x66\x0F\xD7\xD1",),
(0x400015, "\x90\xd0",),
(0x400017, "\x80\xf4\x99",),
(0x40001a, "\x48\x31\xc0",),
(0x40001d, "\x80\x30\x99",),
(0x400020, "\x80\x30\x99",),
(0x400023, "\x0F\x87\x00\x00\x00\x00",),
]

if __name__ == '__main__':
    import sys

    for addr, insn_bytes in test_insns:
        insns = Lift(insn_bytes, addr)
        for x in insns:
            print(x)
            pass