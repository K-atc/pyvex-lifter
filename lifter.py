#!/usr/bin/python2
import pyvex
import archinfo
from capstone import *
import sys
from hexdump import hexdump

class UnhandledStmtError(Exception):
    def __init__(self, x):
        self.expression = x.pp()
        self.message = "Unhandled Statement Error"

def usage():
    print("{} BIN_FILE".format(sys.argv[0]))
    exit(1)

def clean_dir(x):
    print(filter(lambda x: not x.startswith('_'), dir(x)))

def parse_expr_args(args):
    ret = []
    for i, x in enumerate(args):
        ret.append({})
        ret[i]['tag'] = x.tag
        if x.tag in ["Iex_RdTmp"]:
            ret[i]['tmp'] = x.tmp
        elif x.tag in ["Iex_Const"]:
            ret[i]['con'] = int(str(x.con), 16)
        else:
            raise UnhandledStmtError(expr)
    return ret

def parse_expr(expr):
    ret = {}
    ret['tag'] = expr.tag
    if expr.tag in ["Iex_Get"]:
        clean_dir(expr)
        ret['offset'] = expr.offset
        ret['ty'] = expr.ty
    elif expr.tag in ["Iex_Const"]:
        ret['con'] = int(str(expr.con), 16)
    elif expr.tag in ["Iex_RdTmp"]:
        ret['tmp'] = expr.tmp
    elif expr.tag in ["Iex_Binop", "Iex_Unop"]:
        ret['op'] = expr.op
        ret['args'] = parse_expr_args(expr.args)
    elif expr.tag in ["Iex_Load"]:
        ret['addr'] = parse_expr(expr.addr)
        ret['ty'] = expr.ty
    elif expr.tag in ["Iex_CCall"]:
        ret['retty'] = expr.retty
        ret['cee'] = expr.cee
        ret['args'] = parse_expr_args(expr.args)
    else:
        raise UnhandledStmtError(expr)
    return ret

def Lift(insn_bytes, START_ADDR, count):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    # for i in md.disasm(insn_bytes, 0x1000):
    #     print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    #     print("%r" % i.bytes)
    #     irsb = pyvex.IRSB(bytes(i.bytes), START_ADDR, archinfo.ArchAMD64(), max_bytes=len(i.bytes))
    #     irsb.pp()

    offset = 0
    len_insn_bytes = len(insn_bytes)
    if count < len_insn_bytes:
        len_insn_bytes = count
        insn_bytes = insn_bytes[:len_insn_bytes]
    insns = []
    while offset < len_insn_bytes:
        ### print a instruction
        print("")
        for insn in md.disasm(insn_bytes[offset:], START_ADDR + offset):
            print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
            # irsb = pyvex.IRSB(bytes(insn.bytes), insn.address, archinfo.ArchAMD64(), max_bytes=insn.size)
            break
        if True:
            try:
                irsb = pyvex.IRSB(insn_bytes[offset:], insn.address, archinfo.ArchAMD64())
            except Exception as e:
                print("[!] Exception: " + str(e))
                break # quit lifting
            offset += irsb.size
            # continue
            
            ### pretty print a basic block
            irsb.pp()

            ### interpret statements
            for stmt in irsb.statements:
                ### Skip lifting
                if stmt.tag in ["Ist_Put", "Ist_IMark"]:
                    # continue
                    pass
                
                # clean_dir(stmt)
                print("")
                stmt.pp()

                ret = {}
                ret['full'] = str(stmt)
                ret['tag'] = stmt.tag
                if False:
                    pass
                elif stmt.tag in ["Ist_Put"]:
                    ret['data'] = parse_expr(stmt.data)
                    ret['offset'] = stmt.offset
                elif stmt.tag in ["Ist_Store"]:
                    ret['data'] = parse_expr(stmt.data)
                elif stmt.tag in ["Ist_WrTmp"]:
                    ret['tmp'] = stmt.tmp
                    ret['data'] = parse_expr(stmt.data)
                elif stmt.tag == "Ist_Exit":
                    ret['jumpkind'] = stmt.jumpkind
                    ret['guard'] = parse_expr(stmt.guard)
                    ret['offsIP'] = stmt.offsIP
                    ret['dst'] = int(str(stmt.dst), 16)
                elif stmt.tag == "Ist_IMark":
                    ret['addr'] = stmt.addr
                    ret['len'] = stmt.len
                elif stmt.tag == "Ist_AbiHint":
                    ret['base'] = parse_expr(stmt.base)
                    ret['len'] = stmt.len
                    ret['nia'] = int(str(stmt.nia), 16)
                else:
                    raise UnhandledStmtError(stmt)
                print ret
                insns.append(ret)
    return insns

if __name__ == '__main__':
    if len(sys.argv) < 2:
        usage()

    BIN_FILE = sys.argv[1]
    START_ADDR = 0x4000a5

    with open(BIN_FILE, 'rb') as f:
        insn_bytes = f.read()[0x25:]

    insns = Lift(insn_bytes, START_ADDR, count)
    # for x in insns:
    #     print(x)