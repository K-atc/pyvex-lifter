#!/usr/bin/python2
import pyvex
import archinfo
from capstone import *

class UnhandledStmtError(Exception):
    def __init__(self, x):
        self.expression = x.pp()
        self.message = "Unhandled Statement Error"

def clean_dir(x):
    print(filter(lambda x: not x.startswith('_'), dir(x)))

def parse_const(const):
    ret = {}
    ret['tag'] = const.tag
    ret['size'] = const.size
    ret['value'] = const.value
    return ret

def parse_expr_args(args, tyenv=None):
    ret = []
    for i, x in enumerate(args):
        ret.append({})
        ret[i]['tag'] = x.tag
        if (tyenv is not None) and hasattr(x, "result_size"):
            ret[i]['result_size'] = int(x.result_size(tyenv))
        if x.tag in ["Iex_RdTmp"]:
            ret[i]['tmp'] = x.tmp
        elif x.tag in ["Iex_Const"]:
            ret[i]['con'] = int(str(x.con), 16)
        else:
            raise UnhandledStmtError(expr)
    return ret

def parse_expr(expr, tyenv=None):
    ret = {}
    ret['tag'] = expr.tag
    if (tyenv is not None) and hasattr(expr, "result_size"):
        ret['result_size'] = int(expr.result_size(tyenv))
    if hasattr(expr, "endness"):
        ret['endness'] = expr.endness
    if expr.tag in ["Iex_Get"]:
        ret['offset'] = expr.offset
        ret['ty'] = expr.ty
    elif expr.tag in ["Iex_Const"]:
        ret['con'] = int(str(expr.con), 16)
    elif expr.tag in ["Iex_RdTmp"]:
        ret['tmp'] = expr.tmp
    elif expr.tag in ["Iex_Binop", "Iex_Unop"]:
        ret['op'] = expr.op
        ret['args'] = parse_expr_args(expr.args, tyenv=tyenv)
        ret['nargs'] = len(ret['args'])
    elif expr.tag in ["Iex_Load"]:
        ret['addr'] = parse_expr(expr.addr, tyenv=tyenv)
        ret['ty'] = expr.ty
    elif expr.tag in ["Iex_CCall"]:
        ret['retty'] = expr.retty
        ret['cee'] = expr.cee
        ret['args'] = parse_expr_args(expr.args, tyenv=tyenv)
    else:
        raise UnhandledStmtError(expr)
    return ret

def Lift(insn_bytes, START_ADDR, count):
    try:
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
            disasm_str = ""
            for insn in md.disasm(insn_bytes[offset:], START_ADDR + offset):
                # print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
                disasm_str = "%s\t%s" %(insn.mnemonic, insn.op_str)
                # irsb = pyvex.IRSB(bytes(insn.bytes), insn.address, archinfo.ArchAMD64(), max_bytes=insn.size)
                break
            if True:
                irsb = pyvex.IRSB(insn_bytes[offset:], insn.address, archinfo.ArchAMD64())

                offset += irsb.size
                # continue

                ### pretty print a basic block
                irsb.pp()

                ### fetch block jumpkind
                block_jump_insn = {}
                if irsb.jumpkind:
                    block_jump_insn['full'] = irsb.jumpkind.split('_', 1)[1]
                    block_jump_insn['tag'] = "Ist_Jump"
                    block_jump_insn['jumpkind'] = irsb.jumpkind

                ### interpret statements
                for stmt in irsb.statements:
                    # clean_dir(stmt)
                    # print("")
                    # stmt.pp()

                    ret = {}
                    ret['full'] = str(stmt)
                    ret['tag'] = stmt.tag
                    if False:
                        pass
                    elif stmt.tag in ["Ist_Put"]:
                        ret['data'] = parse_expr(stmt.data, tyenv=irsb.tyenv)
                        ret['offset'] = stmt.offset
                    elif stmt.tag in ["Ist_Store"]:
                        ret['addr_expr'] = parse_expr(stmt.addr) # <pyvex.expr.RdTmp object at 0x7f44c6c5ba70>
                        ret['endness'] = stmt.endness
                        ret['data'] = parse_expr(stmt.data, tyenv=irsb.tyenv)
                    elif stmt.tag in ["Ist_WrTmp"]:
                        ret['tmp'] = stmt.tmp
                        ret['data'] = parse_expr(stmt.data, tyenv=irsb.tyenv)
                    elif stmt.tag == "Ist_Exit":
                        ret['jumpkind'] = stmt.jumpkind
                        ret['guard'] = parse_expr(stmt.guard, tyenv=irsb.tyenv)
                        ret['offsIP'] = stmt.offsIP
                        ret['dst'] = parse_const(stmt.dst)
                    elif stmt.tag == "Ist_IMark":
                        ret['addr'] = stmt.addr
                        ret['len'] = stmt.len
                        ret['disasm'] = disasm_str
                    elif stmt.tag == "Ist_AbiHint":
                        ret['base'] = parse_expr(stmt.base, tyenv=irsb.tyenv)
                        ret['len'] = stmt.len
                        ret['nia'] = int(str(stmt.nia), 16)
                    else:
                        raise UnhandledStmtError(stmt)

                    # print ret
                    insns.append(ret)
                if block_jump_insn is not {}:
                    insns.append(block_jump_insn)
                    pass

    except Exception as e:
        import sys, os
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        sys.stderr.write("[!] Exception: %s\n" % str((str(e), fname, exc_tb.tb_lineno)))

    return insns
