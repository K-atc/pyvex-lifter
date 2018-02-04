#!/usr/bin/python2
import pyvex
import inspect

def get_attr(cls, name):
    if hasattr(cls, name):
        if name == "tag":
            return cls.tag
        elif name == "type":
            return cls.type
        else:
            raise Exception("Unknown attribute")
    else:
        return None

def do(cls, attr_name):
    v = map(lambda x: x[1],inspect.getmembers(cls, inspect.isclass))
    v = filter(lambda x: x is not None, map(lambda x: get_attr(x, attr_name), v))
    return list(set(v))

def format(tags, type_name):
    print("")
    print("typedef enum %s {" % type_name)
    print("%s%s_Invalid," % (" " * 4, tags[0][:3]))
    for x in tags:
        print('%s%s,' % (" " * 4, x))
    print("} %s;" % type_name)

format(do(pyvex.stmt, "tag"), "vex_tag_ist")
format(do(pyvex.expr, "tag"), "vex_tag_iex")
format(do(pyvex.const, "type"), "vex_tag_ity")
format(do(pyvex.const, "tag"), "vex_tag_ico")