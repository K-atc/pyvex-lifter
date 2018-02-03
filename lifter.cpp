#include <stdio.h>
#include <python2.7/Python.h>
#include <string>
#include <vector>
#include <map>

#include <string.h>
#include <fstream>

typedef enum vex_tag_ist {
	Ist_Invalid,
	Ist_Put,
	Ist_Store,
	Ist_WrTmp,
	Ist_Exit,
	Ist_IMark,
	Ist_AbiHint,
} vex_tag_ist;

typedef enum vex_tag_iex {
	Iex_Invalid,
	Iex_Get,
	Iex_Const,
	Iex_RdTmp,
	Iex_BinOp,
	Iex_UnOp,
	Iex_Load,
	Iex_CCall,
} vex_tag_iex;

typedef enum vex_tag_ity {
	Ity_Invalid,
	Ity_I8,
	Ity_I16,
	Ity_I32,
	Ity_I64,
} vex_tag_ity;

typedef struct vex_expr {
	vex_tag_iex tag = Iex_Invalid;
	int con = 0;
	int tmp = 0;
	int offset = 0;
} vex_expr;

typedef struct vex_data {
	vex_tag_iex tag = Iex_Invalid;
	vex_tag_ity ty = Ity_Invalid;
	std::string op = "Iop_Invalid";
	int con = 0;
	int tmp = 0;
	int offset = 0;
	vex_expr args[8];
} vex_data;

typedef struct vex_insn {
	vex_tag_ist tag = Ist_Invalid;
	int offset = 0;
	vex_data data;
	std::string full = "";
	int addr = 0;
	int len = 0;
} vex_insn;

typedef std::vector<struct vex_insn> vex_insns;
typedef std::map<unsigned int, vex_insns> vex_insns_group;

#define tag_str_to_enum(x) if (tag == #x) {return x;}
#define tag_enum_to_str(x) if (tag == x) {return #x;}

vex_tag_ist vex_tag_ist_str_to_enum(std::string tag)
{
	tag_str_to_enum(Ist_Put);
	tag_str_to_enum(Ist_Store);
	tag_str_to_enum(Ist_WrTmp);
	tag_str_to_enum(Ist_Exit);
	tag_str_to_enum(Ist_IMark);
	tag_str_to_enum(Ist_AbiHint);
	return Ist_Invalid;
}

std::string vex_tag_enum_to_str(vex_tag_ist tag)
{
	tag_enum_to_str(Ist_Put);
	tag_enum_to_str(Ist_Store);
	tag_enum_to_str(Ist_WrTmp);
	tag_enum_to_str(Ist_Exit);
	tag_enum_to_str(Ist_IMark);
	tag_enum_to_str(Ist_AbiHint);
	return "Ist_Invalid";
}

vex_tag_iex vex_tag_iex_str_to_enum(std::string tag)
{
	tag_str_to_enum(Iex_Get);
	tag_str_to_enum(Iex_Const);
	tag_str_to_enum(Iex_RdTmp);
	tag_str_to_enum(Iex_BinOp);
	tag_str_to_enum(Iex_UnOp);
	tag_str_to_enum(Iex_Load);
	tag_str_to_enum(Iex_CCall);
	return Iex_Invalid;
}

std::string vex_tag_enum_to_str(vex_tag_iex tag)
{
	tag_enum_to_str(Iex_Get);
	tag_enum_to_str(Iex_Const);
	tag_enum_to_str(Iex_RdTmp);
	tag_enum_to_str(Iex_BinOp);
	tag_enum_to_str(Iex_UnOp);
	tag_enum_to_str(Iex_Load);
	tag_enum_to_str(Iex_CCall);
	return "Iex_Invalid";
}

vex_tag_ity vex_tag_ity_str_to_enum(std::string tag)
{
	tag_str_to_enum(Ity_Invalid);
	tag_str_to_enum(Ity_I8);
	tag_str_to_enum(Ity_I16);
	tag_str_to_enum(Ity_I32);
	tag_str_to_enum(Ity_I64);
	return Ity_Invalid;
}

std::string vex_tag_enum_to_str(vex_tag_ity tag)
{
	tag_enum_to_str(Ity_Invalid);
	tag_enum_to_str(Ity_I8);
	tag_enum_to_str(Ity_I16);
	tag_enum_to_str(Ity_I32);
	tag_enum_to_str(Ity_I64);
	return "Ity_Invalid";
}

void print_vex_insn_data(vex_data data, const char* prefix)
{
	if (data.tag == Iex_Invalid) return;
	printf("\t%s.tag = %s\n", prefix, vex_tag_enum_to_str(data.tag).c_str());
	printf("\t%s.ty = %s\n", prefix, vex_tag_enum_to_str(data.ty).c_str());
	printf("\t%s.op = %s\n", prefix, data.op.c_str());
	printf("\t%s.con = 0x%x\n", prefix, data.con);
	printf("\t%s.tmp = %d\n", prefix, data.tmp);
}

void print_vex_insns(vex_insns insns)
{
	for (auto &insn : insns) {
		puts("");
		printf("%s\n", insn.full.c_str());
		printf("\ttag = %s\n", vex_tag_enum_to_str(insn.tag).c_str());
		printf("\toffset = %d\n", insn.offset);
		print_vex_insn_data(insn.data, "data");
		if (insn.tag == Ist_IMark) {
			printf("\taddr = 0x%x\n", insn.addr);
			printf("\tlen = %d\n", insn.len);
		}
	}
}

bool vex_lift(vex_insns_group *insns_group, unsigned char *insns_bytes, unsigned int start_addr, int count)
{
	PyObject *global, *func;

	// Python インタプリタの起動
	Py_Initialize();

	PyRun_SimpleString("import sys");
	PyRun_SimpleString("sys.path.append(\".\")");
	PyRun_SimpleString("from lifter import Lift");

	// スクリプトの関数への参照を取得
	global = PyModule_GetDict(PyImport_ImportModule("__main__"));
	func = PyDict_GetItemString(global, "Lift");

	// もし参照がうまくとれたら
	if (PyCallable_Check(func))
    {
		// 評価する
		PyObject *ans = PyEval_CallFunction(func, "zii", insns_bytes, start_addr, count);
		if( ans )
		{
			if (PyList_Check(ans)) {
				unsigned int current_addr;
				for(Py_ssize_t i = 0; i < PyList_Size(ans); i++) {
					PyObject *item = PyList_GetItem(ans, i);
					struct vex_insn insn;
					PyObject *v, *data, *args;
					v = PyDict_GetItemString(item, "full");
					insn.full = PyString_AsString(v);
					v = PyDict_GetItemString(item, "tag");
					insn.tag = vex_tag_ist_str_to_enum(PyString_AsString(v));
					v = PyDict_GetItemString(item, "offset");
					if (v) insn.offset = PyInt_AsLong(v);
					v = PyDict_GetItemString(item, "addr");
					if (v) insn.addr = PyInt_AsLong(v);	
					v = PyDict_GetItemString(item, "len");
					if (v) insn.len = PyInt_AsLong(v);					
					data = PyDict_GetItemString(item, "data");
					if (data) { 
						v = PyDict_GetItemString(data, "tag");
						insn.data.tag = vex_tag_iex_str_to_enum(PyString_AsString(v));
						v = PyDict_GetItemString(data, "ty");
						if (v) insn.data.ty = vex_tag_ity_str_to_enum(PyString_AsString(v));
						v = PyDict_GetItemString(data, "op");
						if (v) insn.data.op = PyString_AsString(v);
						v = PyDict_GetItemString(data, "tmp");
						if (v) insn.data.tmp = PyInt_AsLong(v);
						v = PyDict_GetItemString(data, "con");
						if (v) insn.data.con = PyInt_AsLong(v);		
						v = PyDict_GetItemString(data, "offset");
						if (v) insn.data.offset = PyInt_AsLong(v);
						args = PyDict_GetItemString(data, "args");
						if (args) {
							for(Py_ssize_t j = 0; j < PyList_Size(args); j++) {
								v = PyDict_GetItemString(item, "tmp");								
								if (v) insn.data.args[j].tmp = PyInt_AsLong(v);
								v = PyDict_GetItemString(item, "con");								
								if (v) insn.data.args[j].con = PyInt_AsLong(v);
								v = PyDict_GetItemString(item, "offset");								
								if (v) insn.data.args[j].offset = PyInt_AsLong(v);
							}
						}
					}

					if (insn.tag == Ist_IMark) {
						current_addr = insn.addr;
						(*insns_group)[current_addr].push_back(insn);
					}
					else {
						(*insns_group)[current_addr].push_back(insn);
					}
				}
			} else {
				fprintf(stderr, "Passed PyObject pointer was not a list or tuple!");
			}
			for(auto itr = insns_group->begin(); itr != insns_group->end(); ++itr) {
				printf("address = 0x%x\n", itr->first);
				print_vex_insns(itr->second);
			}
		}
		Py_DECREF(ans);
	}
	else {
		fprintf(stderr, "ref error\n");
		return false;
	}

	// リファレンスを解放
	Py_DECREF(global);
    Py_DECREF(func);

	// インタプリタ終了
	Py_Finalize();

	return true;
}

void usage(const char *argv[])
{
	fprintf(stderr, "usage: %s BIN_FILE BIN_OFFSET(hex) START_ADDR(hex)\n", argv[0]);
	exit(1);
}

size_t getFileSize(const char* file_name)
{
    struct stat st;
    if(stat(file_name, &st) != 0) {
        return 0;
    }
    return st.st_size; 
}

static size_t readFileAll(const char* file_name, unsigned char* read_to, size_t size)
{
    if (read_to == nullptr) {
        fprintf(stderr, "in readfileAll, param read_to is nullptr. exit");
        return 0;
    }
    std::ifstream ifs(file_name);
    if (ifs.fail()) {
        fprintf(stderr, "Fialed to read %s. exit", file_name);
        return 0;
    }
    std::string read_to_str((std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>());
    memset(read_to, 0, size);
    memcpy(read_to, read_to_str.c_str(), size);
    return strlen((char *) read_to);
}

int main(int argc, const char *argv[])
{
	char bug[1024];
	if (argc < 4) {
		usage(argv);
	}
	const char *BinFileName = argv[1];
	int bin_offset = strtol(argv[2], 0, 16);
	printf("offset = 0x%x\n", bin_offset);
	unsigned int start_addr = strtol(argv[3], 0, 16);
	printf("start_addr = 0x%x\n", start_addr);
    size_t file_size = getFileSize(BinFileName);
    unsigned char* bin;
    bin = (unsigned char*) malloc(file_size);
    readFileAll(BinFileName, bin, file_size);

	vex_insns_group insns_group;
	bool err;
	// err = vex_lift(&insns, (unsigned char *)"\x48\x89\xe5");
	err = vex_lift(&insns_group, &bin[bin_offset], start_addr, file_size - bin_offset);
	return 0;
}