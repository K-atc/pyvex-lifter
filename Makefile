all: lifter
	#

lifter: lifter.cpp lifter.py.inc
	g++ -std=c++11 -o $@ $< -lpython2.7

%.py.inc: %.py
	(echo 'const char script[] = ""'; sed -e 's/\\/\\\\/g' -e 's/\"/\\\"/g' -e 's/^/\t\"/g' -e 's/$$/\\n\"/g' $<; echo ' "";') > $@

test: lifter
	./lifter correct-argv1.bin 0x25 0x4000a5

test-gdb: lifter
	gdb -q ./lifter -ex "r correct-argv1.bin 0x25 0x4000a5"