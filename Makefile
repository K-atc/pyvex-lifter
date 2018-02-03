all: lifter
	# 
lifter: lifter.cpp
	g++ -o $@ $< -lpython2.7

test: lifter
	./lifter correct-argv1.bin 0x25 0x400080

test-gdb: lifter
	gdb -q ./lifter -ex "r correct-argv1.bin 0x25 0x400080"