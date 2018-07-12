# Simple makefile to build this go program

all: depend
	./build


static: depend
	./build -s


.PHONY: depend

depend:
	./dep.sh sync

