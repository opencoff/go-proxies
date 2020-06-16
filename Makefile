# Simple makefile to build this go program

all static: depend
	./build -s


.PHONY: depend clean realclean

depend:

clean realclean:
	-rm -rf bin

