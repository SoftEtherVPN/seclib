# Makefile

OPTIONS_COMPILE_DEBUG=-D_DEBUG -DDEBUG -D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64 -I./seclib_src/ -g -fsigned-char

OPTIONS_LINK_DEBUG=-g -fsigned-char -lm -ldl -lrt -lpthread -lssl -lcrypto -lreadline -lncurses -lz

OPTIONS_COMPILE_RELEASE=-DNDEBUG -DVPN_SPEED -D_REENTRANT -DREENTRANT -D_THREAD_SAFE -D_THREADSAFE -DTHREAD_SAFE -DTHREADSAFE -D_FILE_OFFSET_BITS=64 -I./seclib_src/ -O2 -fsigned-char

OPTIONS_LINK_RELEASE=-O2 -fsigned-char -lm -ldl -lrt -lpthread -lssl -lcrypto -lreadline -lncurses -lz

HEADERS_SECLIB=seclib_src/seclib.h

OBJECTS_SECLIB=obj/obj/linux/seclib.o obj/obj/linux/seclib_test.o

ifeq ($(DEBUG),YES)
	OPTIONS_COMPILE=$(OPTIONS_COMPILE_DEBUG)
	OPTIONS_LINK=$(OPTIONS_LINK_DEBUG)
else
	OPTIONS_COMPILE=$(OPTIONS_COMPILE_RELEASE)
	OPTIONS_LINK=$(OPTIONS_LINK_RELEASE)
endif


# Build Action
default:	build

build:	$(OBJECTS_SECLIB) bin/sectest

obj/obj/linux/seclib.o: seclib_src/seclib.c $(HEADERS_SECLIB)
	@mkdir -p obj/obj/linux/
	@mkdir -p bin/
	$(CC) $(OPTIONS_COMPILE) -c seclib_src/seclib.c -o obj/obj/linux/seclib.o

obj/obj/linux/seclib_test.o: seclib_src/seclib_test.c $(HEADERS_SECLIB)
	$(CC) $(OPTIONS_COMPILE) -c seclib_src/seclib_test.c -o obj/obj/linux/seclib_test.o

bin/sectest: obj/obj/linux/seclib.o $(HEADERS_SECLIB) $(OBJECTS_SECLIB)
	$(CC) obj/obj/linux/seclib.o obj/obj/linux/seclib_test.o $(OPTIONS_LINK) -o bin/sectest

clean:
	-rm -f $(OBJECTS_SECLIB)
	-rm -f bin/sectest

help:
	@echo "make [DEBUG=YES]"
	@echo "make install"
	@echo "make clean"


