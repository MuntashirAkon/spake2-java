ifeq ($(OS),Windows_NT)
	detected_os := Windows
else
	detected_os := $(shell sh -c 'uname 2>/dev/null || echo Unknown')
endif

test: test.c spake25519.c sha512.c sha512.h ed25519.c curve25519_32.h
	gcc -o test test.c
	./test

lib: spake2.cpp spake25519.c sha512.c sha512.h ed25519.c curve25519_32.h
	gcc -o spake2.o -c -fPIC -I${JAVA_HOME}/include spake2.cpp
ifeq ($(detected_os),Darwin)
	gcc -dynamiclib -o libspake2.dylib spake2.o -lc
endif
ifeq ($(detected_os),Linux)
	gcc -shared -fPIC -o libspake2.so spake2.o -lc
endif
ifeq ($(detected_os),Windows)
	gcc -shared -o spake2.dll spake2.o -Wl,--add-stdcall-alias
endif
