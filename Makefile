# Linux shared library. On Windows use MinGW:
#   gcc -O2 -shared -o libnetlock_net.dll netlock_net.c -lws2_32 -liphlpapi
#
# The lib* prefix is required: a file named netlock_net.so next to
# netlock_net.py is imported by Python as the module (no PyInit_*).

CC ?= gcc
CFLAGS ?= -O2 -fPIC -Wall

.PHONY: all clean images dll

all: libnetlock_net.so

libnetlock_net.so: netlock_net.c
	$(CC) $(CFLAGS) -shared -o $@ netlock_net.c

dll: libnetlock_net.dll

libnetlock_net.dll: netlock_net.c
	x86_64-w64-mingw32-gcc -O2 -shared -o $@ netlock_net.c -lws2_32 -liphlpapi

images: libnetlock_net.so
	python3 build_images.py

clean:
	rm -f libnetlock_net.so libnetlock_net.dll netlock_net.so netlock_net.dll netlock.pak netlock.img netlock.iso
