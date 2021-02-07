CC ?= gcc
CCLD ?= $(CC)
CFLAGS ?= -O2 -g -fstack-protector-strong -D_FORTIFY_SOURCE=2
CCLDFLAGS ?= -Wl,-z,relro -Wl,-z,now

all: ctrtool

ctrtool: container-launcher.o container-rootfs-mount.o mini-init.o reset_cgroup.o simple-renameat2.o mount_seq.o main.o
	$(CCLD) $(CCLDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $< -Wall

clean:
	rm -f *.o ctrtool

.PHONY: all clean
