CC ?= gcc
CCLD ?= $(CC)
AR ?= ar
CFLAGS ?= -O3 -g -fstack-protector-strong -fstack-clash-protection -fcf-protection=full -D_FORTIFY_SOURCE=2 -fPIC -fPIE
CCLDFLAGS ?= -Wl,-z,relro -Wl,-z,now -pie
CCLDFLAGS_S ?= -Wl,-z,relro -Wl,-z,now -static-pie

all: ctrtool ctrtool-static

ctrtool-static: ctrtool.a arch/current/arch.a
	$(CCLD) $(CCLDFLAGS_S) -o $@ $^

ctrtool: ctrtool.a arch/current/arch.a
	$(CCLD) $(CCLDFLAGS) -o $@ $^

ctrtool.a: container-launcher.o cl-nsenter.o ctrtool-common.o container-rootfs-mount.o debug_shell.o mini-init.o reset_cgroup.o set_fds.o simple-renameat2.o mount_seq.o main.o
	$(AR) r $@ $^

arch/current/arch.a:
	make -C arch all

%.o: %.c ctrtool-common.h arch/current/arch.a
	$(CC) $(CFLAGS) -c -o $@ $< -Wall

clean:
	rm -f *.o ctrtool ctrtool-static ctrtool.a
	make -C arch clean

.PHONY: all clean
