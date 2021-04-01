CC ?= $(CROSS_COMPILE)gcc
CCLD ?= $(CC)
AR ?= $(CROSS_COMPILE)ar
CFLAGS ?= -O3 -g -Wall -fstack-protector-strong -fstack-clash-protection -fcf-protection=full -D_FORTIFY_SOURCE=2 -fPIC -fPIE $(CFLAGS_EXTRA)
CCLDFLAGS ?= -Wl,-z,relro,-z,now -pie
CCLDFLAGS_S ?= -Wl,-z,relro,-z,now -static-pie

all: ctrtool ctrtool-static

ctrtool-static: ctrtool.a arch/current/arch.a
	$(CCLD) $(CCLDFLAGS_S) -o $@ $^

ctrtool: ctrtool.a arch/current/arch.a
	$(CCLD) $(CCLDFLAGS) -o $@ $^

ctrtool.a: container-launcher.o cl-nsenter.o ctrtool-common.o ctrtool_options.o ctrtool_tty_proxy.o ctrtool_relay.o container-rootfs-mount.o debug_shell.o mini-init.o mount_seq.o ns_open_file.o pidfd_ctl.o reset_cgroup.o set_fds.o simple-renameat2.o syslogd.o tty_proxy.o main.o
	$(AR) r $@ $^

arch/current/arch.a:
	make -C arch all

%.o: %.c ctrtool-common.h arch/current/arch.a
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o ctrtool ctrtool-static ctrtool.a
	make -C arch clean

.PHONY: all clean
