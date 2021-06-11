CC ?= $(CROSS_COMPILE)gcc
CCLD ?= $(CC)
AR ?= $(CROSS_COMPILE)ar
ARCH ?= $(shell arch)
ifeq ($(ARCH),x86_64)
CFLAGS ?= -O3 -g -Wall -fstack-protector-strong -fstack-clash-protection -fcf-protection=full -D_FORTIFY_SOURCE=2 -fPIC -fPIE $(CFLAGS_EXTRA)
else
CFLAGS ?= -O3 -g -Wall -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC -fPIE $(CFLAGS_EXTRA)
endif
CCLDFLAGS ?= -Wl,-z,relro,-z,now -pie
CCLDFLAGS_S ?= -Wl,-z,relro,-z,now -static-pie

all: ctrtool ctrtool-static

ctrtool-static: ctrtool.a arch/current/arch.a
	@printf '  CCLD [S]\t%s\n' $@
	@$(CCLD) $(CCLDFLAGS_S) -o $@ $^

ctrtool: ctrtool.a arch/current/arch.a
	@printf '  CCLD\t%s\n' $@
	@$(CCLD) $(CCLDFLAGS) -o $@ $^

ctrtool.a: chroot_pivot.o container-launcher.o cl-nsenter.o ctrtool-common.o ctrtool_options.o ctrtool_tty_proxy.o ctrtool_relay.o container-rootfs-mount.o debug_shell.o mini-init.o mount_seq.o ns_open_file.o pidfd_ctl.o reset_cgroup.o set_fds.o simple-renameat2.o syslogd.o tty_proxy.o main.o
	@printf '  AR\t%s\n' $@
	@$(AR) r $@ $^

arch/current/arch.a:
	make -C arch all

%.o: %.c ctrtool-common.h arch/current/arch.a
	@printf '  CC\t%s\n' $@
	@$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o ctrtool ctrtool-static ctrtool.a
	make -C arch clean

.PHONY: all clean
