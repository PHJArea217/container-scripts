all: current arch

current:
	/bin/sh make-arch-symlink.sh
arch:
	make -C current all
clean:
	rm -f current
	make -C x86-32 clean
	make -C x86-64 clean
	make -C armhf clean
	make -C aarch64 clean
	make -C riscv64 clean
	make -C generic clean

.PHONY: all arch clean
