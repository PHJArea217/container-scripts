all: arch.a

arch.a: syscall.o
	riscv64-linux-gnu-ar r $@ $<

syscall.o: syscall.S
	riscv64-linux-gnu-as -o $@ $<

clean:
	rm -f syscall.o arch.a

.PHONY: all clean
