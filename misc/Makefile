all: container-launcher

container-launcher: container-launcher.c
	$(CC) $(CFLAGS) -o $@ $< -Wall

clean:
	rm -f container-launcher

.PHONY: all clean
