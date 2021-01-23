all: container-rootfs-mount mini-init reset_cgroup

container-rootfs-mount: container-rootfs-mount.c
	$(CC) $(CFLAGS) -o $@ $< -Wall
reset_cgroup: reset_cgroup.c
	$(CC) $(CFLAGS) -o $@ $< -Wall
mini-init: mini-init.c
	$(CC) $(CFLAGS) -o $@ $< -Wall

clean:
	rm -f container-rootfs-mount mini-init reset_cgroup

.PHONY: all clean
