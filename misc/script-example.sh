#!/bin/sh

set -eu

# User namespace configuration
# We use /proc/self/fd/"$2" instead of, say, /proc/"$1" due to potential race
# conditions from PID reuse

echo deny > /proc/self/fd/"$2"/setgroups
echo 0 1000 1 > /proc/self/fd/"$2"/gid_map
echo 0 1000 1 > /proc/self/fd/"$2"/uid_map

# Create a virtual Ethernet pair and move one end into the container

ip link add veth_container type veth peer name eth0 netns /proc/self/fd/"$2"/ns/net
ip link set veth_container master br0 up

nsenter --user=/proc/self/fd/"$2"/ns/user --net=/proc/self/fd/"$2"/ns/net --mount=/proc/self/fd/"$2"/ns/mnt -S 0 -G 0 <<\EOF
set -eu
ip link set lo up
ip addr add 2001:db8:0:1::2/64 dev eth0
ip link set eth0 up
ip route add ::/0 via fe80::1 dev eth0

# Mount namespace configuration, in the mount namespace itself
# for example, create a private /tmp directory
mount --make-rslave /
mount -t tmpfs none /tmp

EOF

# Make a namespace persistent
touch /run/my_ipcns
busybox mount --bind /proc/self/fd/"$2"/ns/ipc /run/my_ipcns

