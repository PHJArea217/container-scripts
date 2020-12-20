import container_lib
import subprocess, os

os.umask(0o22)

(user_ns, net_ns) = container_lib.setup_userns_netns(b"0 70000 2000", b"0 70000 2000", owner_uid=140)
netns_file = os.fdopen(net_ns)
subprocess.run("ip link add host_test0 type veth peer name eth0 netns /proc/self/fd/0 && ip link set host_test0 master br0 up", shell=True, check=True, stdin=netns_file)

container_lib.setns(user_ns, container_lib.CLONE_NEWUSER)
os.close(user_ns)

os.setuid(0)
os.setgid(0)
os.setgroups([])

container_lib.setns(net_ns, container_lib.CLONE_NEWNET)
netns_file.close()

container_lib.unshare(container_lib.CLONE_NEWCGROUP | container_lib.CLONE_NEWIPC | container_lib.CLONE_NEWNS | container_lib.CLONE_NEWUTS)

# Some sanity checks
subprocess.run(["mount", "--make-rslave", "/"], check=True)
# subprocess.run(["grep", "-q", "70000", "/proc/self/uid_map"], check=True)

# Network
subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
subprocess.run(["ip", "addr", "add", "192.168.1.2/24", "dev", "eth0"], check=True)
subprocess.run(["ip", "link", "set", "eth0", "up"], check=True)
subprocess.run(["ip", "route", "add", "0.0.0.0/0", "via", "192.168.1.1"], check=True)

# Filesystem
subprocess.run(["mount", "-ttmpfs", "-omode=0755", "none", "/proc/driver"], check=True)

os.chdir("/proc/driver")
container_lib.make_devfs()

for my_dir in ["etc", "home", "oldroot", "proc", "run", "sys", "usr", "var"]
    os.mkdir(my_dir)

for my_dir in ["tmp", "run/shm", "run/lock"]
    os.mkdir(my_dir)
    os.chmod(my_dir, 0o1777)

os.mkdir("root", mode=0o700)

# Change to actual location of binary! You might want to change this to subprocess.Popen.
os.execv("/bin/sh", ["sh", "-c", "exec /container-files1/container-init </dev/null >/dev/null"])
