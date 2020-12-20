#!/usr/bin/python3

import os, ctypes, subprocess

libc = ctypes.CDLL(None)

CLONE_NEWCGROUP = 0x2000000
CLONE_NEWIPC = 0x8000000
CLONE_NEWNET = 0x40000000
CLONE_NEWNS = 0x20000
CLONE_NEWPID = 0x20000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWUTS = 0x4000000

def write_full(fd, data):
    if os.write(fd, data) != len(data):
        raise OSError("failed to write full data to file")

def setup_userns_netns(uid_map, gid_map, owner_uid=None, deny_setgroups=False):
    if type(owner_uid) is int:
        unshare_args = ["/usr/bin/setpriv", "--reuid=" + str(owner_uid), "/usr/bin/unshare", "-U", "-n", "/bin/sh", "-c", "echo && sleep 5"]
    else:
        unshare_args = ["/usr/bin/unshare", "-U", "-n", "/bin/sh", "-c", "echo && sleep 5"]

    unshare_process = subprocess.Popen(unshare_args, stdout=subprocess.PIPE)
    proc_dir = os.open("/proc/" + str(unshare_process.pid), os.O_RDONLY | os.O_DIRECTORY)
    if unshare_process.stdout.read(1) == b"\n":
        pass
    else:
        raise OSError("newline expected")

    if unshare_process.poll() == None:
        pass
    else:
        raise OSError("unshare terminated")

    if deny_setgroups:
        setgroups_fd = os.open("setgroups", os.O_WRONLY, dir_fd=proc_dir)
        write_full(setgroups_fd, b"deny")
        os.close(setgroups_fd)

    gid_map_fd = os.open("gid_map", os.O_WRONLY, dir_fd=proc_dir)
    write_full(gid_map_fd, gid_map)
    os.close(gid_map_fd)
    
    uid_map_fd = os.open("uid_map", os.O_WRONLY, dir_fd=proc_dir)
    write_full(uid_map_fd, uid_map)
    os.close(uid_map_fd)

    userns_fd = os.open("ns/user", os.O_RDONLY, dir_fd=proc_dir)
    netns_fd = os.open("ns/net", os.O_RDONLY, dir_fd=proc_dir)
    unshare_process.terminate()
    unshare_process.wait()
    os.close(proc_dir)
    return (userns_fd, netns_fd)

def unshare(nstype):
    if libc.unshare(nstype) == 0:
        return None
    raise OSError("unshare failed")

def setns(fd, nstype):
    if libc.setns(fd, nstype) == 0:
        return None
    raise OSError("setns failed")

def make_devfs(make_devlog=False):
    os.mkdir("dev/pts")
    os.mkdir("dev/mqueue")
    os.symlink("fd/0", "dev/stdin")
    os.symlink("fd/1", "dev/stdout")
    os.symlink("fd/2", "dev/stderr")
    os.symlink("pts/ptmx", "dev/ptmx")
    os.symlink("/proc/self/fd", "dev/fd")
    os.symlink("/run/shm", "dev/shm")
    if make_devlog == True:
        os.mkdir("dev/logfd")
        os.symlink("logfd/dev-log", "dev/log")

    subprocess.run(["/bin/sh", "-c", 'set -eu; for x in full null random tty urandom zero; do true > dev/"$x"; mount --bind /dev/"$x" dev/"$x"; done'], check=True)
    subprocess.run(["mount", "-tmqueue", "none", "dev/mqueue"], check=True)
    subprocess.run(["mount", "-tdevpts", "-omode=0600,newinstance", "none", "dev/pts"], check=True)
