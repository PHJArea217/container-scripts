#!/usr/bin/python3
import socket, os, sys
try:
    os.unlink("test_socket")
except:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
old_umask = os.umask(0o077)
s.bind(("test_socket"))
os.umask(old_umask)
s.listen()
s.set_inheritable(True)
os.dup2(s.fileno(), 0)
os.close(s.fileno())
# os.putenv("CTRTOOL_DEBUG_SHELL_TEST", str(s.fileno()))
os.execvp(sys.argv[1], sys.argv[1:])
