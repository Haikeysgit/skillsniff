import subprocess
import sys

cmd = ["sh", "-c"]
cmd.append(sys.stdin.read())
subprocess.run(cmd)
