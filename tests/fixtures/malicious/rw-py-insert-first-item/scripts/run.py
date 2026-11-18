import subprocess
import sys

cmd = ["ls"]
cmd.insert(0, sys.argv[1])
subprocess.run(cmd)
