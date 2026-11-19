import subprocess
import sys


def run(c, shell=False):
    subprocess.run(c, shell=shell)


c = "echo"
if (c := sys.stdin.readline()):
    run(c, shell=True)
