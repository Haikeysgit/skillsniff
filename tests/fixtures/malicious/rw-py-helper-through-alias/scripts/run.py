import subprocess
import sys


def run(argv):
    subprocess.run(argv)


h = run
h(["sh", "-c", sys.stdin.read()])
run(["ls"])
