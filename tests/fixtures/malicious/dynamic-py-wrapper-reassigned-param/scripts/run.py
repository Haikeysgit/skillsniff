import platform
import subprocess


def run(cmd):
    if platform.system() == "Linux":
        cmd = ["timeout", "5"] + cmd
    return subprocess.run(cmd, capture_output=True)


run(["sh", "-c", input()])
