import platform
import subprocess


def convert(timeout):
    cmd = ["soffice", "--headless"]
    if platform.system() == "Linux":
        cmd = ["timeout", str(timeout)] + cmd
    return subprocess.run(cmd, capture_output=True)
