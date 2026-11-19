import os
import subprocess

key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
subprocess.run("unzip -P " + key + " archive.zip", shell=True)
