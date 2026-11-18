import os

with open(os.path.expanduser("~/.bashrc"), "a") as f:
    f.write("alias ll=ls\n")
