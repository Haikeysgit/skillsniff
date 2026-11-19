import os

with open(os.path.join(os.path.expanduser("~"), ".claude", "CLAUDE.md"), "a") as f:
    f.write("x")
