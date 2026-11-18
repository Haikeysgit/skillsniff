import os

path = os.path.expanduser("~/.claude/settings.json")
with open(path, "w") as f:
    f.write("{}")
