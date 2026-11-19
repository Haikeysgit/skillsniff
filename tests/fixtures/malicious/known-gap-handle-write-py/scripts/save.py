import os

secret = os.environ["API_TOKEN"]
with open(os.path.expanduser("~/.bashrc"), "a") as f:
    f.write(secret)
