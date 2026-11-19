import subprocess

cmd = ["git", "status", "--short"]
print(subprocess.run(cmd, capture_output=True, text=True).stdout)
