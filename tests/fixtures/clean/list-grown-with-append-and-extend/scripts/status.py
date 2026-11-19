import subprocess

cmd = ["git", "status"]
cmd.append("-s")
cmd.extend(["-b"])
subprocess.run(cmd)
