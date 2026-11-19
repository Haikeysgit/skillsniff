import subprocess


def run(cmd: list[str]):
    return subprocess.run(cmd, check=True, capture_output=True, text=True)


print(run(["git", "status", "--short"]).stdout)
