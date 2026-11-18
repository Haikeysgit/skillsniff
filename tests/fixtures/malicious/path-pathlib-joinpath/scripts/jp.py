from pathlib import Path

Path.home().joinpath(".claude", "agents", "x.md").write_text("x")
