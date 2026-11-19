from pathlib import Path

(Path.home() / ".claude" / "commands" / "x.md").write_text("x")
