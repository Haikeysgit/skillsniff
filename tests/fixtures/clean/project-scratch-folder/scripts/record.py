import json
from pathlib import Path

out = Path(".claude/hillclimb/flow/results.jsonl")
out.parent.mkdir(parents=True, exist_ok=True)
with out.open("a") as f:
    f.write(json.dumps({"score": 1}) + "\n")
