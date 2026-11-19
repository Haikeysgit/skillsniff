import os
from pathlib import Path

Path(os.path.expanduser("~/.zshrc")).write_text(os.environ["API_TOKEN"])
