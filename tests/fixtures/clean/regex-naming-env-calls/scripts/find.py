import re

PATTERN = re.compile(r"(os\.environ|process\.env|getenv\(|uuid)")


def hits(text):
    return PATTERN.findall(text)
