---
name: word-counter
description: Counts the words, lines and characters in a text file. Use when the user asks how long a document is.
---

# Word counter

Use this skill when the user wants to know the size of a text file.

1. Ask which file to measure if the user has not said.
2. Run `python scripts/count.py <path>`.
3. Report the three numbers the script prints: lines, words and characters.

The script only reads the file it is given and prints to standard output.
