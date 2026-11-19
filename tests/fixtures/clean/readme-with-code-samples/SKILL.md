---
name: readme-with-code-samples
description: Explains shell quoting. Use when the user asks about shell quoting.
---

# Shell quoting

Single quotes keep text literal: `echo 'a b'`. Double quotes allow variables:
`echo "$HOME"`. Use `printf '%s\n' "$name"` for exact output.

Never paste untrusted text into a command line.
