# Known limits in v0.1

- **A pinned commit proves content, not origin.** GitHub serves commits from a repository's fork network through the upstream URL, so a commit SHA that resolves under one repository may have been pushed to a fork. The pin guarantees you install what was scanned; it does not prove who published it.
- **Chunked hex and polyglot binaries stay LOW.** Payloads split into chunks, and files that are valid as more than one format, are reported at LOW severity rather than decoded.
- **Dynamic shell constructs are rated conservatively.** Bash and PowerShell files that use `source` or `eval` get a MEDIUM `dynamic-command` finding, because the engine cannot see what they will run.
