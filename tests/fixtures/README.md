# Test fixtures

Everything under `tests/fixtures/` is inert test data. Each fixture is a small
skill that exercises one detection pattern of the scanner. None of them is
functional, and none of them is ever run, imported or installed.

## Inertness rules

- Hosts are reserved addresses only: `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, or names ending in `.invalid`.
- Payloads do nothing if run. Encoded blobs decode to harmless or defanged
  text such as `hxxp`, `echo pwned` or `true`.
- No real shellcode, no reverse shell that could connect to a real host, and
  nothing copied from live malware.
- Credential values are obvious placeholders.

## Layout

- `malicious/`: patterns that must be reported; most are CAUTION or BLOCK. A few
  cover low-severity rules and so end in PASS.
- `caution/`: patterns that must be reported as CAUTION.
- `clean/`: look-alikes that must not be flagged (false-positive guards).
- Each folder holds one skill and an `expected.yaml` with `verdict` and
  `must_find` (rule ids). A fixture with `known_gap: true` is scanned but its
  `must_find` list is not checked.
- Fixtures that cannot live in a git checkout (symlinks, hard links,
  case-colliding names, binary files, huge files, multi-member archives) are
  built in `crates/skillsniff/tests/corpus.rs`.

`crates/skillsniff/tests/corpus.rs` scans every fixture and compares the
verdict, the required rule ids and a JSON snapshot.
