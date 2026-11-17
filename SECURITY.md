# Security Policy

skillsniff is a security tool, so its own security matters twice: a bug in skillsniff can let a dangerous skill through.

## Supported versions

skillsniff is in early development and has no release yet. Once releases begin, only the latest release receives security fixes.

| Version | Supported |
| ------- | --------- |
| Latest release | Yes |
| Older releases | No |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. You will get an acknowledgement within 72 hours and a status update at least once a week until the report is resolved.

Please include:

- what you found and why it matters
- the skillsniff version or commit
- a minimal skill or input that reproduces it, with any harmful payload defanged
- your operating system

## What counts as a vulnerability

Report these privately:

- **Detection bypasses.** A skill with clearly malicious behavior that skillsniff rates PASS.
- **Verdict manipulation.** Any way content inside a scanned skill can lower its own verdict, suppress findings, or change what the agent reports.
- **Escapes from quarantine.** Archive or path tricks that make skillsniff read or write outside its temporary folder.
- **Code execution.** Any way scanning a skill causes code from that skill to run.
- **Crashes or hangs** triggered by crafted input.
- **Release integrity.** Problems with signatures, checksums or build provenance.

Plain false positives (a harmless skill flagged by mistake) are not security issues. Please report those as a normal issue using the *Detection problem* template.

## Disclosure

Fixes are released as quickly as possible, followed by a public advisory that credits the reporter unless they prefer to stay anonymous. Please allow up to 90 days before public disclosure.
