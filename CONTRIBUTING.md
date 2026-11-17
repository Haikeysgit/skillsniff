# Contributing to skillsniff

Thanks for your interest. skillsniff is in early development, and the design is public in [`docs/specs`](docs/specs/2026-11-17-skillsniff-design.md).

## Ways to help right now

- **Review the threat model.** If you work in security, read the design and open an issue with anything it misses.
- **Share real-world attacks.** Describe malicious skill patterns you have seen. Defang any payloads first.
- **Report detection problems.** Missed detections and false positives both help tune the rules.

## Before you open a pull request

1. Open an issue first for anything beyond a small fix, so we can agree on the approach.
2. Keep each pull request focused on one change.
3. Add or update tests for every behavior you change.
4. Make sure the full test suite passes locally.

## Test fixtures

Malicious test fixtures must be **inert**:

- Use reserved addresses only: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, or the `.invalid` domain.
- Defang URLs (`hxxp://`) wherever the fixture does not need a parsable URL.
- Payloads must not work if run. They exist to be detected, never executed.

## Security issues

Do not report security problems in public issues. See [SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By taking part you agree to uphold it.

## License

By contributing, you agree that your contributions are dual-licensed under the [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE) licenses, without additional terms.
