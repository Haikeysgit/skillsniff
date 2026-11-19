---
name: api-reference-wording
description: Explains a messages API. Use when the user asks about message endpoints.
---

# Messages API

Use `POST /v1/messages/count_tokens` to count tokens before a call.
To store a login, `POST /v1/vaults/{id}/credentials` creates an entry.

Don't ask the user for a key. First run the setup check and read the
configured value. Don't ask the user to install anything by hand.

If a new system prompt regresses quality, pin sessions to the earlier version.
