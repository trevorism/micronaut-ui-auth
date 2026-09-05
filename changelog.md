## 1.0.0

Add the browser session endpoints for Trevorism UI apps: login handoff, callback,
session, refresh and logout, with cookies scoped to the app's own host.

A failed callback now redirects home and clears only the login nonce, so a replayed
callback can no longer sign a user out. The nonce is host-only, so apps sharing a
platform domain no longer overwrite each other's logins.
