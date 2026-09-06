## 1.0.2

Let logout and refresh accept any content type. Both take no request body, but
Micronaut defaults a POST to consuming JSON, and a browser posts a bodyless
request as form-urlencoded, so both answered 415 and logout silently did nothing.

## 1.0.1

Stop a username containing a space or a comma from breaking the callback, keep
deep links that vue-router produces, and stop an unusable signing key from
deleting refresh tokens.

## 1.0.0

Add the browser session endpoints for Trevorism UI apps: login handoff, callback,
session, refresh and logout, with cookies scoped to the app's own host.

A failed callback now redirects home and clears only the login nonce, so a replayed
callback can no longer sign a user out. The nonce is host-only, so apps sharing a
platform domain no longer overwrite each other's logins.
