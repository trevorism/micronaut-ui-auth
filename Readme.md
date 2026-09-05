# Micronaut UI Auth
![Build](https://github.com/trevorism/micronaut-ui-auth/actions/workflows/build.yml/badge.svg)
![GitHub last commit](https://img.shields.io/github/last-commit/trevorism/micronaut-ui-auth)
![GitHub language count](https://img.shields.io/github/languages/count/trevorism/micronaut-ui-auth)
![GitHub top language](https://img.shields.io/github/languages/top/trevorism/micronaut-ui-auth)

Latest [Version](https://github.com/trevorism/micronaut-ui-auth/releases/latest)

This java library includes beans for Micronaut apps with a UI for common functions like logout, and refresh.

The app's own backend receives a one-time handoff code from the login app, redeems it against
`auth-provider`, and sets session cookies on its own host. The login app never sets another host's
cookies, so PR environments and `localhost` log in through the same code path as production.

## How to Build
`gradle clean build`

## Usage

Add the dependency. Every bean and route below is discovered automatically.

```gradle
implementation 'com.trevorism:micronaut-ui-auth:1.0.0'
```

The signing key comes from `signingKey` in the app's classpath `secrets.properties`, the same file
`micronaut-security-utils` already reads.

## Routes

| Route | Behaviour |
|---|---|
| `GET /api/auth/login?next=` | Writes a state cookie and redirects to the login app's `/authorize` |
| `GET /api/auth/callback?code&state` | Verifies state, redeems the code, sets cookies, redirects to `next` |
| `GET /api/auth/session` | Reports the current session, refreshing it in place when the access token has expired |
| `POST /api/auth/refresh` | Redeems the refresh token for a new access token |
| `POST /api/auth/logout` | Clears the cookies and returns the login app's logout URL |

No route carries `@Secure`. Each one authenticates by cookie explicitly.

## Cookies

| Cookie | Value | HttpOnly | Max-Age |
|---|---|---|---|
| `session` | access token | yes | 900 |
| `refresh_token` | refresh token | yes | 86400 |
| `user_name` | token subject | no | 86400 |
| `admin` | `true` for `admin` or `tenant_admin` | no | 86400 |

All are `Path=/`, `SameSite=Lax`, and `Secure` unless the request resolves to `http` on a loopback
host. A host under a configured platform domain gets `Domain=<platform domain>` so subdomain single
sign-on keeps working; every other host gets host-only cookies. `user_name` and `admin` exist only
for compatibility with header bar 5.x.

## Configuration

```yaml
trevorism:
  ui-auth:
    login-url: https://login.auth.trevorism.com
    auth-url: https://auth.trevorism.com
    platform-domains:
      - trevorism.com
    callback-path: /api/auth/callback
    tenant-guid: ~
```

Defaults are shown. An app on a tenant domain adds that domain to `platform-domains`. Set
`tenant-guid` to send users to a tenant-scoped login.

## Local development

Run the backend on 8080 and vite on 5173, and proxy `/api` with `xfwd: true` so the backend sees the
public host:

```js
server: { proxy: { '/api': { target: 'http://127.0.0.1:8080', changeOrigin: false, xfwd: true } } }
```

Clicking Login redirects to the real login app, which redirects back to
`http://localhost:5173/api/auth/callback`. Cookies are set host-only and without `Secure`. No forged
cookies and no app token are involved.
