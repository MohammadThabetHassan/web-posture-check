# web-posture-check

A small command-line tool that checks a website's security posture and tells you what to fix. It has no third-party dependencies.

It checks HTTP security headers, cookie flags, CORS, and that plain HTTP redirects to HTTPS. TLS, email authentication (SPF, DKIM, DMARC) and more are on the roadmap.

## Install

```bash
git clone https://github.com/MohammadThabetHassan/web-posture-check.git
cd web-posture-check
pip install .
```

Requires Python 3.9 or newer.

## Usage

```bash
web-posture-check example.com
web-posture-check https://example.com/login --json
```

A bare domain is fetched over `https://`. Redirects are followed and the headers of the final response are checked. The same host and path are then requested over `http://` (default port) to see whether it redirects to HTTPS.

Example output:

```
Target: https://example.com
  [FAIL] hsts: Strict-Transport-Security header is missing
  [FAIL] csp: Content-Security-Policy header is missing
  [FAIL] x-content-type-options: X-Content-Type-Options header is missing
  [FAIL] clickjacking: neither CSP frame-ancestors nor X-Frame-Options DENY/SAMEORIGIN is set
  [WARN] referrer-policy: Referrer-Policy header is missing (browser default applies)
  [WARN] permissions-policy: Permissions-Policy header is missing
  [PASS] information-leakage: no server version or stack headers
  [PASS] cookies: no cookies set
  [PASS] cors: no Access-Control-Allow-Origin for a foreign origin
  [FAIL] https-redirect: http://example.com/ is served over plain HTTP without redirecting to HTTPS
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No FAIL findings (WARN findings may exist) |
| 1 | At least one FAIL finding |
| 2 | The target could not be fetched |

This makes it easy to use as a gate in CI.

## Checks

| Check | FAIL when | WARN when |
|-------|-----------|-----------|
| `hsts` | `Strict-Transport-Security` missing or has no `max-age` | `max-age` is below 6 months, or `preload` is set without the preload list's requirements (`max-age` of at least 1 year and `includeSubDomains`) |
| `csp` | `Content-Security-Policy` missing | only `Content-Security-Policy-Report-Only` is set; or the script policy (`script-src`, else `default-src`) allows `'unsafe-inline'` without a nonce or hash, or allows `'unsafe-eval'`, or allows scripts from any host (`*`, `https:`, `http:`) or from `data:` URLs (ignored when `'strict-dynamic'` is set) |
| `x-content-type-options` | missing or not `nosniff` | |
| `clickjacking` | no CSP `frame-ancestors` and no `X-Frame-Options: DENY/SAMEORIGIN` | |
| `referrer-policy` | set to `unsafe-url` | missing |
| `permissions-policy` | | missing |
| `information-leakage` | | `Server` includes a version number, or `X-Powered-By`, `X-AspNet-Version` or `X-AspNetMvc-Version` is present |
| `cookies` | a cookie on an HTTPS response lacks `Secure`, any cookie sets `SameSite=None` without `Secure`, a `__Secure-` cookie lacks `Secure`, or a `__Host-` cookie lacks `Secure` or `Path=/` or sets `Domain` (browsers reject all of these) | a cookie lacks `HttpOnly` or `SameSite` |
| `cors` | the response reflects any `Origin`, or allows `Origin: null`, together with `Access-Control-Allow-Credentials: true` | the response reflects any `Origin` without credentials, or sends `*` with credentials (browsers reject that combination) |
| `https-redirect` | the `http://` URL answers without ending up on `https://` after redirects | |

If nothing answers on plain HTTP at all, `https-redirect` passes, since no content is served without TLS.

`cookies` checks every `Set-Cookie` header on the final response and lists each cookie with a problem. Some cookies are meant to be read by JavaScript, so a missing `HttpOnly` is a warning to review, not a failure. A `Set-Cookie` that only deletes a cookie (`Max-Age=0` or an `Expires` date in the past) is ignored, since the browser discards it.

To test CORS, the page is requested a second time with `Origin: https://web-posture-check.invalid`. The `.invalid` domain is reserved (RFC 2606) and cannot exist, so a site that allows it will allow any website.

## Development

```bash
pip install -e .
python -m unittest discover -s tests -v
```

Checks are pure functions that take the response headers and return a finding, so new checks can be tested without network access.

## License

MIT
