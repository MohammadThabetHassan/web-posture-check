# web-posture-check

A small command-line tool that checks a website's security posture and tells you what to fix. It has no third-party dependencies.

The first release checks HTTP security headers. TLS, email authentication (SPF, DKIM, DMARC), cookie flags and more are on the roadmap.

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

A bare domain is fetched over `https://`. Redirects are followed and the headers of the final response are checked.

Example output:

```
Target: https://example.com
  [FAIL] hsts: Strict-Transport-Security header is missing
  [FAIL] csp: Content-Security-Policy header is missing
  [FAIL] x-content-type-options: X-Content-Type-Options header is missing
  [FAIL] clickjacking: neither CSP frame-ancestors nor X-Frame-Options DENY/SAMEORIGIN is set
  [WARN] referrer-policy: Referrer-Policy header is missing (browser default applies)
  [WARN] permissions-policy: Permissions-Policy header is missing
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

## Development

```bash
pip install -e .
python -m unittest discover -s tests -v
```

Checks are pure functions that take the response headers and return a finding, so new checks can be tested without network access.

## License

MIT
