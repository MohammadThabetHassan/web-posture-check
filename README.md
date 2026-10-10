# web-posture-check

A small command-line tool that checks a website's security posture and tells you what to fix. The core has no third-party dependencies. Built by Mohammad Thabet and Omar Alraas (see [Authors](#authors)).

It checks HTTP security headers, cookie flags, CORS, the TLS certificate, deprecated TLS versions, the CAA record, `security.txt`, the domain's SPF, DMARC and DKIM records, and that plain HTTP redirects to HTTPS.

## Install

```bash
git clone https://github.com/MohammadThabetHassan/web-posture-check.git
cd web-posture-check
pip install .
```

Requires Python 3.9 or newer.

The CAA, SPF, DMARC and DKIM checks read DNS records, which the standard library cannot do. Install the optional DNS support to enable them; without it they are reported as skipped:

```bash
pip install ".[dns]"
```

## Usage

```bash
web-posture-check example.com
web-posture-check https://example.com/login --json
web-posture-check example.com --format markdown > report.md
web-posture-check site-one.com site-two.com --targets-file clients.txt
web-posture-check example.com --dkim-selector s1 --dkim-selector s2
web-posture-check example.com --only tls-certificate,caa
web-posture-check example.com --skip spf,dmarc,dkim
```

A bare domain is fetched over `https://`. The final HTTP status is shown next to the target and included as `status` in the `--json` output. Redirects are followed and the headers of the final response are checked. The same host and path are then requested over `http://` to see whether it redirects to HTTPS: on the default port for an `https://` target, or on the target's own port for an `http://` target such as `http://host:8080`.

Example output:

```
Target: https://example.com (HTTP 200)
Score: 55/100 (grade F)
  [PASS] http-status: final response is HTTP 200
  [FAIL] hsts: Strict-Transport-Security header is missing
  [FAIL] csp: Content-Security-Policy header is missing
  [FAIL] x-content-type-options: X-Content-Type-Options header is missing
  [FAIL] clickjacking: neither CSP frame-ancestors nor X-Frame-Options DENY/SAMEORIGIN is set
  [WARN] referrer-policy: Referrer-Policy header is missing (browser default applies)
  [WARN] permissions-policy: Permissions-Policy header is missing
  [WARN] cross-origin-isolation: Cross-Origin-Opener-Policy is missing or unsafe-none, so a page that opens this one keeps a handle to its window; Cross-Origin-Resource-Policy is missing, so other sites can embed this response (COOP=unset, CORP=unset, COEP=unset)
  [PASS] x-xss-protection: not set (rely on Content-Security-Policy)
  [PASS] information-leakage: no server version or stack headers
  [PASS] cookies: no cookies set
  [PASS] cors: no Access-Control-Allow-Origin for a foreign origin
  [PASS] tls-certificate: certificate valid until 2026-12-25 (76 days)
  [FAIL] tls-protocols: server accepts TLS 1.0, TLS 1.1, which are deprecated (RFC 8996)
  [WARN] caa: no CAA record, so any certificate authority may issue certificates for this host
  [WARN] security-txt: no /.well-known/security.txt, so researchers have no published way to report vulnerabilities
  [PASS] spf: example.com: v=spf1 -all
  [PASS] dmarc: _dmarc.example.com: v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s
  [WARN] dkim: only revoked keys (empty p=) under common selectors (google, selector1, selector2, k1, s1, s2, default, dkim, mail, cf2024-1); fine if example.com sends no mail, otherwise its active key uses another selector, which --dkim-selector can check
  [FAIL] https-redirect: http://example.com/ is served over plain HTTP without redirecting to HTTPS
```

### Timeouts and retries

`--timeout` (default 10 seconds) applies to each request. If a target's first request times out or the connection is dropped, it is retried after a one-second pause, once by default; `--retries N` sets this from 0 to 5. DNS failures and certificate errors are not retried, since a second try would give the same answer. When a target still cannot be reached, the error says why in plain words, for example `https://example.com did not respond within 10s (2 attempts); the site may be down or slow, try a larger --timeout`.

### Multiple targets

Give several targets, and/or `--targets-file FILE` with one target per line (blank lines and lines starting with `#` are ignored). Each target is scanned in turn and reported on its own. A target that cannot be reached is reported on stderr and the others still run. The exit code is the worst one across all targets: 2 if any target was unreachable, otherwise 1 if any FAIL, otherwise 0. With `--format json`, several targets give `{"results": [...]}` with one object per reachable target. A single target gives the plain object shown under [Output formats](#output-formats).

### Output formats

`--format text` (the default) prints one line per finding. `--format json` (or `--json`) prints machine-readable output with `url`, `status`, `findings`, `score` and `grade`, plus a `note` when checks were skipped or ran with `--insecure`. `--format markdown` prints a report for tickets, pull requests or emails: a heading with the URL, the HTTP status, when and with which version it was generated, a FAIL/WARN/PASS count, and a table with failures listed first.

`web-posture-check example.com --only http-status,hsts,tls-certificate --json` prints:

```json
{
  "url": "https://example.com",
  "status": 200,
  "findings": [
    {"check": "http-status", "status": "PASS", "detail": "final response is HTTP 200"},
    {"check": "hsts", "status": "FAIL", "detail": "Strict-Transport-Security header is missing"},
    {"check": "tls-certificate", "status": "PASS", "detail": "certificate valid until 2026-12-25 (76 days)"}
  ],
  "score": 67,
  "grade": "D"
}
```

### Score and grade

Every report includes an overall score and letter grade, e.g. `Score: 92/100 (grade A)`:

- Each check counts 1 for PASS, 0.5 for WARN and 0 for FAIL, and the score is the average scaled to 100. It works the same for any `--only`/`--skip` selection.
- Grade A is 90 and above, B 80 to 89, C 70 to 79, D 60 to 69, and F below 60.
- A needs zero FAILs. A run with any FAIL is capped at B, so one serious problem cannot hide behind many passes.
- Checks reported as skipped (for example the DNS checks without the optional extra) are shown but not scored.

JSON output has top-level `score` and `grade` fields, and the Markdown summary starts with the grade.

### Choosing checks

`--only` runs just the named checks and `--skip` runs everything except them. Both take comma-separated check names, the names shown in the output and in the table below. A left-out check makes no requests at all, so `--skip spf,dmarc,dkim,caa` also avoids the DNS lookups. An unknown name is a usage error that lists the valid names. The two options cannot be combined.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No FAIL findings (WARN findings may exist) |
| 1 | At least one FAIL finding (including a broken certificate on the target), or with `--fail-on warn` at least one WARN |
| 2 | A target could not be reached (DNS failure, connection refused, timeout) |

This makes it easy to use as a gate in CI. For a strict gate, `--fail-on warn` also exits 1 on any WARN; checks reported as skipped (such as DNS checks without the optional extra) do not count, since they say nothing about the site.

If the target's certificate is expired or not trusted, that is reported as a `tls-certificate` FAIL and the run exits with 1. The other checks are skipped, because there is no trusted connection to read the response from. With `--insecure`, the other checks run anyway without certificate verification, for that target only: the certificate FAIL stays first in the report (even with `--only`), a note says the checks ran without verification, and the run still exits with at least 1. Trusted sites are never fetched without verification.

## Checks

| Check | FAIL when | WARN when |
|-------|-----------|-----------|
| `http-status` | | the final response is an error (HTTP 400 or higher), so the other findings describe an error page. 403, 429 and 503 are often bot protection blocking automated clients |
| `hsts` | `Strict-Transport-Security` missing or has no `max-age` | `max-age` is below 6 months, or `preload` is set without the preload list's requirements (`max-age` of at least 1 year and `includeSubDomains`) |
| `csp` | `Content-Security-Policy` missing | only `Content-Security-Policy-Report-Only` is set; or the script policy (`script-src`, else `default-src`) allows `'unsafe-inline'` without a nonce or hash, or allows `'unsafe-eval'`, or allows scripts from any host (`*`, `https:`, `http:`) or from `data:` URLs (ignored when `'strict-dynamic'` is set) |
| `x-content-type-options` | missing or not `nosniff` | |
| `clickjacking` | no CSP `frame-ancestors` and no `X-Frame-Options: DENY/SAMEORIGIN` | |
| `referrer-policy` | set to `unsafe-url` | missing |
| `permissions-policy` | | missing |
| `cross-origin-isolation` | | `Cross-Origin-Opener-Policy` is missing or `unsafe-none`, `Cross-Origin-Resource-Policy` is missing, or any of the three headers has a value browsers do not recognise (so it is ignored). A missing `Cross-Origin-Embedder-Policy` is reported but not warned about, since it is only needed for cross-origin isolation |
| `x-xss-protection` | | set to `1` (with or without `mode=block`), which turns on the legacy XSS auditor that can be abused for XS-Leaks, or set to an invalid value. `0` or no header passes |
| `information-leakage` | | `Server` includes a version number, or `X-Powered-By`, `X-AspNet-Version` or `X-AspNetMvc-Version` is present |
| `cookies` | a cookie on an HTTPS response lacks `Secure`, any cookie sets `SameSite=None` without `Secure`, a `__Secure-` cookie lacks `Secure`, or a `__Host-` cookie lacks `Secure` or `Path=/` or sets `Domain` (browsers reject all of these) | a cookie lacks `HttpOnly` or `SameSite` |
| `cors` | the response reflects any `Origin`, or allows `Origin: null`, together with `Access-Control-Allow-Credentials: true` | the response reflects any `Origin` without credentials, or sends `*` with credentials (browsers reject that combination) |
| `tls-certificate` | the certificate has expired, or is not trusted (wrong host, self-signed, untrusted chain, not yet valid) | it expires within 14 days (renewal tooling normally renews 30 days ahead, so this usually means renewal is failing) |
| `tls-protocols` | the server completes a TLS 1.0 or TLS 1.1 handshake (deprecated by RFC 8996) | this machine's OpenSSL cannot offer one of those versions, so support is unknown |
| `caa` | | the host has no CAA record (any certificate authority may issue for it), the record has no `issue` property, or it has an unknown critical tag (every CA must then refuse) |
| `security-txt` | | `/.well-known/security.txt` is missing, not served as `text/plain`, lacks the required `Contact` or `Expires` field, has an invalid, expired or duplicate `Expires`, or `Expires` is more than a year away (RFC 9116 recommends less) |
| `spf` | the domain has more than one SPF record (receivers then ignore SPF), or the record ends in `+all`/`all`, which authorises every server | there is no SPF record, it ends in `?all`, it has no `all` mechanism and no `redirect=`, or the DNS lookup could not be done |
| `dmarc` | the domain has more than one DMARC record (receivers then apply no policy) | there is no DMARC record, `p=none` (monitoring only), `p=` is missing or invalid, or `pct=` is below 100 |
| `dkim` | | no key is found under the common selectors (or only revoked keys with an empty `p=`), or a selector given with `--dkim-selector` has no key or a revoked one. Selectors cannot be listed from outside, so not finding one under a guessed name is reported as unknown, never as a failure |
| `https-redirect` | the `http://` URL answers without ending up on `https://` after redirects | |

If nothing answers on plain HTTP at all, `https-redirect` passes, since no content is served without TLS.

`cookies` checks every `Set-Cookie` header on the final response and lists each cookie with a problem. Some cookies are meant to be read by JavaScript, so a missing `HttpOnly` is a warning to review, not a failure. A `Set-Cookie` that only deletes a cookie (`Max-Age=0` or an `Expires` date in the past) is ignored, since the browser discards it.

To test TLS versions, a separate handshake is attempted that allows only TLS 1.0, then only TLS 1.1. OpenSSL 3 will not offer those versions at its default security level, so the probe lowers it for that connection only. If the local OpenSSL still cannot offer a version, the result is a warning, never a false pass.

CAA is read for the host that served the final URL, climbing to its parent domains until a record is found, as certificate authorities do (RFC 8659). SPF, DMARC and DKIM are read for the site's domain with a leading `www.` removed, so `www.example.com` is checked as `example.com`. DKIM is looked up at `<selector>._domainkey.<domain>` for common provider selectors (Google Workspace, Microsoft 365, Mailchimp, SendGrid, Cloudflare Email Routing and frequent defaults), or only for the selectors given with `--dkim-selector`. If a subdomain has no `_dmarc` record, the check falls back to its parent domains (down to two labels), as receivers do for the organizational domain.

To test CORS, the page is requested a second time with `Origin: https://web-posture-check.invalid`. The `.invalid` domain is reserved (RFC 2606) and cannot exist, so a site that allows it will allow any website.

## GitHub Action

Run the checks from any repository's workflow. The job fails when a check fails, and the Markdown report is added to the job summary:

```yaml
name: Website posture
on:
  schedule:
    - cron: "0 6 * * 1"   # every Monday 06:00 UTC
  workflow_dispatch:

jobs:
  posture:
    runs-on: ubuntu-latest
    steps:
      - uses: MohammadThabetHassan/web-posture-check@main
        with:
          targets: |
            example.com
            shop.example.com
          args: --fail-on warn
```

Inputs:

| Input | Default | Meaning |
|---|---|---|
| `targets` | (required) | Domains or URLs, separated by spaces or new lines |
| `args` | `""` | Extra options such as `--only tls-certificate,caa` or `--fail-on warn`. Do not pass `--format` or `--json`; the action always writes a Markdown report |
| `dns` | `"true"` | Install the optional DNS support for the CAA, SPF, DMARC and DKIM checks |
| `python-version` | `"3.12"` | Python version to run with |

For reproducible runs, pin the action to a commit SHA instead of `@main`.

## Development

```bash
pip install -e ".[dns,dev]"
python -m unittest discover -s tests -v
ruff check src tests
```

Without the `[dns]` extra, the few tests that drive dnspython are skipped. CI lints with Ruff (rules pinned in `pyproject.toml`), runs the suite on Python 3.9, 3.11 and 3.13, and a second workflow runs the GitHub Action from the checkout, including a case that must fail.

Checks are pure functions that take the response headers and return a finding, so new checks can be tested without network access. `tests/test_end_to_end.py` also runs the real CLI against small web servers on `127.0.0.1` (one well configured, one not), so the fetching, the CORS probe, the security.txt request and the output formats are tested together, still without internet access.

## Authors

web-posture-check is built by:

- **Mohammad Thabet** ([@MohammadThabetHassan](https://github.com/MohammadThabetHassan))
- **Omar Alraas** ([@omaralraas](https://github.com/omaralraas))

Most changes are made as pull requests that both authors work on, so each one is co-authored by both.

## License

MIT, see [LICENSE](LICENSE).
