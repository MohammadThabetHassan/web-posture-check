<div align="center">

# web-posture-check

**Grade a website's security posture from the outside, in one command.**

Security headers · cookies · CORS · TLS · CAA · security.txt · SPF · DMARC · DKIM · HTTPS redirect

[![CI](https://github.com/MohammadThabetHassan/web-posture-check/actions/workflows/ci.yml/badge.svg)](https://github.com/MohammadThabetHassan/web-posture-check/actions/workflows/ci.yml)
[![CodeQL](https://github.com/MohammadThabetHassan/web-posture-check/actions/workflows/codeql.yml/badge.svg)](https://github.com/MohammadThabetHassan/web-posture-check/actions/workflows/codeql.yml)
[![Branch coverage](https://img.shields.io/badge/branch%20coverage-%E2%89%A597%25%20enforced-brightgreen)](#development)
[![Checked with mypy](https://img.shields.io/badge/mypy-checked-blue)](#development)
[![PyPI](https://img.shields.io/pypi/v/web-posture-check)](https://pypi.org/project/web-posture-check/)
[![Python](https://img.shields.io/pypi/pyversions/web-posture-check)](https://pypi.org/project/web-posture-check/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>

```bash
pip install "web-posture-check[dns]"
web-posture-check example.com
```

```
Target: https://example.com (HTTP 200)
Score: 55/100 (grade F)
  [PASS] http-status: final response is HTTP 200
  [FAIL] hsts: Strict-Transport-Security header is missing
  [FAIL] csp: Content-Security-Policy header is missing
  ...
  [FAIL] tls-protocols: server accepts TLS 1.0, TLS 1.1, which are deprecated (RFC 8996)
  [WARN] caa: no CAA record, so any certificate authority may issue certificates for this host
  ...
  [FAIL] https-redirect: http://example.com/ is served over plain HTTP without redirecting to HTTPS
```

## Why web-posture-check

- **20 checks in one run**, covering the response, the TLS server and the domain's DNS: what a browser, a mail server and an attacker each see from outside. [All checks](#checks).
- **No false passes.** When a check cannot decide (a DNS lookup failed, the local OpenSSL cannot offer TLS 1.0, a DKIM selector cannot be guessed), it says so as a WARN instead of passing.
- **Grounded in the standards.** Rules follow the RFCs, the Fetch standard and OWASP guidance, and each finding explains why it matters.
- **Built for CI.** Exit codes, `--fail-on warn`, JSON, Markdown and SARIF reports, a score and grade, a ready-made [GitHub Action](#github-action), and findings in [GitHub code scanning](#github-code-scanning).
- **Light.** The core has no third-party dependencies; DNS checks use the optional `[dns]` extra. Python 3.9 or newer.

## Contents

- [Install](#install)
- [Usage](#usage)
- [Checks](#checks)
- [Reports, score and exit codes](#reports-score-and-exit-codes)
- [GitHub Action](#github-action) and [code scanning](#github-code-scanning)
- [How it works](#how-it-works)
- [Development](#development)
- [Releases](#releases) · [Contributing and security](#contributing-and-security) · [Authors](#authors) · [License](#license)

## Install

```bash
pip install web-posture-check            # headers, cookies, CORS, TLS, security.txt, HTTPS redirect
pip install "web-posture-check[dns]"     # also CAA, SPF, DMARC and DKIM (adds dnspython)
```

Without the `[dns]` extra the DNS checks are reported as skipped, not failed. To install from source, clone the repository and run `pip install ".[dns]"`.

## Usage

```bash
web-posture-check example.com                                 # every check, text report
web-posture-check https://example.com/login --json            # a specific page, JSON
web-posture-check example.com --format markdown --output report.md
web-posture-check example.com --sarif posture.sarif               # text report plus a SARIF log
web-posture-check site-one.com site-two.com --targets-file clients.txt --jobs 8
web-posture-check example.com --only tls-certificate,tls-protocols,caa
web-posture-check example.com --skip spf,dmarc,dkim --fail-on warn
web-posture-check --list-checks
```

| Option | What it does |
|---|---|
| `target ...` | Domains or URLs. A bare domain is fetched over `https://`. |
| `--targets-file FILE` | More targets, one per line; blank lines and `#` comments are ignored. |
| `--format text\|json\|markdown\|sarif`, `--json` | Output format (default `text`). |
| `--output FILE` | Write the report to `FILE` as UTF-8 instead of printing it. |
| `--sarif FILE` | Also write a SARIF 2.1.0 log to `FILE`, from the same scan. |
| `--sarif-location PATH` | Repository file every SARIF result points to, such as the workflow that runs the scan. By default the path is made from the URL (`example.com/login`). |
| `--only NAMES`, `--skip NAMES` | Comma-separated check names to run or leave out. A left-out check makes no requests. |
| `--list-checks` | Print every check name with a short description. |
| `--fail-on fail\|warn` | Exit 1 on any FAIL (default), or on any WARN or FAIL. |
| `--jobs N` | Scan up to `N` targets at the same time (default 4, max 16). Output keeps the input order. |
| `--timeout SECONDS` | Per-request timeout (default 10). |
| `--retries N` | Retry a target's first request after a timeout or dropped connection (default 1, max 5). DNS and certificate errors are not retried. |
| `--insecure` | If a target's certificate is not trusted, still run the other checks for that target without verification. The certificate stays a FAIL. |
| `--dkim-selector NAME` | DKIM selector to check, repeatable. By default common provider selectors are tried. |
| `--version` | Print the version. |

## Checks

`web-posture-check --list-checks` prints this list. Each check reports PASS, WARN or FAIL with a one-line reason.

| Area | Checks |
|---|---|
| **Response** | `http-status` · `hsts` · `csp` · `x-content-type-options` · `clickjacking` · `referrer-policy` · `permissions-policy` · `cross-origin-isolation` · `x-xss-protection` · `information-leakage` |
| **Cookies and CORS** | `cookies` · `cors` |
| **TLS** | `tls-certificate` · `tls-protocols` |
| **DNS and email** | `caa` · `spf` · `dmarc` · `dkim` |
| **Policy and transport** | `security-txt` · `https-redirect` |

<details>
<summary><b>Response headers</b>: exactly when each check fails or warns</summary>

| Check | FAIL when | WARN when |
|---|---|---|
| `http-status` | | the final response is HTTP 400 or higher, so the other findings describe an error page. 403, 429 and 503 are often bot protection blocking automated clients |
| `hsts` | `Strict-Transport-Security` is missing or has no `max-age` | `max-age` is below 6 months, or `preload` is set without the preload list's requirements (`max-age` of at least 1 year and `includeSubDomains`) |
| `csp` | `Content-Security-Policy` is missing | only the report-only header is set; or the script policy (`script-src`, else `default-src`) allows `'unsafe-inline'` without a nonce or hash, `'unsafe-eval'`, or scripts from any host (`*`, `https:`, `http:`) or `data:` (ignored with `'strict-dynamic'`) |
| `x-content-type-options` | missing or not `nosniff` | |
| `clickjacking` | no CSP `frame-ancestors` and no `X-Frame-Options: DENY/SAMEORIGIN` | |
| `referrer-policy` | set to `unsafe-url` | missing |
| `permissions-policy` | | missing |
| `cross-origin-isolation` | | `Cross-Origin-Opener-Policy` is missing or `unsafe-none`, `Cross-Origin-Resource-Policy` is missing, or any of the three headers has a value browsers do not recognise. A missing `Cross-Origin-Embedder-Policy` is reported but not warned about |
| `x-xss-protection` | | set to `1` (with or without `mode=block`), which turns on the legacy XSS auditor that can be abused for XS-Leaks, or set to an invalid value |
| `information-leakage` | | `Server` includes a version number, or `X-Powered-By`, `X-AspNet-Version` or `X-AspNetMvc-Version` is present |

</details>

<details>
<summary><b>Cookies and CORS</b></summary>

| Check | FAIL when | WARN when |
|---|---|---|
| `cookies` | a cookie on an HTTPS response lacks `Secure`; `SameSite=None` without `Secure`; a `__Secure-` cookie lacks `Secure`; a `__Host-` cookie lacks `Secure` or `Path=/` or sets `Domain` (browsers reject all of these) | a cookie lacks `HttpOnly` or `SameSite` |
| `cors` | the response reflects any `Origin`, or allows `Origin: null`, together with `Access-Control-Allow-Credentials: true` | it reflects any `Origin` without credentials, or sends `*` with credentials (browsers reject that combination) |

Every `Set-Cookie` header is checked, and a `Set-Cookie` that only deletes a cookie (`Max-Age=0` or a past `Expires`) is ignored. A missing `HttpOnly` is a warning because some cookies are meant to be read by JavaScript.

</details>

<details>
<summary><b>TLS</b></summary>

| Check | FAIL when | WARN when |
|---|---|---|
| `tls-certificate` | the certificate has expired or is not trusted (wrong host, self-signed, untrusted chain, not yet valid) | it expires within 14 days; renewal tooling normally renews 30 days ahead, so this usually means renewal is failing |
| `tls-protocols` | the server completes a TLS 1.0 or TLS 1.1 handshake (deprecated by RFC 8996) | this machine's OpenSSL cannot offer one of those versions, so support is unknown |

</details>

<details>
<summary><b>DNS and email</b> (needs the <code>[dns]</code> extra)</summary>

| Check | FAIL when | WARN when |
|---|---|---|
| `caa` | | no CAA record (any certificate authority may issue), no `issue` property, or an unknown critical tag (every CA must then refuse) |
| `spf` | more than one SPF record (receivers then ignore SPF), or a record ending in `+all` / `all` | no SPF record, `?all`, or no `all` mechanism and no `redirect=` |
| `dmarc` | more than one DMARC record (receivers then apply no policy) | no DMARC record, `p=none`, a missing or invalid `p=`, or `pct=` below 100 |
| `dkim` | | no key under the common selectors, only revoked keys, or a selector given with `--dkim-selector` is missing or revoked. Selectors cannot be listed from outside, so this is reported as unknown, never as a failure |

</details>

<details>
<summary><b>Policy and transport</b></summary>

| Check | FAIL when | WARN when |
|---|---|---|
| `security-txt` | | `/.well-known/security.txt` is missing, not `text/plain`, lacks `Contact` or `Expires`, or has an invalid, expired, duplicate or more-than-a-year-away `Expires` (RFC 9116) |
| `https-redirect` | the `http://` URL answers without ending up on `https://` after redirects | |

If nothing answers on plain HTTP at all, `https-redirect` passes, since nothing is served without TLS.

</details>

## Reports, score and exit codes

**Formats.** `text` (default) prints one line per finding. `sarif` is a SARIF 2.1.0 log for [GitHub code scanning](#github-code-scanning) and other SARIF viewers. `json` gives `url`, `status`, `findings`, `score` and `grade` (plus `note` when checks were skipped or ran with `--insecure`); several targets give `{"results": [...]}`. `markdown` is a report for tickets, pull requests and emails, with failures first:

```markdown
## Web posture report: https://example.com

HTTP 200, generated 2026-10-10 15:50 UTC by web-posture-check 0.3.0

**Grade F** (40/100): **3 FAIL**, **0 WARN**, 2 PASS

| Status | Check | Detail |
|---|---|---|
| FAIL | `hsts` | Strict-Transport-Security header is missing |
| FAIL | `csp` | Content-Security-Policy header is missing |
| FAIL | `https-redirect` | http://example.com/ is served over plain HTTP without redirecting to HTTPS |
| PASS | `http-status` | final response is HTTP 200 |
| PASS | `tls-certificate` | certificate valid until 2026-12-25 (76 days) |
```

**Score and grade.** Each check counts 1 for PASS, 0.5 for WARN and 0 for FAIL, averaged to 100, so it means the same for any `--only` / `--skip` selection. A is 90 and above, B 80, C 70, D 60, F below. **A needs zero FAILs**: one serious problem cannot hide behind many passes. Skipped checks are shown but not scored.

**Exit codes.** With several targets, the worst one wins.

| Code | Meaning |
|---|---|
| 0 | No FAIL (WARN findings may exist) |
| 1 | At least one FAIL, including an untrusted certificate; with `--fail-on warn`, also any WARN |
| 2 | A target could not be reached (DNS failure, refused, timeout), or `--output` or `--sarif` could not be written |

## GitHub Action

Check sites on a schedule. The job fails on problems and the Markdown report appears in the job summary.

```yaml
name: Website posture
on:
  schedule:
    - cron: "0 6 * * 1"   # Mondays 06:00 UTC
  workflow_dispatch:

jobs:
  posture:
    runs-on: ubuntu-latest
    steps:
      - id: posture
        uses: MohammadThabetHassan/web-posture-check@v0.3.0
        with:
          targets: |
            example.com
            shop.example.com
          args: --fail-on warn
      - if: always()
        env:
          GRADE: ${{ steps.posture.outputs.grade }}
          SCORE: ${{ steps.posture.outputs.score }}
        run: echo "Grade $GRADE ($SCORE/100)"
```

| Input | Default | Meaning |
|---|---|---|
| `targets` | (required) | Domains or URLs, separated by spaces or new lines |
| `args` | `""` | Extra options such as `--only tls-certificate,caa` or `--fail-on warn`. Do not pass `--format`, `--json`, `--output`, `--sarif` or `--sarif-location`; the action writes the Markdown report and the SARIF log itself |
| `dns` | `"true"` | Install the `[dns]` extra for the CAA, SPF, DMARC and DKIM checks |
| `python-version` | `"3.12"` | Python version to run with |

| Output | Meaning |
|---|---|
| `score` | Lowest score (0–100) across the targets |
| `grade` | Worst grade (A–F) across the targets |
| `exit-code` | The tool's exit code (see above) |
| `report` | Path of the Markdown report file, e.g. to attach to an issue |
| `sarif` | Path of the SARIF 2.1.0 log, for [code scanning](#github-code-scanning) |

### GitHub code scanning

Since v0.4.0: upload the `sarif` output and every FAIL and WARN becomes an alert in the repository's **Security** tab. Alerts open when a problem appears and close by themselves when a later scan no longer finds it.

```yaml
jobs:
  posture:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - id: posture
        uses: MohammadThabetHassan/web-posture-check@v0.4.0
        with:
          targets: example.com
      - if: always() && steps.posture.outputs.sarif != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: ${{ steps.posture.outputs.sarif }}
          category: web-posture-check
```

FAIL becomes an error and WARN a warning; PASS and skipped checks are not uploaded. A website has no source line, so each alert points to the workflow file that ran the scan and names the URL in its message. An alert's identity is the check and the URL, so a detail that changes between runs (such as days until a certificate expires) updates the same alert instead of opening a new one. The Action's own CI uploads its SARIF to code scanning on every change, so the format is checked against GitHub itself, and validates it against the OASIS SARIF 2.1.0 schema.

For a fully reproducible workflow, pin the action to the release's commit SHA instead of the tag. The SecuritySolution.tech website runs this action every day alongside its own posture script.

## How it works

- **The response.** The target is fetched once (redirects followed) and the headers, cookies and status of the final response are checked. A second request with `Origin: https://web-posture-check.invalid`, a reserved domain that cannot exist (RFC 2606), tests CORS: a site that trusts it trusts any website.
- **TLS.** The certificate is read with the standard verifying TLS context. TLS 1.0 and 1.1 are each probed with a handshake allowed only that version; OpenSSL 3 will not offer them at its default security level, so the probe lowers it for that connection only, and if it still cannot offer one the result is a WARN, never a pass.
- **DNS.** CAA is read for the host, climbing to parent domains as certificate authorities do (RFC 8659). SPF, DMARC and DKIM are read for the mail domain (`www.` removed); DMARC falls back to the organizational domain as receivers do; DKIM is looked up at `<selector>._domainkey.<domain>` for Google Workspace, Microsoft 365, Mailchimp, SendGrid, Cloudflare Email Routing and common defaults, or for `--dkim-selector`.
- **Transport.** The same host and path are requested over `http://` (default port for an `https://` target, the target's own port for an `http://` one) to see whether it ends up on HTTPS.
- **Concurrency and `--insecure`.** Targets are scanned in a thread pool. A target scanned with `--insecure` gets its own unverified TLS context passed down its call chain only, so it can never affect another target's requests.

## Development

```bash
pip install -e ".[dns,dev]"
coverage run -m unittest discover -s tests -v && coverage report   # tests, branch coverage
ruff check src tests                                               # lint
mypy                                                               # type check, tests included
```

| Module (`src/webposture/`) | Role |
|---|---|
| `cli.py` | Arguments, `--list-checks`, the loop over targets |
| `runner.py` | The check list and summaries, and scanning one target: fetch, run the selected checks, exit code |
| `fetch.py` | HTTP requests, redirects, retries and error messages |
| `output.py`, `markdown.py`, `sarif.py` | Text, JSON, Markdown and SARIF rendering |
| `headers.py`, `cookies.py`, `cors.py`, `tls.py`, `transport.py`, `caa.py`, `securitytxt.py`, `emailauth.py` | The checks |
| `score.py`, `findings.py` | Score and grade, and the `Finding` type |

Checks are pure functions that take a response and return a `Finding`, so most tests need no network. `tests/test_end_to_end.py` runs the real CLI against small web servers on `127.0.0.1`, and `tests/test_tls_live.py` runs real TLS handshakes against a local server with a throwaway CA made by `openssl`, so the certificate and protocol code is tested without mocks. No test touches the internet.

CI on every change:

- **Ruff** lint and **mypy** type checking (every function body, tests included).
- The test suite on Python 3.9, 3.11 and 3.13 with **branch coverage**, which must stay at 97% or more (99% today). Each run puts the coverage table in its job summary.
- **CodeQL** static analysis of the Python code and the workflows (security-extended queries).
- The GitHub Action run from the checkout: a passing case, a case that must fail, and its SARIF uploaded to code scanning and validated against the OASIS schema.

Every action in the workflows is pinned to a commit SHA, and Dependabot keeps them and the Python tooling current.

## Releases

Changes are listed in [CHANGELOG.md](CHANGELOG.md). Pushing a tag such as `v0.3.0` runs [`release.yml`](.github/workflows/release.yml): it checks the tag matches the package version, builds and checks the package, and publishes it to PyPI with Trusted Publishing, so no PyPI token exists anywhere. Every published file carries a PyPI attestation linking it to that workflow.

## Contributing and security

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability in the tool itself, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Authors

- **Mohammad Thabet** ([@MohammadThabetHassan](https://github.com/MohammadThabetHassan))
- **Omar Alraas** ([@omaralraas](https://github.com/omaralraas))

Most changes are pull requests that both authors work on, so each is co-authored by both.

## License

MIT, see [LICENSE](LICENSE).
