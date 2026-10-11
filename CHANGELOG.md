# Changelog

All notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- SARIF 2.1.0 output for GitHub code scanning: `--format sarif`, and `--sarif FILE` to write a SARIF log next to the normal report from the same scan. FAIL is an error, WARN a warning; alerts keep one identity per check and URL across runs. `--sarif-location PATH` points every result at a repository file.
- The GitHub Action always writes a SARIF log, anchored to the workflow file that runs it, and has a `sarif` output for `github/codeql-action/upload-sarif`. CI uploads it to code scanning and validates it against the OASIS SARIF schema.
- The package is fully annotated, checked with mypy's strict options, and ships `py.typed` (PEP 561) for projects that import it. Tests are type-checked inside every function.
- CI runs the tests on Python 3.9 to 3.15 on Linux and on Windows and macOS, with branch coverage (99% minimum, 100% today, the table in each job summary), and installs the built wheel into clean environments with and without the `[dns]` extra.
- `tests/offline.py` runs the suite with only loopback reachable, and fails it if any test tries to reach the network, even when the code under test catches the error. CI and the release workflow run the tests this way.
- CodeQL analysis of the Python code and the workflows.
- Tests against real local servers: `tests/test_https_end_to_end.py` runs the CLI over HTTPS with a throwaway CA, and `tests/test_tls_live.py` runs the certificate fetch and the TLS 1.0/1.1 probes.

### Changed

- Markdown reports write the URL and each detail as code spans, so text a site sends is shown literally (see Security).
- A target that could not be scanned is part of the JSON report, in input order, with `"status": null`, `"findings": []` and an `"error"`, and of the Markdown report, with an **Error:** line. With one target, `--json` used to print nothing at all.
- With `--insecure`, a target that cannot be fetched even without certificate verification exits 2, like any target that could not be scanned (it exited 1).
- The DNS checks are reported as skipped for an IP address or a single-label host such as `localhost`, which have no domain to look up.
- `--sarif-location` without `--sarif` or `--format sarif` is a usage error instead of being ignored, and its path is written as a relative URI (`/` separators, spaces and `%` encoded).
- The report is written before the SARIF log, and both are always attempted.
- The release workflow runs the test suite before it builds. Every action in the workflows is pinned to a commit SHA, no checkout keeps the job's token (`persist-credentials: false`), pull request runs cancel the run they replace, and Dependabot proposes a release only after it has been out for seven days.
- For code that imports `webposture`: `runner.scan(target, ScanOptions)` returns `(result, exit code)`, and a result carries an `error` when the target could not be scanned; `checks.py` lists every check; `emailauth.lookup_txt` returns `([], reason)` on failure.

### Fixed

Checks that passed, or judged the wrong value, when a header was repeated, listed or unusual. Each now reads the header as browsers do:

- `hsts`: only the first header counts (RFC 6797). `max-age=0`, which tells browsers to stop enforcing HTTPS, and a repeated directive, which makes browsers ignore the header, now fail. So does a header received over plain HTTP, where browsers ignore it.
- `csp`: every header and every comma-separated policy is enforced, so a weakness counts only when every policy that restricts scripts has it. An empty policy fails, a policy without `script-src` or `default-src` warns (it passed), and `'strict-dynamic'` also turns off `'unsafe-inline'`.
- `clickjacking`: a `frame-ancestors` that allows any site (`*`, a bare scheme such as `https:`, or `https://*`) fails, even with `X-Frame-Options: DENY`, which browsers then ignore (it passed). Repeated `X-Frame-Options` values follow the HTML standard.
- `referrer-policy`: the last recognised value of a list applies, so `unsafe-url, strict-origin` is judged as `strict-origin`. `no-referrer-when-downgrade` and unrecognised values warn.
- `x-content-type-options`: the first value decides (Fetch standard). `permissions-policy`: an empty header warns. `information-leakage`: every `Server` header is checked. `cors`: repeated headers are combined, so `x, x` does not count as the probe origin.
- `cookies`: cookies set by redirects on the way to the final page are checked too, each against the scheme of the response that set it, and the last version of a cookie counts. They were not checked at all.
- `dmarc`: a subdomain that inherits its parent's record is judged by `sp=`, so `p=reject; sp=none` no longer passes for `mail.example.com`.
- `caa`: the lookup climbs to the top-level domain, as certificate authorities do (RFC 8659).
- `https-redirect`: a redirect to another `http://` URL or to a scheme other than `https://` is named as such.
- A target with spaces, control characters, credentials, an invalid port or host name, or a scheme other than `http(s)` is that target's error (exit 2) instead of a crash or a request. So is a response that is not HTTP, which crashed the run, and a redirect loop, which was graded as if its last redirect were the page. Any unexpected exception while scanning one target is that target's error too; the other targets are still reported.
- `--timeout` must be a number of seconds above 0: `0` made every request fail, and negative numbers, `nan` and `inf` crashed the run.
- Ctrl-C exits at once with code 130 instead of waiting for running scans, and a closed pipe (`| head`) ends quietly instead of with a traceback.
- Error pages and failed redirects no longer leave their connection open until garbage collection.
- A `--sarif` file that cannot be written no longer stops the report from being written.
- A server whose certificate has no expiry date is reported as untrusted instead of crashing the certificate check.
- The TLS 1.0/1.1 probe no longer emits a `DeprecationWarning` when it asks for those versions.

### Security

- Terminal injection: a site could put escape sequences in a header (for example OSC 52, which sets the clipboard of whoever runs the scan, or sequences that clear or rewrite the screen) and the text report printed them as they were. Text output and error messages now show control characters and bidirectional overrides as visible escapes such as `\x1b`.
- Markdown injection: a site's text could add links, images, HTML, @mentions and issue references to a report rendered in a job summary, issue or pull request. Backslash escapes are not enough on GitHub, so the text is now in code spans. The Action reads its grade only from the report's summary lines, so a site cannot add one.
- Only HTTP and HTTPS are ever requested. A redirect to `ftp://` made the tool connect to whatever host and port the site named; it is now refused, like a redirect to any other scheme. A target such as `file:///etc/hostname` was read from the local disk; a target with a scheme other than `http(s)` is now rejected.

## [0.3.0] - 2026-10-10

Makes the GitHub Action ready for the GitHub Marketplace and adds two CLI options.

### Added

- `--list-checks` prints every check name with a one-line description.
- `--output FILE` writes the report to a UTF-8 file instead of printing it. A file that cannot be written exits 2.
- The GitHub Action has outputs: `score` (lowest across targets), `grade` (worst), `exit-code` and `report` (path of the Markdown report), so later steps can use the result.
- Issue templates (bug report, feature request) and a pull request template.

### Changed

- The Action writes its report with `--output` instead of a shell redirect, and its description and authors are ready for the Marketplace listing.
- The README is rewritten: quick start, every check's FAIL and WARN rules, the Action's inputs and outputs, how it works, and development notes.

## [0.2.0] - 2026-10-10

First release published to PyPI. Every change below was a pull request co-authored by Mohammad Thabet and Omar Alraas.

### Added

- Checks
  - `hsts` reports `includeSubDomains` and `preload`, and warns when `preload` is set without the preload list's requirements (#2)
  - `csp` warns on `'unsafe-inline'` without a nonce or hash, `'unsafe-eval'`, and scripts from any host or `data:` URLs (#3, #4)
  - `information-leakage`: versioned `Server` and stack-disclosure headers (#5)
  - `https-redirect`: plain HTTP must redirect to HTTPS (#6)
  - `cookies`: `Secure`, `HttpOnly`, `SameSite` and `__Host-` / `__Secure-` prefix rules on every `Set-Cookie` (#7, #8)
  - `cors`: an origin probe that detects policies letting any website read responses (#9)
  - `cross-origin-isolation`: COOP, CORP and COEP (#10)
  - `x-xss-protection`: warns when the legacy XSS auditor is turned on (#11)
  - `http-status`: flags error pages, including bot protection (#12)
  - `tls-certificate`: expiry, and any certificate error on the target reported as a finding (#13, #14)
  - `tls-protocols`: fails when the server still accepts TLS 1.0 or 1.1 (#15)
  - `security-txt`: RFC 9116 checks (#16)
  - `spf`, `dmarc` and `dkim` email authentication checks, with the optional `[dns]` extra (#17, #18, #19)
  - `caa`: which certificate authorities may issue for the host (#20)
- Running and reporting
  - `--only` / `--skip` to choose checks; skipped checks make no requests (#21)
  - `--format markdown` report and `--format json` (#22)
  - Overall score and letter grade (#23)
  - Several targets per run and `--targets-file` (#24); scanned in parallel with `--jobs` (#34)
  - `--fail-on warn` for strict CI gates (#25)
  - Composite GitHub Action (#26)
  - `--retries` and plain-language errors for timeouts and dropped connections (#27)
  - `--insecure` to check a site whose certificate is broken (#28)
- End-to-end tests against local web servers (#29); Ruff linting in CI (#32)

### Fixed

- `cors` matched `Access-Control-Allow-Origin: null` case-insensitively; browsers compare it exactly, so only `null` counts (#35)
- `https-redirect` probed port 80 for an `http://host:8080` target and could wrongly pass (#30)

### Changed

- `cli.py` split into `cli`, `runner`, `fetch` and `output`; the `--insecure` global replaced by an explicit TLS context (#33)
- README refreshed, and both authors credited (#31)
- The package version is read from `webposture.__version__` (#1)
- Packaging metadata, a tag-triggered release workflow with PyPI Trusted Publishing, `SECURITY.md`, `CONTRIBUTING.md` and Dependabot for the pinned Actions and Python tooling (#35)

## [0.1.0] - 2026-10-09

- Initial release: HTTP security header checks with text and JSON output.

[Unreleased]: https://github.com/MohammadThabetHassan/web-posture-check/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/MohammadThabetHassan/web-posture-check/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/MohammadThabetHassan/web-posture-check/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/MohammadThabetHassan/web-posture-check/tree/v0.1.0
