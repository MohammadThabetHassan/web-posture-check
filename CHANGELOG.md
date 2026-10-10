# Changelog

All notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

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

- `https-redirect` probed port 80 for an `http://host:8080` target and could wrongly pass (#30)

### Changed

- `cli.py` split into `cli`, `runner`, `fetch` and `output`; the `--insecure` global replaced by an explicit TLS context (#33)
- README refreshed, and both authors credited (#31)
- The package version is read from `webposture.__version__` (#1)

## [0.1.0] - 2026-10-09

- Initial release: HTTP security header checks with text and JSON output.

[0.2.0]: https://github.com/MohammadThabetHassan/web-posture-check/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/MohammadThabetHassan/web-posture-check/tree/v0.1.0
