# Changelog

All notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- README: how web-posture-check compares with Mozilla HTTP Observatory, testssl.sh, internet.nl and securityheaders.com, and what it does not do.
- README: a compatibility promise for 0.x: exit codes, check names, JSON fields, statuses and the Action's inputs and outputs only change in a minor version, with a CHANGELOG entry.

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
