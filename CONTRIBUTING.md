# Contributing

Thanks for helping. Bug reports, new checks and fixes are all welcome.

## Set up

```bash
git clone https://github.com/MohammadThabetHassan/web-posture-check.git
cd web-posture-check
pip install -e ".[dns,dev]"
```

## Before you open a pull request

```bash
python -m unittest discover -s tests -v
ruff check src tests
```

CI runs both on Python 3.9, 3.11 and 3.13, plus a workflow that runs the GitHub Action from the checkout.

## Guidelines

- **One change per pull request**, with tests. Checks are pure functions that take a response and return a
  `Finding`, so most changes can be tested without network access; `tests/test_end_to_end.py` shows how to
  test the whole CLI against a local web server.
- **Never report a false PASS.** If a check cannot decide (a lookup failed, the local OpenSSL cannot test
  something, a selector cannot be guessed), report a WARN that says so.
- **Cite the standard** (RFC, Fetch, OWASP) in a comment when a rule comes from one.
- Keep the core free of third-party dependencies. DNS-based checks use the optional `[dns]` extra.
- Add a line to `CHANGELOG.md` under an "Unreleased" heading.

Security problems in the tool itself: please follow [SECURITY.md](SECURITY.md) instead of opening an issue.
