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
coverage run tests/offline.py && coverage report   # every test, network blocked, branch coverage
ruff check src tests                                 # lint
mypy                                                 # strict for the package, tests included
```

`tests/offline.py` runs `python -m unittest discover -s tests` with only loopback reachable, and passes
extra arguments on to it: `python tests/offline.py -p "test_fetch.py"` runs one file. Run tests through
discover like this, not as `python -m unittest tests.test_x`: the test modules import their shared
helpers (`tests/tls_fixtures.py`) as top-level modules.

CI runs the same on Python 3.9 to 3.15 on Linux and on Windows and macOS, fails below 99% branch
coverage, builds and installs the package, and runs the GitHub Action from the checkout.

## Guidelines

- **One change per pull request**, with tests. Checks are pure functions that take a response and return a
  `Finding`, so most changes can be tested without network access; `tests/test_end_to_end.py` and
  `tests/test_https_end_to_end.py` show how to test the whole CLI against a local web server.
- **No test may reach the internet.** Use a local server or a mock; `tests/offline.py` fails the run otherwise.
- **A new check** goes in `src/webposture/checks.py` (name and summary, in report order) and in the code
  that runs it (`headers.run` for a response header, otherwise `runner.run_checks`), with its FAIL and
  WARN rules in the README.
- **Annotate new code.** mypy checks the package with its strict options.
- **Treat what a site sends as hostile.** Findings quote it; the text and Markdown reports escape it
  (`textsafe.printable`), and a new output format must too.
- **Never report a false PASS.** If a check cannot decide (a lookup failed, the local OpenSSL cannot test
  something, a selector cannot be guessed), report a WARN that says so.
- **Cite the standard** (RFC, Fetch, OWASP) in a comment when a rule comes from one.
- Keep the core free of third-party dependencies. DNS-based checks use the optional `[dns]` extra.
- Add a line to `CHANGELOG.md` under an "Unreleased" heading.

Security problems in the tool itself: please follow [SECURITY.md](SECURITY.md) instead of opening an issue.
