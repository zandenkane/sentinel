# Contributing to Sentinel

Thanks for wanting to help. This is a small project and we keep things simple.

## Dev Setup

```bash
git clone https://github.com/<you>/sentinel.git
cd sentinel
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Requires Python 3.10+.

## Running Tests

```bash
pytest
```

That's it. If you add a new module, add tests for it too.

## Code Style

We use **ruff** for linting and formatting:

```bash
ruff check .
ruff format .
```

Type hints are expected on all public functions. Run `mypy sentinel/` to check.

Line length limit is 100 chars (configured in `pyproject.toml`).

## Adding a Detection Module

1. Create a new file in `sentinel/`, e.g. `sentinel/yourmodule.py`.
2. Import `Finding` from `sentinel.finding` and have your module return `list[Finding]`.
3. Wire it into `sentinel/scanner.py` by adding your import and registering it in the `MODULES` or `NEW_MODULES` list.
4. Add the module key to `ALL_MODULE_KEYS` so it shows up in `--modules` and `--list-modules`.
5. Write tests.

Look at any existing module (like `arp.py` or `dnsmon.py`) for the pattern.

## Bug Reports and Feature Requests

Open a GitHub issue. Include enough detail to reproduce the problem or understand the request.

## Submitting Changes

No CLA, no formal process. Fork the repo, make your changes, open a PR. Keep PRs focused on one thing. We will review and merge or ask for tweaks.

If you are unsure whether a change makes sense, open an issue first to discuss it.

## License

By contributing, you agree your code falls under the project's MIT license.
