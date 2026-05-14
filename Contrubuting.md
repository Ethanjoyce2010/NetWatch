# Contributing to NetWatch

Thanks for helping improve NetWatch. This project is a host-based network
monitor and response tool, so contributions should keep operator safety,
clear reporting, and low false-positive rates in mind.

## Getting Started

1. Fork or branch from the latest main branch.
2. Create a virtual environment with Python 3.10 or newer.
3. Install runtime and development dependencies:

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

1. Run the test suite before making changes:

```bash
python -m pytest tests/ -q
```

## Code Contributions

- Keep changes focused. A small detection-rule improvement should not also
  reformat unrelated files.
- Prefer existing project patterns over new abstractions.
- Add or update tests for behavior changes, especially detector rules,
  whitelist behavior, report output, response actions, and provider parsing.
- Keep potentially destructive functionality opt-in and behind clear user
  confirmation.
- Avoid committing generated artifacts such as reports, alert logs, feed
  caches, local map outputs, or virtual environment files.
- Use clear names for rules, CLI flags, and report fields. Operators should
  understand findings quickly during triage.

## Detection Rules

When adding or changing detection logic:

- Include a short, actionable alert description.
- Set severity conservatively and explain high or critical severity with
  concrete evidence.
- Add enough detail fields for reports, CSV output, whitelist matching, and
  future investigation workflows.
- Add tests for both positive and non-triggering cases where practical.

## Threat Intelligence Providers

Provider integrations should:

- Work without network access during tests by using mocked API responses.
- Avoid hard-coding private API keys or real secrets.
- Fail gracefully when an API key is missing, a provider is unavailable, or a
  response shape changes.
- Cache imported feed data only in the configured NetWatch cache directory.

## Bug Reports

Please include:

- The NetWatch command you ran.
- Operating system and Python version.
- Whether the command was run with administrator/root privileges.
- Expected behavior and actual behavior.
- Relevant traceback, alert output, or a minimal sample input.
- Whether the issue reproduces with the latest code.

Do not include real secrets, API keys, private tokens, or sensitive internal
IP details unless they are carefully redacted.

## Feature Requests

Useful feature requests describe:

- The workflow or investigation problem you are trying to solve.
- Example input and desired output.
- Whether the feature should affect live monitoring, reports, exports, or CLI
  one-shot modes.
- Any safety concerns, false-positive risks, or platform-specific behavior.

## Security Reports

Please do not report vulnerabilities in the public issue tracker. Follow
[SECURITY.md](SECURITY.md) for private reporting instructions.

## Pull Request Checklist

- Tests pass with `python -m pytest tests/ -q`.
- New behavior is documented in `README.md` when it changes the user-facing
  CLI or output.
- Risky actions require explicit user confirmation.
- Generated files are not included.
- The change is scoped to the described bug or feature.
