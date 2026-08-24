# Contributing

Thank you for helping improve OhMyDB.

## Before contributing

1. Search existing issues and pull requests.
2. For major architectural changes, open a discussion or issue first.
3. Never include real credentials, production SQL, customer data, or database dumps.

## Local setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
python -m unittest discover -s tests -v
```

## Pull requests

- Keep changes focused.
- Add tests for protocol parsing and risk decisions.
- Document fail-open or fail-closed behavior explicitly.
- Treat silent forwarding of unclassified mutations as a security-sensitive change.
- Update `CHANGELOG.md` when user-visible behavior changes.

## Commit style

Use concise imperative commits, for example:

```text
Add full-table UPDATE estimate
Reject unknown extended-protocol portals
Document estimator permissions
```
