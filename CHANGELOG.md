# Changelog

All notable changes to this project will be documented here.

## [0.1.0-alpha] - 2026-07-26

### Added

- PostgreSQL Simple Query interception
- PostgreSQL extended `Parse → Bind → Execute` interception
- `sqlglot`-based SQL classification
- warnings for `UPDATE`, `DELETE`, `DROP`, and `TRUNCATE`
- read-only impact preview for eligible filtered mutations
- native Tkinter confirmation popup
- CLI confirmation fallback
- common binary parameter decoding heuristics
- package CLI entry point

### Security notice

This release is intended for disposable development environments. It is not yet a sole production protection layer.
