# OhMyDB Release Checklist

Use this checklist before publishing a new stable OhMyDB release.

## Code quality

- [ ] Focused tests pass
- [ ] Full test suite passes
- [ ] `python -m compileall -q sql_safety_proxy` passes
- [ ] `python -m pip check` passes
- [ ] `git diff --check` passes

## Compatibility

- [ ] `ohmydb --version` works
- [ ] Legacy `sql-safety-proxy --version` works
- [ ] PostgreSQL path is validated
- [ ] MySQL/MariaDB path is validated when affected
- [ ] Supported Python versions pass CI

## Packaging

- [ ] Wheel builds successfully
- [ ] Source distribution builds successfully
- [ ] `twine check` passes
- [ ] Fresh virtual-environment install succeeds

## Docker

- [ ] Image builds successfully
- [ ] CLI works inside the image
- [ ] Container runs as a non-root user

## Release

- [ ] Version references are updated
- [ ] Release notes summarize user-visible changes
- [ ] Release tag points to the intended `main` commit
- [ ] Release assets are uploaded
- [ ] SHA-256 checksums are generated
- [ ] GitHub release is marked stable when appropriate

## Final verification

After publishing, verify the release from a clean environment instead of relying only on the development checkout.