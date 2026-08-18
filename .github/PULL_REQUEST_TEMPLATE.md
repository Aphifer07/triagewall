## Summary

Describe the operator-visible problem and the smallest complete change that
addresses it.

## Scope

- In scope:
- Deliberately unchanged:

## Validation

- [ ] A regression test failed before the fix and passes after it (when fixing a bug).
- [ ] `git diff --check`
- [ ] `python -m unittest discover -s tests`
- [ ] Dashboard JavaScript tests (when dashboard code changed)
- [ ] `python scripts/gold_gate.py verify`
- [ ] `PYTHONPATH=. python tests/test_spc.py`
- [ ] `python -m compileall -q triagewall tests scripts`
- [ ] Relevant Compose, YAML, HTML, and workflow validation

List focused tests and exact results:

## Security and operations

- [ ] No credential, private configuration document, or alert evidence enters URLs, logs, audit details, or browser storage.
- [ ] Default-off writes, `config:write` authorization, demo-mode denial, and sensor read-only behavior remain intact.
- [ ] Migration, backup, rollback, or deployment impact is documented.
- [ ] Documentation and release evidence are updated when behavior or claims changed.

## Files changed

List every changed file and why it belongs in this pull request.

## Screenshots

Add sanitized before/after screenshots for user-interface changes.
