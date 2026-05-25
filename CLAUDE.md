# CLAUDE.md

## After every code change

Run both checks before reporting work done. No exceptions.

```
python -m ruff check src/ tests/
python -m pytest tests/ -q
```

Fix every ruff violation. All tests must pass. If a test catches a new bug, fix the bug — don't adjust the test to pass.

## Commit discipline

- Commit only what was explicitly asked for.
- Do not start the next task without being asked.
- Do not push unless asked.

## Proxy repo

W:\apc-hsm-proxy is owned by a separate session. Never read, edit, or touch any file under that path.

## Code style

- No comments unless the WHY is non-obvious.
- No trailing summaries in responses — the diff speaks for itself.
- Default to no new files; edit existing ones.
