# NEMOS release notes

NEMOS is the SIH-focused release engineering pass.

## Highlights

- Version metadata is synchronized across package, API and tests.
- Added an offline synthetic detection validation harness.
- Added SIH demo, presentation and judge-narrative documentation.
- Kept the validation path local and non-invasive.
- Corrected stale API version expectations in the test suite.

## Verification

Dependency-independent tests should be run with:

```bash
python -m unittest discover -s tests -v
```

The API tests additionally require the runtime dependencies from
`requirements.txt`.
