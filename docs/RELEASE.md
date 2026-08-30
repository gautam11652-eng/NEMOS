# Release process

NEMOS uses [semantic versioning](https://semver.org/). For a monitoring tool,
treat a change in detection behaviour as user-visible: a threshold change that
alters what gets alerted on is at least a minor bump, even though no API
signature changed.

## Version is single-sourced

`nemos/version.py` is the only place the version is written.

```python
VERSION = "3.3.0"
```

`pyproject.toml` reads it via `dynamic = ["version"]`, and `/api/health`
reports the same value. Do not add a second literal version anywhere — a CI job
verifies that the built artifacts carry the version from `version.py`, and it
exists because these had previously drifted apart.

## Steps

1. **Confirm `main` is green.** All CI jobs pass on the commit you intend to
   release.

2. **Bump the version** in `nemos/version.py`.

3. **Update `CHANGELOG.md`.** Add a section for the new version using
   Added / Changed / Fixed / Removed. Describe behaviour, not implementation:
   readers want to know what changed for them. Detection-threshold changes must
   be called out explicitly, because they alter what a deployment alerts on.

4. **Work through [`RELEASE_CHECKLIST.md`](../RELEASE_CHECKLIST.md).** It covers
   the verification that automation cannot do for you — capture on a real
   interface, graceful shutdown, authentication.

5. **Verify the build locally:**

   ```bash
   python -m pytest -q
   ruff check .
   python -m compileall -q main.py nemos tests
   python -m pip_audit -r requirements.txt
   python -m build
   ls dist/     # filenames must carry the new version
   ```

6. **Commit and tag.** The tag must match `version.py` exactly:

   ```bash
   git commit -am "Release NEMOS 3.3.0"
   git tag -a v3.3.0 -m "NEMOS 3.3.0"
   git push origin main --follow-tags
   ```

   A tag ahead of `version.py` has happened before and makes it impossible to
   tell what a deployed build actually contains. Check both before tagging.

7. **Publish release notes** on GitHub from the CHANGELOG section.

## What not to ship

Never package or commit a `.env`, a runtime database, packet captures, logs,
virtual environments, caches or credentials. `.gitignore` covers the common
cases; verify with `git status` and by inspecting the built sdist rather than
trusting it.

## Verification commands

```bash
python -m pytest -q                            # full suite
python -m compileall -q main.py nemos tests    # syntax
ruff check .                                   # lint
python -m pip_audit -r requirements.txt        # dependency audit
python tools/validate_detection.py             # offline detection check
./scripts/verify-kali.sh                       # full environment check
```

The API and delivery tests require the runtime dependencies from
`requirements.txt`; `requirements-dev.txt` includes those plus the tooling.
