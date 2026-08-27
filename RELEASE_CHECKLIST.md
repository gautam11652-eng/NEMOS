# NEMOS Release Checklist

Before publishing a release:

- [ ] `python -m pytest -q` passes
- [ ] `python -m compileall -q main.py nemos tests` passes
- [ ] `python -m pip_audit -r requirements.txt` passes
- [ ] `python -m build` succeeds
- [ ] No `.env`, database, logs, virtualenv, caches, or credentials are packaged
- [ ] Local-only binding remains the documented default
- [ ] Remote binding requires an API token and trusted hosts
- [ ] Packet capture has been tested on a controlled interface
- [ ] Graceful shutdown has been tested
- [ ] Dashboard/API authentication has been tested
- [ ] CHANGELOG.md is updated
- [ ] Security-sensitive changes are reviewed before release
