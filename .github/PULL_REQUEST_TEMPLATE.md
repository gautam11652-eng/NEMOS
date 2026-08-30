## What this changes

<!-- What does this do, and why is it needed? -->

## How it was verified

<!--
Which of these did you run, and what was the result? Paste real output rather
than asserting it passed.
-->

- [ ] `python -m pytest -q`
- [ ] `ruff check .`
- [ ] `python -m compileall -q main.py nemos tests`
- [ ] `node --check nemos/static/app.js` (if the dashboard changed)

## Checklist

- [ ] Behaviour changes come with tests; a bug fix has a test that fails without it
- [ ] Any state keyed by an attacker-influenceable value (source address, hostname) is bounded
- [ ] Nothing expensive was added to the packet-capture path
- [ ] Detection changes carry evidence, and any ATT&CK mapping is supported by observed behaviour
- [ ] Documentation matches what the code actually does
- [ ] No credentials, tokens, captures, databases or generated files are committed

## Detection-threshold changes

<!--
Delete this section if you did not change a threshold. Otherwise: what traffic
motivated it, the expected effect on false positives and negatives, and how you
validated it.
-->
