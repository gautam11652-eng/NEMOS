# Contributing

1. Fork the repository and create a focused branch.
2. Keep changes defensive and authorized-use oriented.
3. Add or update tests for behavioral changes.
4. Run:
   ```bash
   python -m compileall -q nemos main.py
   python -m unittest discover -s tests -v
   ```
5. Do not commit `venv/`, databases, captures, secrets, or generated files.
6. Explain detection-threshold changes and expected false-positive tradeoffs in the pull request.
