## Developer setup (pre-commit)
pip install pre-commit
pre-commit install
Hooks: detect-private-key, check-added-large-files, gitleaks, semgrep.
They run on every commit. Do not use --no-verify; CI runs the same checks anyway.