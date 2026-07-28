# Contributing to Triagewall

Triagewall is pre-release and changing rapidly. Contributions are welcome but please coordinate before doing significant work.

## Before you start

- For bug reports, open a GitHub issue with reproduction steps and your environment details (OS, Python version, Suricata version, Ollama version, model used).
- For feature ideas, open a GitHub Discussion first. Check the
  [roadmap](ROADMAP.md) and the
  [Core/Lab product boundary](docs/core-lab-product-boundary.md) before
  proposing significant new scope.
- For security issues, see [SECURITY.md](SECURITY.md) — do not open a public issue.

Experimental Triagewall Lab work is not accepted into the public Core tree
until the documented graduation gates are met. Core changes should remain
production-ready and must not introduce a Lab dependency into the default
installation.

## Development setup

Triagewall targets Python 3.11+. The current development environment runs on Debian Trixie with Python 3.13.

```bash
git clone https://github.com/aaronphifer/triagewall.git
cd triagewall
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r tests/requirements-ci.txt
```

Triagewall expects an Ollama instance reachable at the address in your `.env` file. The default model is `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M`. Other models work but the prompt and JSON-output expectations are tuned for that model class.

## Running tests

Run the same core checks used by pull-request CI:

```bash
PYTHONPATH=. python -m unittest discover -s tests -p "test_*.py"
node --test tests/test_dashboard_polling.js
python -m compileall -q triagewall tests scripts
docker compose config --quiet
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml \
  --profile wazuh config --quiet
```

The regression workflow also resolves the locked dashboard dependencies and
builds the Core and optional Wazuh images.

## Code style

- Follow the surrounding style; no repository-wide autoformatter is currently
  enforced.
- Type hints on all new public functions
- Docstrings on modules and non-trivial functions
- Keep `git diff --check` clean.

## License implications of contributing

Triagewall is licensed under AGPL-3.0. By contributing, you agree that your contributions are licensed under the same terms. If you're contributing on behalf of an employer, ensure you have the authority to do so under that license.

If your organization needs Triagewall under a different license (e.g., MIT or BSD for internal use without AGPL §13 obligations), commercial licenses are available — email licensing@triagewall.io.

## Code of Conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Be kind, be patient, and assume good intent.
