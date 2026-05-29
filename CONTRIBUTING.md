# Contributing to Triagewall

Triagewall is pre-release and changing rapidly. Contributions are welcome but please coordinate before doing significant work.

## Before you start

- For bug reports, open a GitHub issue with reproduction steps and your environment details (OS, Python version, Suricata version, Ollama version, model used).
- For feature ideas, open a GitHub Discussion first. Most "what if Triagewall did X" ideas already exist on the v0.2/v0.3 roadmap and I'd rather coordinate than have parallel work.
- For security issues, see [SECURITY.md](SECURITY.md) — do not open a public issue.

## Development setup

Triagewall targets Python 3.11+. The current development environment runs on Debian Trixie with Python 3.13.

```bash
git clone https://github.com/aaronphifer/triagewall.git
cd triagewall
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # (planned for v0.1)
```

Triagewall expects an Ollama instance reachable at the address in your `.env` file. The default model is `hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M`. Other models work but the prompt and JSON-output expectations are tuned for that model class.

## Running tests

(Test suite is being developed alongside v0.1. This section will be filled in when meaningful tests exist.)

## Code style

- Format with `ruff format` (config will be in `pyproject.toml`)
- Type hints on all new public functions
- Docstrings on modules and non-trivial functions

## License implications of contributing

Triagewall is licensed under AGPL-3.0. By contributing, you agree that your contributions are licensed under the same terms. If you're contributing on behalf of an employer, ensure you have the authority to do so under that license.

If your organization needs Triagewall under a different license (e.g., MIT or BSD for internal use without AGPL §13 obligations), commercial licenses are available — email licensing@triagewall.io.

## Code of Conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Be kind, be patient, and assume good intent.
