# Contributing to Malwar

Thanks for your interest in contributing! Malwar is a malware detection engine for agentic AI skill files, and community contributions make it stronger.

## Reporting Bugs

Open a [GitHub issue](https://github.com/Ap6pack/malwar/issues/new?template=bug_report.yml) with:
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version, Malwar version)

## Suggesting Features

Open a [feature request](https://github.com/Ap6pack/malwar/issues/new?template=feature_request.yml) describing the use case and proposed solution.

## Development Setup

```bash
# Clone
git clone https://github.com/Ap6pack/malwar.git
cd malwar

# Install in development mode
pip install -e ".[dev]"

# Initialize the database
malwar db init

# Run tests
pytest tests/ --ignore=tests/benchmark --ignore=tests/live

# Run linter
ruff check src/ tests/

# Run type checker
mypy src/
```

## Code Style

- **Linter**: Ruff (config in `pyproject.toml`)
- **Type hints**: Required for all public functions
- **Copyright header**: Every Python file must start with:
  ```python
  # Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
  ```

## Adding a Detection Rule

1. Create a new file in `src/malwar/detectors/rule_engine/rules/`
2. Subclass `BaseRule` and decorate with `@rule`
3. Add test fixtures in `tests/fixtures/skills/`
4. Add unit tests in `tests/unit/detectors/test_rule_engine.py`
5. Verify zero false positives on benign fixtures

## Pull Request Process

1. Fork the repo and create a feature branch
2. Write tests for your changes
3. Ensure `ruff check` and `pytest` pass
4. Add copyright headers to new files
5. Submit a PR with a clear description

## Code of Conduct

Be respectful and constructive. We're all here to make the security ecosystem better. Harassment, trolling, and unconstructive criticism are not tolerated.

## Contributions

By submitting a PR, you agree that your contributions are subject to the project's BSL-1.1 terms.
