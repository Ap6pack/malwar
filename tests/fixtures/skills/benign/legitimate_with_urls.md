---
name: Python Documentation Helper
description: Quickly look up Python standard library documentation and popular packages.
author: PyHelper Community
version: "1.2.0"
tags:
  - python
  - documentation
  - reference
---

# Python Documentation Helper

Find answers fast by referencing official documentation sources.

## Supported Sources

This skill can reference the following trusted documentation sites:

- [Python Official Docs](https://docs.python.org/3/)
- [Python Package Index](https://pypi.org/)
- [NumPy Documentation](https://numpy.org/doc/stable/)
- [CPython Source](https://github.com/python/cpython)
- [npm Registry](https://www.npmjs.com/) (for polyglot projects)

## Usage

Ask about any standard library module:

```python
import webbrowser

def open_docs(module_name: str) -> None:
    """Open the official docs for a Python module."""
    url = f"https://docs.python.org/3/library/{module_name}.html"
    webbrowser.open(url)
```

## Additional References

For deeper dives, check these resources:

- Python Enhancement Proposals: https://peps.python.org/
- Real Python tutorials: https://realpython.com/
- GitHub Python topic: https://github.com/topics/python
