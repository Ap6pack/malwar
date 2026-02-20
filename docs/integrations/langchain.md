<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# LangChain Integration

Malwar provides a scan-before-execute integration layer that works standalone
and optionally interoperates with [LangChain](https://python.langchain.com/).
No LangChain dependency is required.

## Installation

The integration ships with the `malwar` package -- no extras needed:

```bash
pip install malwar
```

## Quick Start

### MalwarGuard (recommended)

The fastest way to protect your agent pipeline:

```python
from malwar import MalwarGuard

guard = MalwarGuard(block_on="SUSPICIOUS")

# Scan content directly
result = guard.check(skill_content, file_name="SKILL.md")
print(result.verdict, result.risk_score)

# Or use as a decorator
@guard.wrap
def execute_skill(content: str) -> str:
    # This only runs if the scan passes
    return run_skill(content)

execute_skill(skill_content)  # raises MalwarBlockedError if blocked
```

---

## API Reference

### MalwarScanTool

A LangChain-compatible tool that agents can call to scan content.

```python
from malwar import MalwarScanTool

tool = MalwarScanTool(use_llm=False, use_urls=False)
```

#### Constructor

| Parameter  | Type   | Default | Description                          |
|-----------|--------|---------|--------------------------------------|
| `use_llm`  | `bool` | `False` | Enable the LLM analyzer layer       |
| `use_urls` | `bool` | `False` | Enable the URL crawler layer         |

#### Methods

**`run(content, *, file_name="SKILL.md") -> dict`** -- Scan content synchronously.

**`arun(content, *, file_name="SKILL.md") -> dict`** -- Async variant.

---

### MalwarGuard

Middleware that scans content before allowing execution.

```python
from malwar import MalwarGuard

guard = MalwarGuard(
    block_on="MALICIOUS",   # minimum verdict to block
    use_llm=False,
    use_urls=False,
)
```

| Parameter  | Type   | Default       | Description                                     |
|-----------|--------|---------------|-------------------------------------------------|
| `block_on` | `str`  | `"MALICIOUS"` | Minimum verdict to trigger block                |
| `use_llm`  | `bool` | `False`       | Enable the LLM analyzer layer                   |
| `use_urls` | `bool` | `False`       | Enable the URL crawler layer                     |

Valid `block_on` values (in ascending severity order):

- `"CAUTION"` -- block caution and above
- `"SUSPICIOUS"` -- block suspicious and above
- `"MALICIOUS"` -- block only malicious content

#### Methods

**`check(content, file_name="SKILL.md") -> ScanResult`** -- Scan synchronously. Raises `MalwarBlockedError` if threshold exceeded.

**`acheck(content, file_name="SKILL.md") -> ScanResult`** -- Async variant.

**`wrap(func) -> func`** -- Decorator that scans the first string argument before execution.

---

### MalwarCallbackHandler

A callback handler that intercepts tool execution events and scans inputs. Compatible with LangChain's `BaseCallbackHandler` pattern.

**`on_tool_start(tool_name, tool_input, **kwargs) -> ScanResult`** -- Called before tool execution.

**`get_scan_log() -> list[dict]`** -- Returns all scan events recorded by this handler.

---

### MalwarBlockedError

Exception raised when scanned content exceeds the configured threshold.

```python
from malwar import MalwarBlockedError

try:
    guard.check(content)
except MalwarBlockedError as e:
    print(e.verdict)      # "MALICIOUS"
    print(e.risk_score)   # 92
    print(e.findings)     # list[Finding]
    print(e.scan_id)      # "abc-123"
```

---

## Examples

### Basic Guard

```python
from malwar import MalwarGuard, MalwarBlockedError

guard = MalwarGuard(block_on="SUSPICIOUS")
content = open("SKILL.md").read()

try:
    result = guard.check(content)
    print(f"Safe to execute: {result.verdict}")
except MalwarBlockedError as e:
    print(f"BLOCKED: {e.verdict} (score={e.risk_score})")
```

### Decorator Pattern

```python
from malwar import MalwarGuard

guard = MalwarGuard()

@guard.wrap
def run_skill(skill_content: str) -> dict:
    """Execute a skill file. Malwar scans before execution."""
    return {"status": "ok"}

@guard.wrap
async def arun_skill(skill_content: str) -> dict:
    return {"status": "ok"}
```

### LangChain Agent Integration

```python
from malwar import MalwarScanTool
from langchain.agents import initialize_agent, AgentType
from langchain.llms import OpenAI

malwar_tool = MalwarScanTool(use_llm=False, use_urls=False)
tools = [malwar_tool]
agent = initialize_agent(tools, OpenAI(), agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION)
```

### Async Usage

```python
import asyncio
from malwar import MalwarGuard, MalwarBlockedError

async def main():
    guard = MalwarGuard(block_on="SUSPICIOUS", use_llm=False, use_urls=False)
    content = open("SKILL.md").read()

    try:
        result = await guard.acheck(content)
        print(f"Safe: {result.verdict}")
    except MalwarBlockedError as e:
        print(f"Blocked: {e.verdict}")

asyncio.run(main())
```

## Configuration Options

| Option     | Default       | Description                                      |
|-----------|---------------|--------------------------------------------------|
| `block_on` | `"MALICIOUS"` | Verdict threshold for blocking                   |
| `use_llm`  | `False`       | Enable LLM analysis (slower, requires API key)   |
| `use_urls` | `False`       | Enable URL crawling (slower, requires network)   |

Setting `use_llm=False` and `use_urls=False` (the defaults) provides the
fastest scanning using only the rule engine and threat intelligence layers.
