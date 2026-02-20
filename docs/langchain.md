# LangChain Integration

Malwar provides a scan-before-execute integration layer that works standalone
and optionally interoperates with [LangChain](https://python.langchain.com/).
No LangChain dependency is required.

## Installation

The integration ships with the `malwar` package — no extras needed:

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

#### Attributes

| Attribute     | Value                                                  |
|--------------|--------------------------------------------------------|
| `name`        | `"malwar_scan"`                                        |
| `description` | Human-readable description of the tool's purpose       |

#### Methods

**`run(content, *, file_name="SKILL.md") -> dict`**

Scan content synchronously. Returns a dictionary:

```python
{
    "verdict": "CLEAN",          # CLEAN | CAUTION | SUSPICIOUS | MALICIOUS
    "risk_score": 0,             # 0-100
    "findings_count": 0,
    "findings_summary": [],      # list of {id, title, severity, category, confidence}
    "scan_id": "abc-123"
}
```

**`arun(content, *, file_name="SKILL.md") -> dict`**

Async variant of `run()`.

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

#### Constructor

| Parameter  | Type   | Default       | Description                                     |
|-----------|--------|---------------|-------------------------------------------------|
| `block_on` | `str`  | `"MALICIOUS"` | Minimum verdict to trigger block                |
| `use_llm`  | `bool` | `False`       | Enable the LLM analyzer layer                   |
| `use_urls` | `bool` | `False`       | Enable the URL crawler layer                     |

Valid `block_on` values (in ascending severity order):
- `"CLEAN"` — block everything (not recommended)
- `"CAUTION"` — block caution and above
- `"SUSPICIOUS"` — block suspicious and above
- `"MALICIOUS"` — block only malicious content

#### Methods

**`check(content, file_name="SKILL.md") -> ScanResult`**

Scan content synchronously. Returns the `ScanResult` if the verdict is
below the threshold. Raises `MalwarBlockedError` if it meets or exceeds
the threshold.

**`acheck(content, file_name="SKILL.md") -> ScanResult`**

Async variant of `check()`.

**`wrap(func) -> func`**

Decorator that scans the first string argument before executing the
wrapped function. Works with both sync and async functions.

```python
@guard.wrap
def process(content: str) -> str:
    return do_work(content)

@guard.wrap
async def aprocess(content: str) -> str:
    return await do_async_work(content)
```

---

### MalwarCallbackHandler

A callback handler that intercepts tool execution events and scans inputs.
Compatible with LangChain's `BaseCallbackHandler` pattern.

```python
from malwar import MalwarCallbackHandler

handler = MalwarCallbackHandler(
    block_on="MALICIOUS",
    use_llm=False,
    use_urls=False,
)
```

#### Constructor

| Parameter  | Type   | Default       | Description                                     |
|-----------|--------|---------------|-------------------------------------------------|
| `block_on` | `str`  | `"MALICIOUS"` | Minimum verdict to trigger block                |
| `use_llm`  | `bool` | `False`       | Enable the LLM analyzer layer                   |
| `use_urls` | `bool` | `False`       | Enable the URL crawler layer                     |

#### Methods

**`on_tool_start(tool_name, tool_input, **kwargs) -> ScanResult`**

Called before a tool executes. Scans `tool_input` and returns the
`ScanResult`. Raises `MalwarBlockedError` if the verdict exceeds the
threshold.

**`aon_tool_start(tool_name, tool_input, **kwargs) -> ScanResult`**

Async variant of `on_tool_start()`.

**`get_scan_log() -> list[dict]`**

Returns all scan events recorded by this handler. Each entry:

```python
{
    "tool_name": "execute_skill",
    "scan_id": "abc-123",
    "verdict": "CLEAN",
    "risk_score": 0,
    "findings_count": 0,
}
```

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

#### Attributes

| Attribute    | Type            | Description                              |
|-------------|-----------------|------------------------------------------|
| `verdict`    | `str`           | The verdict that triggered the block     |
| `risk_score` | `int`           | Risk score (0-100)                       |
| `findings`   | `list[Finding]` | Detailed findings from the scan          |
| `scan_id`    | `str`           | Unique scan identifier                   |

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
    for finding in e.findings:
        print(f"  - {finding.title}: {finding.description}")
```

### Decorator Pattern

```python
from malwar import MalwarGuard

guard = MalwarGuard()

@guard.wrap
def run_skill(skill_content: str) -> dict:
    """Execute a skill file. Malwar scans before execution."""
    # ... your execution logic ...
    return {"status": "ok"}

# Async variant
@guard.wrap
async def arun_skill(skill_content: str) -> dict:
    # ... your async execution logic ...
    return {"status": "ok"}
```

### LangChain Agent Integration

When using LangChain, `MalwarScanTool` can be added to an agent's tool list:

```python
from malwar import MalwarScanTool

# Create the tool
malwar_tool = MalwarScanTool(use_llm=False, use_urls=False)

# Use with LangChain (if installed)
from langchain.agents import initialize_agent, AgentType
from langchain.llms import OpenAI

tools = [malwar_tool]  # MalwarScanTool is compatible with LangChain's tool interface
agent = initialize_agent(tools, OpenAI(), agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION)
```

### Callback Handler with Tool Pipelines

```python
from malwar import MalwarCallbackHandler, MalwarBlockedError

handler = MalwarCallbackHandler(block_on="SUSPICIOUS")

def execute_tool_pipeline(tools: list, inputs: list[str]):
    for tool, tool_input in zip(tools, inputs):
        try:
            handler.on_tool_start(tool.name, tool_input)
            tool.run(tool_input)
        except MalwarBlockedError as e:
            print(f"Blocked {tool.name}: {e.verdict}")
            continue

    # Review the audit trail
    for entry in handler.get_scan_log():
        print(f"{entry['tool_name']}: {entry['verdict']} (score={entry['risk_score']})")
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
This is recommended for real-time guard checks where latency matters.
