# Plugin System

malwar supports third-party detector plugins that extend the scan pipeline with
custom detection logic. Plugins are loaded at startup and run alongside the
built-in detection layers.

## Architecture

```
┌────────────────────────────────────────────┐
│              ScanPipeline                  │
│                                            │
│  Built-in layers (order 10-40):            │
│    rule_engine -> url_crawler ->           │
│    llm_analyzer -> threat_intel            │
│                                            │
│  Plugin layers (order >= 100):             │
│    plugin:foo -> plugin:bar -> ...         │
└────────────────────────────────────────────┘
```

Plugins implement the `DetectorPlugin` abstract class, which extends the core
`BaseDetector` interface with metadata and lifecycle support.

## Writing a Plugin

### 1. Implement `DetectorPlugin`

```python
from malwar.plugins.base import DetectorPlugin, PluginMetadata
from malwar.models.finding import Finding
from malwar.scanner.context import ScanContext


class MyDetector(DetectorPlugin):
    @property
    def plugin_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my_detector",
            version="1.0.0",
            author="Your Name",
            description="Detects something interesting",
            layer_name="plugin:my_detector",
            tags=["custom"],
        )

    async def detect(self, context: ScanContext) -> list[Finding]:
        findings = []
        # Your detection logic here, analyzing context.skill
        return findings
```

### 2. Optional Lifecycle Hooks

Plugins inherit `setup()` and `teardown()` from `BaseDetector`:

```python
async def setup(self) -> None:
    """Called once before the first scan."""
    self._model = load_model()

async def teardown(self) -> None:
    """Called on shutdown."""
    self._model.close()
```

### 3. Event Hooks

Plugins can register callbacks for scan lifecycle events:

```python
from malwar.plugins.hooks import HookManager, HookType

def on_scan_start(**kwargs):
    print(f"Scan {kwargs['scan_id']} starting")

hook_manager = HookManager()
hook_manager.register(HookType.PRE_SCAN, on_scan_start)
```

Available hook types:

| Hook          | Fired when...                  | Keyword arguments       |
|---------------|--------------------------------|-------------------------|
| `PRE_SCAN`    | Before the pipeline executes   | `scan_id`, `skill`      |
| `POST_SCAN`   | After the pipeline completes   | `scan_id`, `result`     |
| `ON_FINDING`  | Each time a finding is created | `finding_id`, `finding` |

Both sync and async callbacks are supported. Exceptions in hooks are logged and
swallowed so they cannot break the scan pipeline.

## Installing Plugins

### Option A: Entry Points (recommended for packages)

Register your plugin class as a `malwar.detectors` entry point in
`pyproject.toml`:

```toml
[project.entry-points."malwar.detectors"]
my_detector = "my_package.detector:MyDetector"
```

After `pip install my-package`, malwar will discover it automatically.

### Option B: Plugins Directory

Place `.py` files in a directory and set the environment variable:

```bash
export MALWAR_PLUGINS_DIR=/opt/malwar/plugins
```

All `*.py` files (excluding those starting with `_`) will be imported and
scanned for `DetectorPlugin` subclasses.

### Option C: Explicit Module Paths

Set comma-separated dotted module paths:

```bash
export MALWAR_PLUGIN_MODULE_PATHS=my_package.detector,other_package.scanner
```

## Configuration

| Environment Variable       | Description                                    | Default |
|----------------------------|------------------------------------------------|---------|
| `MALWAR_PLUGINS_DIR`       | Directory to scan for plugin `.py` files       | (none)  |
| `MALWAR_ENABLED_PLUGINS`   | Comma-separated list of plugin names to enable | (all)   |
| `MALWAR_PLUGIN_MODULE_PATHS` | Comma-separated dotted module paths          | (none)  |

When `MALWAR_ENABLED_PLUGINS` is not set, all discovered plugins are enabled.
When set, only the listed plugins are enabled; all others are loaded but
disabled.

## CLI Commands

```bash
# List installed plugins
malwar plugin list

# Enable a plugin
malwar plugin enable my_detector

# Disable a plugin
malwar plugin disable my_detector
```

## API Endpoints

| Method | Path                              | Description              |
|--------|-----------------------------------|--------------------------|
| GET    | `/api/v1/plugins`                 | List all plugins         |
| POST   | `/api/v1/plugins/{name}/enable`   | Enable a plugin by name  |
| POST   | `/api/v1/plugins/{name}/disable`  | Disable a plugin by name |

### Example: List plugins

```bash
curl http://localhost:8000/api/v1/plugins | jq
```

```json
[
  {
    "name": "my_detector",
    "version": "1.0.0",
    "author": "Your Name",
    "description": "Detects something interesting",
    "layer_name": "plugin:my_detector",
    "enabled": true
  }
]
```

## Example Plugin

A complete example plugin is provided at `examples/plugins/example_detector.py`.
It detects `TODO`/`FIXME` markers in skill files and demonstrates the full
plugin interface including metadata, detection logic, and finding creation.
