# Interactive TUI Mode

malwar includes an interactive Terminal User Interface (TUI) built with [Rich](https://rich.readthedocs.io/) for a visual, real-time scanning experience.

## Quick Start

```bash
# Launch the interactive TUI
malwar tui

# Launch TUI focused on a specific directory
malwar tui /path/to/skills/
```

## Features

### Interactive Dashboard

The dashboard provides a live overview of scanning activity:

- **Scan Status**: Completed scans, in-progress count, failures, and uptime
- **Verdict Distribution**: Bar chart showing MALICIOUS / SUSPICIOUS / CAUTION / CLEAN counts
- **Recent Results**: Latest scan results with verdict, risk score, and finding count
- **Top Rule Triggers**: Most frequently triggered detection rules
- **System Stats**: Platform, Python version, PID, and system load

Access the dashboard from the TUI prompt:

```
malwar> dashboard
```

Press `Ctrl+C` to return to the command prompt.

### Interactive Scanner / File Browser

Browse and select SKILL.md files for scanning:

```
malwar> scan /path/to/skills/
malwar> browse /path/to/skills/
```

The scanner presents:

1. A file listing with size and modification date
2. File selection (by number, comma-separated, or "all")
3. Layer configuration (which detection layers to run)
4. Real-time progress bar during scanning
5. Rich-formatted results after each file

### Rich-Formatted Scan Output

All scan results are displayed with enhanced formatting:

- **Color-coded verdicts**: Red for MALICIOUS, yellow for SUSPICIOUS, cyan for CAUTION, green for CLEAN
- **Severity badges**: Color-coded labels (e.g., white-on-red for CRITICAL)
- **Findings table**: Sortable by severity with rule ID, confidence, and line numbers
- **Evidence tree**: Collapsible view of evidence per finding with remediation hints
- **Layer tree**: Shows which detection layers executed vs. skipped
- **Progress bars**: Visual progress during multi-file scans

## Watch Mode

Monitor a directory for changes to SKILL.md files and auto-scan when modifications are detected:

```bash
# Watch with default 2-second polling interval
malwar scan /path/to/skills/ --watch

# Watch with custom polling interval
malwar scan /path/to/skills/ --watch --poll-interval 5.0

# Watch with specific layers
malwar scan /path/to/skills/ --watch --layers rule_engine,threat_intel
```

Watch mode uses polling (no external `watchdog` dependency required). It detects:

- New `.md` files added to the directory
- Modified `.md` files (based on filesystem modification time)

Press `Ctrl+C` to stop watching.

## TUI Commands

When running `malwar tui`, the following commands are available at the prompt:

| Command | Description |
|---------|-------------|
| `scan <dir>` | Scan .md files in a directory |
| `browse <dir>` | Browse and select files to scan |
| `dashboard` | Show live dashboard (Ctrl+C to return) |
| `help` | Show available commands |
| `quit` | Exit the TUI |

## Dependencies

The TUI uses only the `rich` library, which is already a core dependency of malwar. No additional TUI frameworks (such as Textual) are required.

## Examples

### Single file scan with Rich output

```bash
malwar scan examples/skills/suspicious_skill.md
```

Output includes color-coded verdict panel, findings table with severity badges, evidence tree, and layer execution summary.

### Batch scan with progress

```bash
malwar scan /path/to/many/skills/
```

Shows a progress bar tracking each file, followed by individual Rich-formatted results.

### Watch mode for CI/development

```bash
malwar scan ./skills/ --watch --poll-interval 1.0
```

Continuously monitors and rescans on changes, useful during skill development.
