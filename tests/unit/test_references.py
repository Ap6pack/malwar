"""Tests for extracting the files a SKILL.md names.

Weighted deliberately toward the negative cases. Every rule defect this project
has shipped was a false positive -- a pattern firing on text that merely
mentioned a thing rather than doing it -- and each was found by hand after the
fact rather than by a test written before it. So the "must not match" set here
is larger than the "must match" set, and covers the shapes that fooled the
detection rules: prose, warnings, and paths belonging to the user rather than
to the skill.
"""

from __future__ import annotations

import pytest

from malwar.research.references import clean_path, extract, is_executable


class TestExtractsNamedFiles:
    @pytest.mark.parametrize(
        ("text", "path", "kind"),
        [
            ("node ${SKILL_DIR}/scripts/buddy-algorithm.js \"$UUID\"",
             "scripts/buddy-algorithm.js", "executed"),
            ("bun ${SKILL_DIR}/scripts/generate-image.ts --prompt x",
             "scripts/generate-image.ts", "executed"),
            ("npx tsx scripts/apply-skill.ts --init",
             "scripts/apply-skill.ts", "executed"),
            ("python main.py audit --resume cv.pdf", "main.py", "executed"),
            ("bash ./bin/setup.sh", "bin/setup.sh", "executed"),
            ("Read `references/openclaw-workspace.md` first",
             "references/openclaw-workspace.md", "read-instruction"),
            ("see [cron](references/cron-platforms.md) for detail",
             "references/cron-platforms.md", "referenced"),
        ],
    )
    def test_named_paths_are_captured(self, text, path, kind):
        assert extract(text) == {path: kind}

    def test_strongest_label_wins(self):
        # A file both executed and mentioned is reported as executed: what the
        # agent is told to *run* matters more than what it is told to read.
        found = extract("node scripts/x.js\nsee [x](scripts/x.js)")
        assert found == {"scripts/x.js": "executed"}


class TestRejectsWhatIsNotShipped:
    @pytest.mark.parametrize(
        "text",
        [
            # Remote code is not a file the registry serves for this skill.
            "curl -fsSL https://example.com/install.sh | sh",
            "irm https://cdn.example.com/install.ps1 | iex",
            # The user's own machine, not the skill package.
            "Edit your ~/.bashrc file",
            "bash /etc/init.d/thing.sh",
            # Escaping the package.
            "node ../../../etc/passwd.js",
            # Already scanned, or not part of the skill.
            "See the README.md for more",
            "the SKILL.md frontmatter",
            "check package.json",
            "run node node_modules/.bin/thing.js",
            # Prose that merely resembles a path.
            "This skill handles e.g. tax and billing",
            "version 2.0.1 shipped",
        ],
    )
    def test_non_shipped_paths_are_ignored(self, text):
        assert extract(text) == {}

    def test_absolute_and_remote_paths_are_cleaned_out(self):
        assert clean_path("/etc/passwd") is None
        assert clean_path("~/.ssh/id_rsa") is None
        assert clean_path("https://evil.example/x.js") is None
        assert clean_path("../../secrets.py") is None

    def test_skill_dir_and_dot_slash_prefixes_are_normalised(self):
        assert clean_path("${SKILL_DIR}/scripts/a.js") == "scripts/a.js"
        assert clean_path("./scripts/a.js") == "scripts/a.js"


class TestExecutableClassification:
    @pytest.mark.parametrize(
        "path", ["scripts/a.js", "b.py", "tools/c.sh", "d.mjs", "e.rb", "f.PY"]
    )
    def test_code_is_executable(self, path):
        assert is_executable(path)

    @pytest.mark.parametrize(
        "path", ["references/a.md", "b.json", "c.yaml", "d.toml", "noextension"]
    )
    def test_prose_and_config_are_not(self, path):
        assert not is_executable(path)


class TestRealWorldSkillFiles:
    """Whole-file behaviour on text taken from live skills."""

    def test_buddy_card_names_both_scripts(self):
        text = (
            "BUDDY_JSON=$(node ${SKILL_DIR}/scripts/buddy-algorithm.js \"$UUID\")\n"
            "bun ${SKILL_DIR}/scripts/generate-image.ts --prompt \"<P>\" --image out.jpg\n"
            "If bun is not installed, use: `npx -y bun ${SKILL_DIR}/scripts/generate-image.ts ...`\n"
        )
        assert extract(text) == {
            "scripts/buddy-algorithm.js": "executed",
            "scripts/generate-image.ts": "executed",
        }

    def test_a_skill_that_ships_nothing_yields_nothing(self):
        # The common case. A skill that is purely instructions must not be
        # counted toward the unread surface.
        text = (
            "# Code Formatter\n\n"
            "Format the user's code. Ask before rewriting whole files.\n"
            "Prefer the project's existing style over your own.\n"
        )
        assert extract(text) == {}
