"""
Structural integrity tests for payment-knowledge-base.md.

The KB is served verbatim as the payment://knowledge-base MCP resource, and its
entries are YAML so agents can extract structured claims. A block that fails to
parse silently degrades into prose the moment a consumer tries to treat it as
data — these tests make that a named failure instead.

Scope is deliberately narrow: parseability and id uniqueness. Provenance and
relationship hygiene are editorial concerns handled at review time.
"""

import re
from pathlib import Path

import pytest
import yaml

_KB_PATH = Path(__file__).parent.parent / "payment-knowledge-base.md"


def _yaml_blocks():
    text = _KB_PATH.read_text(encoding="utf-8")
    return re.findall(r"```yaml\n(.*?)```", text, re.S)


@pytest.fixture(scope="module")
def parsed_blocks():
    blocks = []
    for i, raw in enumerate(_yaml_blocks()):
        id_match = re.search(r"^id: (.+)$", raw, re.M)
        label = id_match.group(1).strip() if id_match else f"<block {i}>"
        blocks.append((label, raw))
    return blocks


class TestKbYamlIntegrity:
    def test_every_yaml_block_parses(self, parsed_blocks):
        failures = {}
        for label, raw in parsed_blocks:
            try:
                yaml.safe_load(raw)
            except yaml.YAMLError as e:
                mark = getattr(e, "problem_mark", None)
                failures[label] = f"line {mark.line + 1}" if mark else str(e)[:80]
        assert not failures, (
            f"KB YAML blocks fail to parse: {failures}. Usual culprit is an "
            "unquoted 'word:' followed by a space inside a plain scalar — "
            "use an em-dash or quote the string."
        )

    def test_entry_ids_are_unique(self, parsed_blocks):
        seen, dupes = {}, {}
        for _label, raw in parsed_blocks:
            try:
                doc = yaml.safe_load(raw)
            except yaml.YAMLError:
                continue  # reported by the parse test
            if isinstance(doc, dict) and isinstance(doc.get("id"), str):
                entry_id = doc["id"]
                if entry_id in seen:
                    dupes[entry_id] = dupes.get(entry_id, 1) + 1
                seen[entry_id] = True
        assert not dupes, f"Duplicate KB entry ids: {dupes}"
