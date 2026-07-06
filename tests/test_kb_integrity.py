"""
Structural integrity tests for payment-knowledge-base.md.

The KB is served verbatim as the payment://knowledge-base MCP resource, and its
entries are YAML so agents can extract structured claims. A block that fails to
parse silently degrades into prose the moment a consumer tries to treat it as
data — these tests make that a named failure instead.

Scope: parseability, id uniqueness, and provenance. Every entry must be
traceable to a source — a non-empty references: list or an explicit inline
citation. Uncited claims fail CI.
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

    def test_every_entry_cites_a_source(self, parsed_blocks):
        """No uncited claims: each entry needs references: or an inline citation.

        The inline-citation pattern accepts the KB's established prose
        conventions ("Source: PUGD0537-004 p.488", "Verified live against APC",
        "per PCI PIN v3.1", "EMV Book 2 Annex A1", ...). New entries should
        prefer the structured references: list pointing at the Sources ledger.
        """
        inline_citation = re.compile(
            r"(?i)\b(source|verified|per PCI|per ISO|per EMV|PUGD\d|X9\.|ISO \d{4,5}"
            r"|EMV Book|Annex|FAQ|whitepaper|API reference|aws-samples|docs\.aws"
            r"|sources ledger)\b"
        )
        uncited = []
        for _label, raw in parsed_blocks:
            try:
                doc = yaml.safe_load(raw)
            except yaml.YAMLError:
                continue  # reported by the parse test
            if not isinstance(doc, dict) or not isinstance(doc.get("id"), str):
                continue
            if doc["id"] == "string":
                continue  # the canonical-shape template block
            if doc.get("references") or inline_citation.search(raw):
                continue
            uncited.append(doc["id"])
        assert not uncited, (
            f"KB entries with no provenance: {uncited}. Add a references: list "
            "naming a Sources-ledger row, public standard, or verification "
            "event (see the Canonical Record Shape section)."
        )

    def test_ledger_citations_resolve(self):
        """Every 'Sources ledger <date>' citation must match a real ledger row.

        The Sources table at the end of the KB is the provenance anchor; a
        citation pointing at a date with no ingestion row is a broken pointer
        (typo, or someone cited the ledger without adding the row).
        """
        text = _KB_PATH.read_text(encoding="utf-8")
        ledger_dates = set()
        for row in re.findall(r"^\| ([0-9/ ()a-z-]+?) \|", text, re.M):
            ledger_dates.update(re.findall(r"\d{4}-\d{2}-\d{2}", row))
        assert ledger_dates, "Sources ledger table not found or has no dated rows"
        broken = sorted(
            {
                date
                for date in re.findall(r"Sources ledger (\d{4}-\d{2}-\d{2})", text)
                if date not in ledger_dates
            }
        )
        assert not broken, (
            f"Citations reference Sources-ledger dates with no matching row: "
            f"{broken}. Add the ingestion row or fix the citation date."
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
