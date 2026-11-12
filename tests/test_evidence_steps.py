"""Tests for the ordered evidence/reproduction sequence on findings.

Covers the normalizer and the markdown renderer, a round-trip through
``ReportState`` into ``vulnerabilities.json`` and the per-finding markdown, and
the update path that revises the sequence on an already-filed finding.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from strix.report.state import ReportState, set_global_report_state
from strix.report.writer import render_evidence_steps, render_vulnerability_md
from strix.tools.reporting.tool import (
    _MAX_EVIDENCE_STEPS,
    _collect_update_changes,
    _normalize_evidence_steps,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReportState:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="test-run")
    set_global_report_state(state)
    return state


_GOOD_STEP = {
    "action": "Open the search page with an XSS payload in q",
    "command": "agent-browser open 'http://t/#/search?q=<img src=x onerror=alert(1)>'",
    "command_lang": "Bash",
    "output": "alert(1) fired; marker rendered in the DOM",
    "screenshot": "xss-proof.png",
}


def test_normalize_keeps_valid_step_and_lowercases_lang() -> None:
    steps, errors = _normalize_evidence_steps([_GOOD_STEP])
    assert errors == []
    assert steps is not None
    step = steps[0]
    assert step["action"] == _GOOD_STEP["action"]
    assert step["command"] == _GOOD_STEP["command"]
    assert step["command_lang"] == "bash"
    assert step["screenshot"] == "xss-proof.png"


def test_normalize_reduces_screenshot_path_to_basename() -> None:
    steps, errors = _normalize_evidence_steps(
        [{"action": "shot", "screenshot": "/workspace/.agent-browser-screenshots/ok.png"}]
    )
    assert errors == []
    assert steps is not None
    assert steps[0]["screenshot"] == "ok.png"


def test_normalize_rejects_empty_action() -> None:
    steps, errors = _normalize_evidence_steps([{"action": "   ", "command": "noop"}])
    assert steps is None
    assert any("action is required" in e for e in errors)


def test_normalize_rejects_traversal_screenshot() -> None:
    _, errors = _normalize_evidence_steps([{"action": "x", "screenshot": "../../etc/passwd"}])
    assert any("screenshot must be" in e for e in errors)


def test_normalize_rejects_non_image_screenshot() -> None:
    _, errors = _normalize_evidence_steps([{"action": "x", "screenshot": "notes.txt"}])
    assert any("screenshot must be" in e for e in errors)


def test_normalize_rejects_non_dict_step() -> None:
    _, errors = _normalize_evidence_steps(["nope"])
    assert any("must be an object" in e for e in errors)


def test_normalize_none_and_non_list() -> None:
    assert _normalize_evidence_steps(None) == (None, [])
    steps, errors = _normalize_evidence_steps({"not": "a list"})
    assert steps is None
    assert any("must be a list" in e for e in errors)


def test_normalize_enforces_step_cap() -> None:
    raw = [{"action": f"step {i}"} for i in range(_MAX_EVIDENCE_STEPS + 5)]
    _, errors = _normalize_evidence_steps(raw)
    assert any("at most" in e for e in errors)


def test_renderer_emits_numbered_steps_with_screenshot_link() -> None:
    steps, _ = _normalize_evidence_steps([_GOOD_STEP, {"action": "Confirm the DOM sink"}])
    md = "\n".join(render_evidence_steps(steps))
    assert "## Reproduction Steps" in md
    assert "**1. Open the search page with an XSS payload in q**" in md
    assert "**2. Confirm the DOM sink**" in md
    # Screenshot resolves against the exported evidence dir, one level up from
    # the per-finding markdown in vulnerabilities/.
    assert "![Open the search page with an XSS payload in q]" in md
    assert "../evidence/screenshots/xss-proof.png" in md


def test_renderer_empty_is_nothing() -> None:
    assert render_evidence_steps([]) == []
    assert render_evidence_steps("not a list") == []


def test_round_trip_through_state_and_markdown(report_state: ReportState) -> None:
    steps, _ = _normalize_evidence_steps([_GOOD_STEP])
    report_id = report_state.add_vulnerability_report(
        title="Reflected DOM XSS in search",
        severity="medium",
        target="http://localhost:3000",
        evidence_steps=steps,
    )
    stored = next(r for r in report_state.get_existing_vulnerabilities() if r["id"] == report_id)
    assert stored["evidence_steps"][0]["screenshot"] == "xss-proof.png"

    md = render_vulnerability_md(stored)
    assert "## Reproduction Steps" in md
    assert "../evidence/screenshots/xss-proof.png" in md

    # Persisted to vulnerabilities.json verbatim.
    run_dir = report_state.get_run_dir()
    data = json.loads((run_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
    persisted = next(r for r in data if r["id"] == report_id)
    assert persisted["evidence_steps"][0]["action"] == _GOOD_STEP["action"]


def test_update_collector_accepts_and_validates_steps() -> None:
    changes, errors = _collect_update_changes({"evidence_steps": [_GOOD_STEP]})
    assert errors == []
    assert changes["evidence_steps"][0]["screenshot"] == "xss-proof.png"

    changes, errors = _collect_update_changes(
        {"evidence_steps": [{"action": "x", "screenshot": "../../etc/passwd"}]}
    )
    assert "evidence_steps" not in changes
    assert any("screenshot must be" in e for e in errors)


def test_update_collector_allows_clearing_steps() -> None:
    changes, errors = _collect_update_changes({"evidence_steps": []})
    assert errors == []
    assert changes["evidence_steps"] == []
