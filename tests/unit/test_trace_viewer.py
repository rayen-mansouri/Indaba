from pathlib import Path

VIEWER = Path(__file__).resolve().parents[2] / "observability" / "sentinel-trace-viewer.html"


def test_viewer_exposes_decision_evidence_and_current_state_field() -> None:
    body = VIEWER.read_text(encoding="utf-8")
    for evidence in ("risk_score", "confidence", "dependency_count", "risk_basis", "replacement"):
        assert evidence in body
    assert "payload.new_state_version" in body
    assert "payload.resulting_state_version" not in body


def test_viewer_has_all_outcome_filters() -> None:
    body = VIEWER.read_text(encoding="utf-8")
    for outcome in ("allow", "block", "escalate", "rewrite"):
        assert f'data-filter="{outcome}"' in body
