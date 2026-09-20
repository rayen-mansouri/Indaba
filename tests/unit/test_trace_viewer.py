from pathlib import Path

VIEWER = Path(__file__).resolve().parents[2] / "observability" / "sentinel-trace-viewer.html"


def test_viewer_exposes_decision_evidence_and_current_state_field() -> None:
    body = VIEWER.read_text(encoding="utf-8")
    for evidence in ("risk_score", "confidence", "dependency_count", "risk_basis", "replacement"):
        assert evidence in body
    assert "new_state_version" in body
    assert "resulting_state_version" not in body


def test_viewer_has_all_outcome_filters() -> None:
    body = VIEWER.read_text(encoding="utf-8")
    for outcome in ("allow", "block", "escalate", "rewrite"):
        assert f'data-filter="{outcome}"' in body


def test_viewer_has_offline_presenter_and_comparison_features() -> None:
    body = VIEWER.read_text(encoding="utf-8")
    for feature in (
        "showOpenFilePicker",
        "Presenter mode",
        "Paired comparison",
        "Scorecards",
        "Captions",
        "rewrite_revalidation_gates",
        "simulated approver",
        "Risk severity",
        "not probability",
        "Authority-source check",
    ):
        assert feature in body
    assert "fetch(" not in body
    assert "permit stage is shown" in body
