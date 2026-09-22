from pathlib import Path

import pytest

from sentinel.sandbox.submission import validate_submission
from tests.conftest import ROOT


def statuses(report) -> dict[str, str]:  # type: ignore[no-untyped-def]
    return {check.name: check.status for check in report.checks}


def test_starter_kits_pass_static_validation() -> None:
    assert validate_submission(str(ROOT / "starter-kits" / "python-defense")).ok
    assert validate_submission(str(ROOT / "starter-kits" / "learned-monitor")).ok


def test_bad_submission_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nUSER root\nVOLUME /var/run/docker.sock\n")
    (tmp_path / "sentinel-submission.yaml").write_text("name: Bad Name\nkind: defense\n")
    (tmp_path / ".env").write_text("TOKEN=x")
    (tmp_path / "config.py").write_text('api_key = "abcdefghijklmnopqrstuvwxyz"\n')
    try:
        (tmp_path / "escape").symlink_to("/etc")
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows symlink privilege is unavailable")
        raise
    report = validate_submission(str(tmp_path))
    result = statuses(report)
    assert not report.ok
    for name in (
        "non_root_user",
        "dockerfile_privileges",
        "manifest",
        "no_secrets",
        "no_escaping_symlinks",
    ):
        assert result[name] == "fail", name


def test_missing_user_instruction_fails(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\n")
    assert statuses(validate_submission(str(tmp_path)))["non_root_user"] == "fail"


def test_file_target_is_rejected(tmp_path: Path) -> None:
    file = tmp_path / "x.txt"
    file.write_text("x")
    assert statuses(validate_submission(str(file)))["target"] == "fail"


def test_submission_rejects_a_non_local_live_service(tmp_path: Path) -> None:
    report = validate_submission(str(tmp_path), live_url="https://example.invalid")
    assert statuses(report)["live_service"] == "fail"
