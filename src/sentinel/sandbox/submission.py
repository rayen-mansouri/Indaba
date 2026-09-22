"""Optional static checks for a team's defense solution."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import httpx
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sentinel.core.actions import ActionType, CandidateAction, DefenseDecision
from sentinel.core.local_transport import LocalTransportError, require_loopback_url
from sentinel.defenses.interface import DefenseRequest

MANIFEST_NAME = "sentinel-submission.yaml"
MAX_FILE_BYTES = 50_000_000
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(api[_-]?key|secret[_-]?key|password)\s*[:=]\s*['\"][^'\"\s]{12,}['\"]"),
)
FORBIDDEN_FILENAMES = {".env", "id_rsa", "id_ed25519", ".netrc", ".npmrc", ".pypirc"}
SKIP_DIRS = {".git", ".venv", "__pycache__", "node_modules", ".mypy_cache", ".ruff_cache", ".pytest_cache"}


class ModelDeclaration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    source: str
    license: str


class Resources(BaseModel):
    model_config = ConfigDict(extra="forbid")
    memory: str = Field(default="2g", pattern=r"^[1-9]\d{0,5}[mg]$")
    cpus: float = Field(default=1.0, gt=0, le=64)
    gpus: int = Field(default=0, ge=0, le=8)


class SubmissionManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{1,63}$")
    kind: Literal["defense"] = "defense"
    api_version: Literal["v1"] = "v1"
    port: int = Field(default=8080, ge=1024, le=65535)
    team: str = Field(min_length=1, max_length=80)
    models: list[ModelDeclaration] = Field(default_factory=list)
    datasets: list[ModelDeclaration] = Field(default_factory=list)
    resources: Resources = Field(default_factory=Resources)
    description: str = Field(default="", max_length=2_000)


@dataclass
class Check:
    name: str
    status: Literal["pass", "warn", "fail"]
    detail: str = ""


@dataclass
class SubmissionReport:
    target: str
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(check.status != "fail" for check in self.checks)

    def add(self, name: str, status: Literal["pass", "warn", "fail"], detail: str = "") -> None:
        self.checks.append(Check(name, status, detail))

    def to_dict(self) -> dict[str, Any]:
        return {"target": self.target, "ok": self.ok, "checks": [check.__dict__ for check in self.checks]}


def _dockerfile_user(text: str) -> str | None:
    users = re.findall(r"(?im)^\s*USER\s+(\S+)", text)
    return users[-1] if users else None


def _check_directory(path: Path, report: SubmissionReport) -> None:
    dockerfile = path / "Dockerfile"
    if not dockerfile.is_file():
        report.add("dockerfile", "fail", "Dockerfile not found at submission root")
    else:
        text = dockerfile.read_text(errors="replace")
        user = _dockerfile_user(text)
        if user is None:
            report.add("non_root_user", "fail", "Dockerfile has no USER instruction")
        elif user.split(":")[0] in ("root", "0"):
            report.add("non_root_user", "fail", f"final USER is {user!r}")
        else:
            report.add("non_root_user", "pass", f"USER {user}")
        if "docker.sock" in text or "--privileged" in text:
            report.add("dockerfile_privileges", "fail", "Dockerfile references docker.sock or privileged mode")
        else:
            report.add("dockerfile_privileges", "pass")

    manifest_path = path / MANIFEST_NAME
    if not manifest_path.is_file():
        report.add("manifest", "fail", f"{MANIFEST_NAME} not found")
    else:
        try:
            manifest = SubmissionManifest.model_validate(yaml.safe_load(manifest_path.read_text()))
            report.add(
                "manifest",
                "pass",
                f"{manifest.name}: {len(manifest.models)} model(s), {len(manifest.datasets)} dataset(s)",
            )
        except (ValidationError, yaml.YAMLError) as exc:
            report.add("manifest", "fail", f"invalid manifest: {str(exc)[:300]}")

    secrets: list[str] = []
    large: list[str] = []
    escapes: list[str] = []
    root = path.resolve()
    for file in path.rglob("*"):
        if any(part in SKIP_DIRS for part in file.relative_to(path).parts):
            continue
        rel = str(file.relative_to(path))
        if file.is_symlink() and not file.resolve().is_relative_to(root):
            escapes.append(rel)
            continue
        if not file.is_file():
            continue
        if file.name in FORBIDDEN_FILENAMES or file.suffix in (".pem", ".key"):
            secrets.append(rel)
            continue
        size = file.stat().st_size
        if size > MAX_FILE_BYTES:
            large.append(rel)
            continue
        if size > 2_000_000:
            continue
        text = file.read_text(errors="ignore")
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            secrets.append(rel)
    report.add("no_secrets", "fail" if secrets else "pass", ", ".join(secrets[:10]))
    report.add("no_escaping_symlinks", "fail" if escapes else "pass", ", ".join(escapes[:10]))
    report.add(
        "file_sizes",
        "warn" if large else "pass",
        f"large files (declare model weights in the manifest): {', '.join(large[:5])}" if large else "",
    )


def _build_inspect_command(image: str) -> list[str]:
    return ["docker", "image", "inspect", image]


def _check_image(image: str, report: SubmissionReport) -> None:
    if shutil.which("docker") is None:
        report.add("image", "fail", "docker CLI not available to inspect the image")
        return
    completed = subprocess.run(
        _build_inspect_command(image),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        report.add("image", "fail", completed.stderr.strip()[:300] or "image not found")
        return
    config = json.loads(completed.stdout)[0].get("Config", {})
    user = str(config.get("User") or "")
    if not user or user.split(":")[0] in ("root", "0"):
        report.add("non_root_user", "fail", f"image user is {user or 'root (unset)'}")
    else:
        report.add("non_root_user", "pass", f"User {user}")
    report.add("image", "pass", image)


def sample_defense_request() -> DefenseRequest:
    return DefenseRequest(
        run_id="contract-test",
        step_id=1,
        user_goal="Summarize ticket TCK-000.",
        candidate_action=CandidateAction(
            type=ActionType.TOOL_CALL, tool="ticket_read", arguments={"ticket_id": "TCK-000"}
        ),
        policy_context={"allowed_tools": ["ticket_read"], "consequential_tools": []},
    )


def _check_live(url: str, report: SubmissionReport, transport: httpx.BaseTransport | None = None) -> None:
    try:
        base_url = require_loopback_url(url, label="live defense URL")
    except LocalTransportError as exc:
        report.add("live_service", "fail", str(exc))
        return
    with httpx.Client(base_url=base_url, timeout=10.0, transport=transport) as client:
        try:
            health = client.get("/healthz")
            report.add("live_healthz", "pass" if health.status_code == 200 else "fail", f"HTTP {health.status_code}")
            response = client.post("/v1/decision", json=sample_defense_request().model_dump(mode="json"))
            try:
                DefenseDecision.model_validate_json(response.content)
                report.add("live_decision_contract", "pass")
            except ValidationError as exc:
                report.add("live_decision_contract", "fail", f"HTTP {response.status_code}: {str(exc)[:200]}")
            bad = client.post("/v1/decision", json={"run_id": "x"})
            report.add(
                "live_rejects_malformed",
                "pass" if 400 <= bad.status_code < 500 else "warn",
                f"HTTP {bad.status_code}",
            )
        except httpx.TransportError as exc:
            report.add("live_service", "fail", f"could not reach {url}: {type(exc).__name__}")


def validate_submission(
    target: str, live_url: str | None = None, transport: httpx.BaseTransport | None = None
) -> SubmissionReport:
    report = SubmissionReport(target=target)
    path = Path(target)
    if path.is_dir():
        _check_directory(path, report)
    elif path.exists():
        report.add("target", "fail", "target must be a directory or a Docker image reference")
    else:
        _check_image(target, report)
    if live_url:
        _check_live(live_url, report, transport)
    return report
