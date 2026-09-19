"""Immutable, hash-bound policy snapshots for one run."""

from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sentinel.core.policies import Policy
from sentinel.firewall.toolspecs import ToolManifest


class PolicySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str = Field(min_length=1, max_length=160)
    policy_id: str
    policy_version: int = Field(ge=1)
    allowed_tools: tuple[str, ...]
    manifest_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    canonical_policy_json: str
    policy_hash: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def _hash_matches(self) -> PolicySnapshot:
        if self.policy_hash != _policy_hash(
            self.run_id,
            self.policy_id,
            self.policy_version,
            self.allowed_tools,
            self.manifest_hash,
            self.canonical_policy_json,
        ):
            raise ValueError("policy hash does not match snapshot contents")
        return self

    @classmethod
    def capture(
        cls,
        run_id: str,
        policy: Policy,
        manifest: ToolManifest,
        allowed_tools: tuple[str, ...],
    ) -> PolicySnapshot:
        unknown = sorted(set(allowed_tools) - {spec.name for spec in manifest.specs})
        if unknown:
            raise ValueError(f"policy snapshot contains unknown allowed tools: {unknown}")
        normalized_tools = tuple(sorted(set(allowed_tools)))
        canonical = json.dumps(policy.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        digest = _policy_hash(
            run_id,
            policy.id,
            policy.version,
            normalized_tools,
            manifest.manifest_hash,
            canonical,
        )
        return cls(
            run_id=run_id,
            policy_id=policy.id,
            policy_version=policy.version,
            allowed_tools=normalized_tools,
            manifest_hash=manifest.manifest_hash,
            canonical_policy_json=canonical,
            policy_hash=digest,
        )


def _policy_hash(
    run_id: str,
    policy_id: str,
    version: int,
    allowed_tools: tuple[str, ...],
    manifest_hash: str,
    canonical: str,
) -> str:
    payload = {
        "run_id": run_id,
        "policy_id": policy_id,
        "policy_version": version,
        "allowed_tools": allowed_tools,
        "manifest_hash": manifest_hash,
        "policy": json.loads(canonical),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
