"""Trusted, deterministic action-firewall primitives."""

from sentinel.firewall.approvals import ApprovalRecord, ApprovalStatus, ApprovalStore
from sentinel.firewall.gates import GateEvaluation, GateEvaluator, GateName, GateResult
from sentinel.firewall.normalization import DestinationMap, TrustedActionAdapters
from sentinel.firewall.policy import PolicySnapshot
from sentinel.firewall.provenance import ProvenanceGraph
from sentinel.firewall.records import (
    AuthenticatedPrincipal,
    CapabilityGrant,
    DataSensitivity,
    DecisionContext,
    NormalizedAction,
    SourceNode,
    TaskScope,
    WorkflowState,
)
from sentinel.firewall.toolspecs import ToolManifest, ToolSpec, build_official_tool_manifest

__all__ = [
    "ApprovalRecord",
    "ApprovalStatus",
    "ApprovalStore",
    "AuthenticatedPrincipal",
    "CapabilityGrant",
    "DataSensitivity",
    "DecisionContext",
    "DestinationMap",
    "GateEvaluation",
    "GateEvaluator",
    "GateName",
    "GateResult",
    "NormalizedAction",
    "PolicySnapshot",
    "ProvenanceGraph",
    "SourceNode",
    "TaskScope",
    "ToolManifest",
    "ToolSpec",
    "TrustedActionAdapters",
    "WorkflowState",
    "build_official_tool_manifest",
]
