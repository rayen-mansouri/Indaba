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
from sentinel.firewall.runtime import GuardedPreparation, SentinelFirewallDefense
from sentinel.firewall.toolspecs import ToolManifest, ToolSpec, build_official_tool_manifest
from sentinel.firewall.trace import TraceContinuityReport, TraceIntegrityError, verify_digest_linked_trace

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
    "GuardedPreparation",
    "NormalizedAction",
    "PolicySnapshot",
    "ProvenanceGraph",
    "SentinelFirewallDefense",
    "SourceNode",
    "TaskScope",
    "ToolManifest",
    "ToolSpec",
    "TraceContinuityReport",
    "TraceIntegrityError",
    "TrustedActionAdapters",
    "WorkflowState",
    "build_official_tool_manifest",
    "verify_digest_linked_trace",
]
