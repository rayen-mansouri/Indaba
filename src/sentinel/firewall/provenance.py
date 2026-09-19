"""Runtime-owned provenance graph and transformation-aware observed content."""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import re
from urllib.parse import unquote

from sentinel.core.provenance import Provenance, Sensitivity, TrustLevel, least_trusted
from sentinel.firewall.records import DataSensitivity, ObservedContent, SourceNode, Transformation

_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
_HEX_TOKEN = re.compile(r"(?:[0-9a-fA-F]{2}){6,}")
_PART = re.compile(r"^\[part\s+\d+/\d+\]\s*", re.IGNORECASE)


def _sensitivity(value: Sensitivity) -> DataSensitivity:
    return DataSensitivity(value.value)


class ProvenanceGraph:
    """Issues opaque IDs and refuses derived nodes without complete parents."""

    def __init__(self, run_id: str, session_id: str) -> None:
        self.run_id = run_id
        self.session_id = session_id
        self._nodes: dict[str, SourceNode] = {}
        self._counter = 0

    @property
    def nodes(self) -> tuple[SourceNode, ...]:
        return tuple(self._nodes.values())

    def _id(self) -> str:
        material = f"{self.run_id}:{self.session_id}:{self._counter}".encode()
        self._counter += 1
        return "src_" + hashlib.sha256(material).hexdigest()[:24]

    def add_source(
        self,
        source_kind: str,
        trust_label: TrustLevel,
        sensitivity: DataSensitivity,
        allowed_destinations: tuple[TrustLevel, ...] = (),
    ) -> SourceNode:
        node = SourceNode(
            node_id=self._id(),
            run_id=self.run_id,
            session_id=self.session_id,
            source_kind=source_kind,
            trust_label=trust_label,
            sensitivity=sensitivity,
            allowed_destinations=allowed_destinations,
        )
        self._nodes[node.node_id] = node
        return node

    def import_provenance(self, provenance: Provenance) -> SourceNode:
        return self.add_source(
            source_kind=provenance.source_type.value,
            trust_label=provenance.trust_level,
            sensitivity=_sensitivity(provenance.sensitivity),
        )

    def derive(self, parent_ids: tuple[str, ...], transformation: Transformation) -> SourceNode:
        if transformation is Transformation.DIRECT:
            raise ValueError("derived nodes require a non-direct transformation")
        try:
            parents = [self._nodes[parent_id] for parent_id in parent_ids]
        except KeyError as exc:
            raise ValueError(f"unknown provenance parent {exc.args[0]!r}") from exc
        if not parents:
            raise ValueError("derived nodes require parents")
        trust = least_trusted([parent.trust_label for parent in parents])
        sensitivities = [parent.sensitivity for parent in parents]
        sensitivity = (
            DataSensitivity.UNKNOWN
            if DataSensitivity.UNKNOWN in sensitivities
            else max(sensitivities, key=lambda item: item.rank)
        )
        restricted = [set(parent.allowed_destinations) for parent in parents if parent.allowed_destinations]
        allowed = tuple(sorted(set.intersection(*restricted), key=lambda item: item.rank)) if restricted else ()
        if transformation is Transformation.UNSUPPORTED:
            trust = TrustLevel.ADVERSARY_CONTROLLED
            sensitivity = DataSensitivity.UNKNOWN
            allowed = ()
        node = SourceNode(
            node_id=self._id(),
            run_id=self.run_id,
            session_id=self.session_id,
            source_kind="transformation",
            trust_label=trust,
            sensitivity=sensitivity,
            allowed_destinations=allowed,
            parent_ids=parent_ids,
            transformation=transformation,
        )
        self._nodes[node.node_id] = node
        return node


def _decoded_tokens(text: str, pattern: re.Pattern[str], decoder: str) -> str:
    decoded: list[str] = []
    for token in pattern.findall(text):
        try:
            if decoder == "base64":
                padded = token + "=" * (-len(token) % 4)
                value = base64.b64decode(padded, validate=True).decode("utf-8")
            else:
                value = bytes.fromhex(token).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        decoded.append(value)
    return "\n".join(decoded)


def derive_observed_variants(graph: ProvenanceGraph, observed: ObservedContent) -> tuple[ObservedContent, ...]:
    """Create lineage-preserving forms used by the official obfuscation library."""
    candidates = (
        (Transformation.BASE64_DECODE, _decoded_tokens(observed.content, _B64_TOKEN, "base64")),
        (Transformation.HEX_DECODE, _decoded_tokens(observed.content, _HEX_TOKEN, "hex")),
        (Transformation.URL_DECODE, unquote(observed.content)),
        (Transformation.ROT13_DECODE, codecs.decode(observed.content, "rot13")),
        (Transformation.REVERSE, observed.content[::-1]),
        (Transformation.WHITESPACE_JOIN, re.sub(r"\s+", "", observed.content)),
    )
    variants = [observed]
    seen = {observed.content}
    for transformation, content in candidates:
        if not content or content in seen:
            continue
        node = graph.derive(observed.source_node_ids, transformation)
        variants.append(ObservedContent(content=content, source_node_ids=(node.node_id,)))
        seen.add(content)
    return tuple(variants)


def concatenate_parts(graph: ProvenanceGraph, parts: tuple[ObservedContent, ...]) -> ObservedContent:
    """Join split directives while preserving every parent source."""
    if not parts:
        raise ValueError("cannot concatenate an empty set of parts")
    parent_ids = tuple(dict.fromkeys(node_id for part in parts for node_id in part.source_node_ids))
    node = graph.derive(parent_ids, Transformation.CONCATENATE)
    content = "".join(_PART.sub("", part.content) for part in parts)
    return ObservedContent(content=content, source_node_ids=(node.node_id,))
