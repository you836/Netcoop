"""Deterministic network topology and connectivity scope analysis for NetCoop AI (Agent 3)."""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping, Sequence
from datetime import datetime
from time import perf_counter
from typing import Any, Optional, Union
from uuid import UUID

from pydantic import Field, ValidationError, field_validator, model_validator

from .common import (
    AgentError,
    AgentFinding,
    AgentName,
    AgentResponse,
    ErrorCode,
    Evidence,
    EvidenceType,
    ExecutionStatus,
    FindingType,
    ProtocolBaseModel,
    Severity,
    ensure_utc_timestamp,
    utc_now,
)

# =====================================================================
# 1. CONSTANTS & RECOGNIZED TOPOLOGY ENUMERATIONS
# =====================================================================

RECOGNIZED_DEVICE_TYPES: frozenset[str] = frozenset(
    {
        "router",
        "switch",
        "core_switch",
        "distribution_switch",
        "aggregation_switch",
        "access_switch",
        "l3_switch",
        "access_point",
        "wireless_controller",
        "firewall",
        "load_balancer",
        "server",
        "host",
        "gateway",
        "modem",
        "optical_transport",
        "unknown",
    }
)

BIDIRECTIONAL_LINK_TYPES: frozenset[str] = frozenset(
    {
        "physical",
        "ethernet",
        "fiber",
        "lldp",
        "cdp",
        "trunk",
        "access",
        "lag",
        "port_channel",
        "wan",
        "wireless",
        "bidirectional",
        "p2p",
    }
)

DIRECTED_LINK_TYPES: frozenset[str] = frozenset(
    {
        "directed",
        "unidirectional",
        "static_route",
        "route",
        "bgp_peer",
        "ospf_neighbor",
        "uplink",
        "downlink",
        "tunnel",
        "dependency",
    }
)

RECOGNIZED_LINK_TYPES: frozenset[str] = BIDIRECTIONAL_LINK_TYPES | DIRECTED_LINK_TYPES

ACTIVE_LINK_STATUSES: frozenset[str] = frozenset({"up", "active", "online", "healthy", "ok", "connected", "forwarding"})
DEGRADED_LINK_STATUSES: frozenset[str] = frozenset({"degraded", "warning", "flapping", "impaired"})
BLOCKED_OR_STANDBY_LINK_STATUSES: frozenset[str] = frozenset({"blocked", "stp_blocked", "standby", "backup", "alternate", "discarding"})
DOWN_LINK_STATUSES: frozenset[str] = frozenset({"down", "failed", "offline", "disconnected", "cut", "unreachable", "admin_down", "shutdown"})

RECOGNIZED_LINK_STATUSES: frozenset[str] = (
    ACTIVE_LINK_STATUSES
    | DEGRADED_LINK_STATUSES
    | BLOCKED_OR_STANDBY_LINK_STATUSES
    | DOWN_LINK_STATUSES
)


# =====================================================================
# 2. TOPOLOGY & INCIDENT CONTEXT INPUT MODELS
# =====================================================================


class TopologyDevice(ProtocolBaseModel):
    """Represents a network device node and its explicitly known segment memberships."""

    device_id: str = Field(..., min_length=1, max_length=128, description="Unique network device identifier.")
    device_type: str = Field(
        default="unknown",
        min_length=1,
        max_length=64,
        description="Device role/type (router, switch, access_point, firewall, server, etc.).",
    )
    segment_ids: list[str] = Field(
        default_factory=list,
        description="Explicitly associated network segment or VLAN IDs.",
    )
    record_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Optional topology source or inventory record ID.",
    )
    timestamp: datetime = Field(default_factory=utc_now)

    _validate_ts = field_validator("timestamp")(ensure_utc_timestamp)

    @field_validator("device_type")
    @classmethod
    def validate_device_type(cls, value: str) -> str:
        normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
        if normalized not in RECOGNIZED_DEVICE_TYPES:
            allowed = ", ".join(sorted(RECOGNIZED_DEVICE_TYPES))
            raise ValueError(f"Unrecognized device_type '{value}'. Allowed values: [{allowed}].")
        return normalized

    @field_validator("segment_ids", mode="before")
    @classmethod
    def validate_segment_ids(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError("'segment_ids' must be a list of non-empty segment ID strings.")
        cleaned: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("Each entry in 'segment_ids' must be a non-empty string.")
            seg = item.strip()
            if seg not in cleaned:
                cleaned.append(seg)
        return cleaned


class TopologyLink(ProtocolBaseModel):
    """
    Represents a physical or logical link between two devices.
    Directionality is controlled by `directed` (or inferred from `link_type` when `directed` is omitted).
    """

    link_id: str = Field(..., min_length=1, max_length=128, description="Unique link identifier.")
    source_device: str = Field(..., min_length=1, max_length=128, description="Source device ID.")
    target_device: str = Field(..., min_length=1, max_length=128, description="Target device ID.")
    source_interface: Optional[str] = Field(default=None, min_length=1, max_length=128, description="Optional source interface ID.")
    target_interface: Optional[str] = Field(default=None, min_length=1, max_length=128, description="Optional target interface ID.")
    link_type: str = Field(
        default="physical",
        min_length=1,
        max_length=64,
        description="Link classification (e.g., 'physical', 'ethernet', 'lldp', 'trunk', 'directed', 'static_route').",
    )
    status: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=64,
        description="Explicitly reported operational status ('up', 'down', 'degraded', 'blocked', 'standby'). None if unknown.",
    )
    operational_status: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=64,
        description="Alias for explicit operational status.",
    )
    directed: Optional[bool] = Field(
        default=None,
        description="If True, link is strictly directed (source -> target). If False, bidirectional. If None, inferred from link_type.",
    )
    segment_ids: list[str] = Field(
        default_factory=list,
        description="Optional VLAN/segment IDs carried on this link when explicitly known.",
    )
    evidence_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Identifier referencing the discovery record (e.g., LLDP/CDP entry or inventory ID).",
    )
    source_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Alias for evidence/source record identifier.",
    )
    record_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Alias for telemetry/topology record identifier.",
    )
    timestamp: datetime = Field(default_factory=utc_now)

    _validate_ts = field_validator("timestamp")(ensure_utc_timestamp)

    @field_validator("link_type")
    @classmethod
    def validate_link_type(cls, value: str) -> str:
        normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
        if normalized not in RECOGNIZED_LINK_TYPES:
            allowed = ", ".join(sorted(RECOGNIZED_LINK_TYPES))
            raise ValueError(f"Unrecognized link_type '{value}'. Allowed values: [{allowed}].")
        return normalized

    @field_validator("status", "operational_status")
    @classmethod
    def validate_link_status(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
        if normalized not in RECOGNIZED_LINK_STATUSES:
            allowed = ", ".join(sorted(RECOGNIZED_LINK_STATUSES))
            raise ValueError(f"Unrecognized link operational status '{value}'. Allowed values: [{allowed}].")
        return normalized

    @field_validator("segment_ids", mode="before")
    @classmethod
    def validate_segment_ids(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError("'segment_ids' must be a list of strings.")
        cleaned: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("Each entry in 'segment_ids' must be a non-empty string.")
            seg = item.strip()
            if seg not in cleaned:
                cleaned.append(seg)
        return cleaned

    @model_validator(mode="after")
    def finalize_link_semantics(self) -> TopologyLink:
        if self.source_device == self.target_device:
            raise ValueError(f"Self-loop link '{self.link_id}' on device '{self.source_device}' is invalid.")
        if self.status is None and self.operational_status is not None:
            self.status = self.operational_status
        if self.directed is None:
            self.directed = self.link_type in DIRECTED_LINK_TYPES
        if self.record_id is None:
            self.record_id = self.evidence_id or self.source_id or self.link_id
        return self


class IncidentContext(ProtocolBaseModel):
    """Incident scope context passed to the Connectivity Agent."""

    affected_device_ids: list[str] = Field(
        default_factory=list,
        description="Device IDs reported as degraded, down, or anomalous.",
    )
    affected_link_ids: list[str] = Field(
        default_factory=list,
        description="Link IDs reported as down or degraded.",
    )
    affected_segment_ids: list[str] = Field(
        default_factory=list,
        description="Segment or VLAN IDs reported as experiencing issues.",
    )
    upstream_findings: list[AgentFinding] = Field(
        default_factory=list,
        description="Upstream AgentFindings from Performance or Infrastructure agents.",
    )
    source_devices: list[str] = Field(
        default_factory=list,
        description="Optional focal/root/core devices used as reference points for reachability or path checks.",
    )
    target_devices: list[str] = Field(
        default_factory=list,
        description="Optional destination devices for reachability checks.",
    )

    @field_validator("affected_device_ids", "affected_link_ids", "affected_segment_ids", "source_devices", "target_devices", mode="before")
    @classmethod
    def validate_string_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError("Context identifier list must be a list of non-empty strings.")
        cleaned: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("Context identifier entries must be non-empty strings.")
            s = item.strip()
            if s not in cleaned:
                cleaned.append(s)
        return cleaned


class ConnectivityInput(ProtocolBaseModel):
    """Top-level structured input for the Connectivity Analysis Agent."""

    devices: list[Any] = Field(default_factory=list)
    links: list[Any] = Field(default_factory=list)
    incident_context: Optional[Union[IncidentContext, dict[str, Any]]] = None
    affected_device_ids: list[str] = Field(default_factory=list)
    affected_link_ids: list[str] = Field(default_factory=list)
    affected_segment_ids: list[str] = Field(default_factory=list)
    upstream_findings: list[Any] = Field(default_factory=list)


# =====================================================================
# 3. GRAPH REPRESENTATION & DETERMINISTIC TRAVERSAL ALGORITHMS
# =====================================================================


class TopologyGraph:
    """
    Deterministic, explicit network topology graph using Python dictionaries and adjacency lists.
    Separates physical/declared adjacency from operational/active links and preserves link directionality.
    """

    def __init__(
        self,
        devices: Optional[Sequence[TopologyDevice]] = None,
        links: Optional[Sequence[TopologyLink]] = None,
    ) -> None:
        self.devices: dict[str, TopologyDevice] = {}
        self.links: dict[str, TopologyLink] = {}
        # Adjacency list mapping device_id -> list of (neighbor_id, TopologyLink)
        self.adjacency: dict[str, list[tuple[str, TopologyLink]]] = {}
        # Reverse adjacency (incoming directed or bidirectional links)
        self.incoming_adjacency: dict[str, list[tuple[str, TopologyLink]]] = {}
        # Segment mappings
        self.segment_to_devices: dict[str, list[str]] = {}
        self.device_to_segments: dict[str, list[str]] = {}
        # Implicit devices referenced by links but missing from the explicit devices list
        self.implicit_devices: set[str] = set()

        for dev in devices or []:
            self.add_device(dev)
        for lnk in links or []:
            self.add_link(lnk)

    def add_device(self, device: TopologyDevice) -> None:
        self.devices[device.device_id] = device
        self.implicit_devices.discard(device.device_id)
        self.adjacency.setdefault(device.device_id, [])
        self.incoming_adjacency.setdefault(device.device_id, [])
        segs = self.device_to_segments.setdefault(device.device_id, [])
        for seg_id in device.segment_ids:
            if seg_id not in segs:
                segs.append(seg_id)
            dev_list = self.segment_to_devices.setdefault(seg_id, [])
            if device.device_id not in dev_list:
                dev_list.append(device.device_id)

    def add_link(self, link: TopologyLink) -> None:
        self.links[link.link_id] = link
        for endpoint in (link.source_device, link.target_device):
            if endpoint not in self.devices:
                self.implicit_devices.add(endpoint)
            self.adjacency.setdefault(endpoint, [])
            self.incoming_adjacency.setdefault(endpoint, [])
            self.device_to_segments.setdefault(endpoint, [])

        # Outgoing from source -> target
        self.adjacency[link.source_device].append((link.target_device, link))
        self.incoming_adjacency[link.target_device].append((link.source_device, link))

        # Only add reverse edge when the link is bidirectional (not directed)
        if not link.directed:
            self.adjacency[link.target_device].append((link.source_device, link))
            self.incoming_adjacency[link.source_device].append((link.target_device, link))

        # Associate link segments only when explicitly supplied on the link
        for seg_id in link.segment_ids:
            for endpoint in (link.source_device, link.target_device):
                segs = self.device_to_segments.setdefault(endpoint, [])
                if seg_id not in segs:
                    segs.append(seg_id)
                dev_list = self.segment_to_devices.setdefault(seg_id, [])
                if endpoint not in dev_list:
                    dev_list.append(endpoint)

    def has_node(self, device_id: str) -> bool:
        return device_id in self.adjacency

    @staticmethod
    def _link_usable(
        link: TopologyLink,
        usable_only: bool,
        excluded_links: set[str],
    ) -> bool:
        if link.link_id in excluded_links:
            return False
        if not usable_only:
            return True
        if link.status is not None and (
            link.status in DOWN_LINK_STATUSES or link.status in BLOCKED_OR_STANDBY_LINK_STATUSES
        ):
            return False
        return True

    def get_direct_neighbors(
        self,
        device_id: str,
        *,
        usable_only: bool = False,
        excluded_devices: Optional[set[str]] = None,
        excluded_links: Optional[set[str]] = None,
    ) -> list[str]:
        """Returns sorted direct neighbor device IDs reachable in 1 hop from `device_id`."""
        if device_id not in self.adjacency:
            return []
        ex_devs = excluded_devices or set()
        ex_links = excluded_links or set()
        neighbors: set[str] = set()
        for nbr, link in self.adjacency[device_id]:
            if nbr in ex_devs:
                continue
            if not self._link_usable(link, usable_only, ex_links):
                continue
            neighbors.add(nbr)
        return sorted(neighbors)

    def get_incident_links(self, device_id: str) -> list[TopologyLink]:
        """Returns all links where `device_id` is either source or target."""
        seen: set[str] = set()
        result: list[TopologyLink] = []
        for _, link in self.adjacency.get(device_id, []):
            if link.link_id not in seen:
                seen.add(link.link_id)
                result.append(link)
        for _, link in self.incoming_adjacency.get(device_id, []):
            if link.link_id not in seen:
                seen.add(link.link_id)
                result.append(link)
        return result

    def get_connected_devices(
        self,
        device_id: str,
        *,
        usable_only: bool = False,
        excluded_devices: Optional[set[str]] = None,
        excluded_links: Optional[set[str]] = None,
    ) -> list[str]:
        """
        Returns all devices reachable from `device_id` (excluding `device_id` itself)
        via breadth-first traversal.
        """
        if device_id not in self.adjacency:
            return []
        ex_devs = set(excluded_devices or set())
        ex_links = set(excluded_links or set())
        if device_id in ex_devs:
            return []

        visited: set[str] = {device_id}
        queue: deque[str] = deque([device_id])
        reached: list[str] = []

        while queue:
            curr = queue.popleft()
            for nbr, link in self.adjacency.get(curr, []):
                if nbr in visited or nbr in ex_devs:
                    continue
                if not self._link_usable(link, usable_only, ex_links):
                    continue
                visited.add(nbr)
                reached.append(nbr)
                queue.append(nbr)

        return sorted(reached)

    def is_reachable(
        self,
        source_device: str,
        target_device: str,
        *,
        usable_only: bool = False,
        excluded_devices: Optional[set[str]] = None,
        excluded_links: Optional[set[str]] = None,
    ) -> bool:
        """Returns True if `target_device` is reachable from `source_device`."""
        return self.find_shortest_path(
            source_device,
            target_device,
            usable_only=usable_only,
            excluded_devices=excluded_devices,
            excluded_links=excluded_links,
        ) is not None

    def find_shortest_path(
        self,
        source_device: str,
        target_device: str,
        *,
        usable_only: bool = False,
        excluded_devices: Optional[set[str]] = None,
        excluded_links: Optional[set[str]] = None,
    ) -> Optional[list[str]]:
        """Finds the shortest hop path of device IDs from `source_device` to `target_device`."""
        if source_device not in self.adjacency or target_device not in self.adjacency:
            return None
        ex_devs = set(excluded_devices or set())
        ex_links = set(excluded_links or set())
        if source_device in ex_devs or target_device in ex_devs:
            return None
        if source_device == target_device:
            return [source_device]

        visited: set[str] = {source_device}
        queue: deque[list[str]] = deque([[source_device]])

        while queue:
            path = queue.popleft()
            curr = path[-1]
            for nbr, link in self.adjacency.get(curr, []):
                if nbr in visited or nbr in ex_devs:
                    continue
                if not self._link_usable(link, usable_only, ex_links):
                    continue
                next_path = [*path, nbr]
                if nbr == target_device:
                    return next_path
                visited.add(nbr)
                queue.append(next_path)
        return None

    def find_all_simple_paths(
        self,
        source_device: str,
        target_device: str,
        *,
        usable_only: bool = False,
        excluded_devices: Optional[set[str]] = None,
        excluded_links: Optional[set[str]] = None,
        max_depth: int = 12,
    ) -> list[list[tuple[str, TopologyLink]]]:
        """
        Returns all simple edge-paths from `source_device` to `target_device`.
        Each path is a list of `(next_device_id, TopologyLink)` steps.
        """
        if source_device not in self.adjacency or target_device not in self.adjacency:
            return []
        ex_devs = set(excluded_devices or set())
        ex_links = set(excluded_links or set())
        if source_device in ex_devs or target_device in ex_devs or source_device == target_device:
            return []

        results: list[list[tuple[str, TopologyLink]]] = []

        def _dfs(curr: str, visited_nodes: set[str], current_steps: list[tuple[str, TopologyLink]]) -> None:
            if len(current_steps) >= max_depth:
                return
            for nbr, link in self.adjacency.get(curr, []):
                if nbr in visited_nodes or nbr in ex_devs:
                    continue
                if not self._link_usable(link, usable_only, ex_links):
                    continue
                next_steps = [*current_steps, (nbr, link)]
                if nbr == target_device:
                    results.append(next_steps)
                else:
                    _dfs(nbr, visited_nodes | {nbr}, next_steps)

        _dfs(source_device, {source_device}, [])
        return results

    def get_segments_for_device(self, device_id: str) -> list[str]:
        return sorted(self.device_to_segments.get(device_id, []))

    def get_devices_for_segment(self, segment_id: str) -> list[str]:
        return sorted(self.segment_to_devices.get(segment_id, []))

    def analyze_device_failure_impact(self, failed_device_id: str) -> dict[str, Any]:
        """
        Evaluates the topological blast radius if `failed_device_id` fails:
        - direct_neighbors: directly adjacent devices
        - directly_associated_segments: segments explicitly attached to `failed_device_id`
        - single_homed_neighbors: neighbors whose only connection to the rest of the component is through `failed_device_id`
        - potentially_affected_devices: union of failed_device_id, direct_neighbors, and disconnected downstream devices
        - potentially_affected_segments: segments explicitly associated with potentially affected devices
        """
        if failed_device_id not in self.adjacency:
            return {
                "known_device": False,
                "direct_neighbors": [],
                "directly_associated_segments": [],
                "isolated_devices": [],
                "potentially_affected_devices": [],
                "potentially_affected_segments": [],
            }

        baseline_component = self.get_connected_devices(failed_device_id, usable_only=True)
        direct_neighbors = self.get_direct_neighbors(failed_device_id)
        direct_segments = self.get_segments_for_device(failed_device_id)

        # Determine which devices in the connected component become disconnected from core/peer anchors
        # or lose connectivity when failed_device_id is removed
        isolated: list[str] = []
        if baseline_component:
            # Choose an anchor node outside failed_device_id (prefer a router/core_switch/firewall or highest-degree survivor)
            AnchorCandidates = sorted(
                baseline_component,
                key=lambda d: (
                    1 if (self.devices.get(d) and self.devices[d].device_type in {"router", "core_switch", "firewall", "gateway"}) else 0,
                    len(self.get_direct_neighbors(d, excluded_devices={failed_device_id})),
                    d,
                ),
                reverse=True,
            )
            anchor = AnchorCandidates[0]
            surviving_from_anchor = set(
                self.get_connected_devices(
                    anchor,
                    usable_only=True,
                    excluded_devices={failed_device_id},
                )
            ) | {anchor}
            for dev_id in baseline_component:
                if dev_id not in surviving_from_anchor:
                    isolated.append(dev_id)
                elif len(self.get_direct_neighbors(dev_id, usable_only=True, excluded_devices={failed_device_id})) == 0 and len(baseline_component) > 1:
                    if dev_id not in isolated:
                        isolated.append(dev_id)

        potentially_affected_devices = sorted({failed_device_id, *direct_neighbors, *isolated})
        potentially_affected_segments: set[str] = set(direct_segments)
        for dev_id in isolated:
            potentially_affected_segments.update(self.get_segments_for_device(dev_id))

        return {
            "known_device": True,
            "direct_neighbors": direct_neighbors,
            "directly_associated_segments": direct_segments,
            "isolated_devices": sorted(isolated),
            "potentially_affected_devices": potentially_affected_devices,
            "potentially_affected_segments": sorted(potentially_affected_segments),
        }

    def analyze_link_failure_impact(self, failed_link_id: str) -> dict[str, Any]:
        """
        Evaluates the topological impact if `failed_link_id` fails:
        - endpoints: [source_device, target_device]
        - has_alternate_physical_path: whether another physical path exists between endpoints
        - alternate_paths: list of alternate path device sequences
        - severed_devices: devices that lose all usable paths to the other endpoint
        - potentially_affected_segments: segments associated with endpoints or severed devices
        """
        link = self.links.get(failed_link_id)
        if link is None:
            return {
                "known_link": False,
                "endpoints": [],
                "has_alternate_physical_path": False,
                "alternate_paths": [],
                "severed_devices": [],
                "potentially_affected_devices": [],
                "potentially_affected_segments": [],
            }

        src, dst = link.source_device, link.target_device
        # Check physical alternate paths (regardless of forwarding state, excluding only this link)
        alt_physical_paths = self.find_all_simple_paths(
            src,
            dst,
            usable_only=False,
            excluded_links={failed_link_id},
        )
        alt_node_paths = [[src, *[step[0] for step in p]] for p in alt_physical_paths]

        # Check usable reachability without the failed link
        reachable_without_link = set(
            self.get_connected_devices(src, usable_only=True, excluded_links={failed_link_id})
        ) | {src}
        baseline_reachable = set(self.get_connected_devices(src, usable_only=False)) | {src}
        severed = sorted(baseline_reachable - reachable_without_link)

        affected_devs = sorted({src, dst, *severed})
        affected_segs: set[str] = set(link.segment_ids)
        for d in (src, dst, *severed):
            affected_segs.update(self.get_segments_for_device(d))

        return {
            "known_link": True,
            "link": link,
            "endpoints": [src, dst],
            "has_alternate_physical_path": len(alt_node_paths) > 0,
            "alternate_paths": alt_node_paths,
            "alternate_edge_paths": alt_physical_paths,
            "severed_devices": severed,
            "potentially_affected_devices": affected_devs,
            "potentially_affected_segments": sorted(affected_segs),
        }

    def find_shared_dependencies(self, target_devices: Sequence[str]) -> dict[str, list[str]]:
        """
        Identifies common upstream/adjacent dependency devices shared across 2 or more
        specified devices (or across all access/leaf devices if >= 2 share an upstream hub/articulation node).
        Returns mapping: shared_dependency_device_id -> sorted list of dependent device_ids.
        """
        valid_targets = [d for d in dict.fromkeys(target_devices) if d in self.adjacency]
        shared_map: dict[str, list[str]] = {}
        if len(valid_targets) < 2:
            return shared_map

        # 1. Direct common neighbors shared by >= 2 target devices
        neighbor_to_dependents: dict[str, set[str]] = {}
        for dev_id in valid_targets:
            for nbr in self.get_direct_neighbors(dev_id):
                neighbor_to_dependents.setdefault(nbr, set()).add(dev_id)

        for candidate, dependents in neighbor_to_dependents.items():
            if len(dependents) >= 2:
                shared_map[candidate] = sorted(dependents)

        # 2. Intermediate transit nodes appearing on all shortest paths between pairs of target devices
        for i in range(len(valid_targets)):
            for j in range(i + 1, len(valid_targets)):
                d1, d2 = valid_targets[i], valid_targets[j]
                all_paths = self.find_all_simple_paths(d1, d2, usable_only=True)
                if not all_paths:
                    continue
                intermediate_sets = [
                    {step[0] for step in path[:-1]} - {d1, d2}
                    for path in all_paths
                ]
                common_transit = set.intersection(*intermediate_sets) if intermediate_sets else set()
                for transit_node in common_transit:
                    deps = set(shared_map.get(transit_node, [])) | {d1, d2}
                    shared_map[transit_node] = sorted(deps)

        return shared_map


# =====================================================================
# 4. CONNECTIVITY ANALYSIS AGENT
# =====================================================================


class ConnectivityAgent:
    """
    Agent 3: Connectivity Analysis Agent.

    Analyzes network topology, device adjacency, multi-hop reachability,
    segment associations, blast radius of device/link issues, shared dependencies,
    and alternate physical paths while strictly distinguishing physical adjacency
    from verified forwarding reachability.
    """

    agent_name = AgentName.CONNECTIVITY

    @staticmethod
    def _make_error(code: ErrorCode, message: str, **details: Any) -> AgentError:
        return AgentError(
            error_code=code,
            message=message,
            source_agent=AgentName.CONNECTIVITY,
            retryable=False,
            details=details,
        )

    def analyze(
        self,
        topology_input: Union[Mapping[str, Any], ConnectivityInput, TopologyGraph],
        incident_context: Optional[Union[Mapping[str, Any], IncidentContext]] = None,
    ) -> AgentResponse:
        """
        Executes deterministic connectivity and topology scope analysis.
        """
        started = perf_counter()
        findings: list[AgentFinding] = []
        errors: list[AgentError] = []
        warnings: list[str] = []
        completed_checks: list[str] = []

        if isinstance(topology_input, TopologyGraph):
            graph = topology_input
            ctx = self._parse_incident_context(incident_context, errors)
            raw_devices_count = len(graph.devices)
            raw_links_count = len(graph.links)
        else:
            parsed = self._parse_and_build_graph(
                topology_input=topology_input,
                explicit_context=incident_context,
                findings=findings,
                errors=errors,
                warnings=warnings,
                completed_checks=completed_checks,
            )
            if parsed is None:
                return AgentResponse(
                    agent_name=AgentName.CONNECTIVITY,
                    status=ExecutionStatus.FAILED,
                    errors=errors,
                    processing_time_ms=(perf_counter() - started) * 1000,
                    execution_metadata={"devices_loaded": 0, "links_loaded": 0},
                )
            graph, ctx, raw_devices_count, raw_links_count = parsed

        # Merge affected devices/segments from upstream_findings if provided
        upstream_finding_ids: list[UUID] = []
        for uf in ctx.upstream_findings:
            upstream_finding_ids.append(uf.finding_id)
            for dev_id in uf.affected_devices:
                if dev_id not in ctx.affected_device_ids:
                    ctx.affected_device_ids.append(dev_id)
            for seg_id in uf.affected_segments:
                if seg_id not in ctx.affected_segment_ids:
                    ctx.affected_segment_ids.append(seg_id)

        # Also automatically inspect links explicitly marked down/degraded in topology
        for link_id, link in graph.links.items():
            if link.status in DOWN_LINK_STATUSES or link.status in DEGRADED_LINK_STATUSES:
                if link_id not in ctx.affected_link_ids:
                    ctx.affected_link_ids.append(link_id)

        # Check if topology is completely empty
        if not graph.devices and not graph.links:
            if not errors:
                errors.append(
                    self._make_error(
                        ErrorCode.MISSING_TOPOLOGY,
                        "No valid topology devices or links were supplied for connectivity analysis.",
                    )
                )
            return AgentResponse(
                agent_name=AgentName.CONNECTIVITY,
                status=ExecutionStatus.FAILED,
                errors=errors,
                processing_time_ms=(perf_counter() - started) * 1000,
                execution_metadata={
                    "devices_received": raw_devices_count,
                    "links_received": raw_links_count,
                    "devices_loaded": 0,
                    "links_loaded": 0,
                },
            )

        # Flag incomplete topology if links exist without device definitions or devices have zero links
        if graph.implicit_devices:
            implicit_sorted = sorted(graph.implicit_devices)
            warnings.append(
                f"Incomplete device inventory: link endpoints {implicit_sorted} were referenced in links "
                f"without explicit device records (device_type and segment_ids unknown for these nodes)."
            )
            completed_checks.append("topology_completeness_check")

        if graph.devices and not graph.links:
            warnings.append(
                "Incomplete topology: device records were supplied without any interconnecting links; "
                "adjacency and multi-hop path analysis are limited to segment membership."
            )
            completed_checks.append("topology_completeness_check")

        # 1. Adjacency & Direct Neighbor checks
        for dev_id in sorted(graph.adjacency.keys()):
            completed_checks.append(f"adjacency:{dev_id}")

        # 2. Segment-to-device relationship checks
        for seg_id in sorted(graph.segment_to_devices.keys()):
            completed_checks.append(f"segment_membership:{seg_id}")

        # 3. Evaluate explicit reachability pairs if requested in incident_context
        self._evaluate_requested_reachability(graph, ctx, findings, warnings, completed_checks)

        # 4. Evaluate impact of reported affected/failed devices
        self._evaluate_affected_devices(
            graph=graph,
            ctx=ctx,
            upstream_finding_ids=upstream_finding_ids,
            findings=findings,
            warnings=warnings,
            completed_checks=completed_checks,
        )

        # 5. Evaluate impact of reported affected/failed links & alternate physical paths
        self._evaluate_affected_links(
            graph=graph,
            ctx=ctx,
            upstream_finding_ids=upstream_finding_ids,
            findings=findings,
            warnings=warnings,
            completed_checks=completed_checks,
        )

        # 6. Evaluate affected segments reported in context
        self._evaluate_affected_segments(
            graph=graph,
            ctx=ctx,
            upstream_finding_ids=upstream_finding_ids,
            findings=findings,
            warnings=warnings,
            completed_checks=completed_checks,
        )

        # 7. Evaluate shared paths / common dependencies and alternate physical links in the topology
        self._evaluate_shared_dependencies(
            graph=graph,
            ctx=ctx,
            upstream_finding_ids=upstream_finding_ids,
            findings=findings,
            completed_checks=completed_checks,
        )
        self._evaluate_alternate_physical_links(
            graph=graph,
            ctx=ctx,
            findings=findings,
            completed_checks=completed_checks,
        )

        deduped_checks = list(dict.fromkeys(completed_checks))

        # Determine ExecutionStatus:
        # PARTIAL if there were validation errors, contradictory links, missing links when devices exist,
        # or unknown devices in incident context; otherwise SUCCESS.
        has_incompleteness = (
            bool(errors)
            or bool(graph.implicit_devices)
            or (bool(graph.devices) and not bool(graph.links))
            or any("not present in the supplied topology" in w for w in warnings)
        )

        if has_incompleteness and (findings or deduped_checks):
            status = ExecutionStatus.PARTIAL
            if errors and not warnings:
                warnings.append(
                    f"{len(errors)} malformed topology record(s) were skipped; valid topology records were retained."
                )
        elif errors and not findings and not deduped_checks:
            status = ExecutionStatus.FAILED
        else:
            status = ExecutionStatus.SUCCESS

        # Compute summary adjacency & segment maps in execution_metadata for easy inspection
        adjacency_map = {
            dev_id: graph.get_direct_neighbors(dev_id)
            for dev_id in sorted(graph.adjacency.keys())
        }
        reachability_map = {
            dev_id: graph.get_connected_devices(dev_id, usable_only=True)
            for dev_id in sorted(graph.adjacency.keys())
        }
        segment_map = {
            seg_id: graph.get_devices_for_segment(seg_id)
            for seg_id in sorted(graph.segment_to_devices.keys())
        }

        return AgentResponse(
            agent_name=AgentName.CONNECTIVITY,
            status=status,
            findings=findings,
            completed_checks=deduped_checks,
            warnings=warnings,
            errors=errors,
            processing_time_ms=(perf_counter() - started) * 1000,
            execution_metadata={
                "devices_received": raw_devices_count,
                "links_received": raw_links_count,
                "devices_loaded": len(graph.devices),
                "implicit_devices": sorted(graph.implicit_devices),
                "links_loaded": len(graph.links),
                "adjacency_map": adjacency_map,
                "usable_reachability_map": reachability_map,
                "segment_to_devices": segment_map,
                "findings_generated": len(findings),
            },
        )

    # -----------------------------------------------------------------
    # INPUT PARSING & CONTRADICTION DETECTION
    # -----------------------------------------------------------------

    def _parse_incident_context(
        self,
        raw_ctx: Optional[Union[Mapping[str, Any], IncidentContext]],
        errors: list[AgentError],
    ) -> IncidentContext:
        if raw_ctx is None:
            return IncidentContext()
        if isinstance(raw_ctx, IncidentContext):
            return raw_ctx
        if not isinstance(raw_ctx, Mapping):
            errors.append(
                self._make_error(
                    ErrorCode.MALFORMED_TELEMETRY,
                    f"incident_context must be a mapping or IncidentContext, got {type(raw_ctx).__name__}.",
                )
            )
            return IncidentContext()
        try:
            return IncidentContext.model_validate(raw_ctx)
        except ValidationError as exc:
            errors.append(
                self._make_error(
                    ErrorCode.MALFORMED_TELEMETRY,
                    f"incident_context failed validation: {exc}",
                )
            )
            return IncidentContext()

    def _parse_and_build_graph(
        self,
        topology_input: Any,
        explicit_context: Optional[Union[Mapping[str, Any], IncidentContext]],
        findings: list[AgentFinding],
        errors: list[AgentError],
        warnings: list[str],
        completed_checks: list[str],
    ) -> Optional[tuple[TopologyGraph, IncidentContext, int, int]]:
        if isinstance(topology_input, ConnectivityInput):
            raw_dict = topology_input.model_dump()
        elif isinstance(topology_input, Mapping):
            raw_dict = dict(topology_input)
        else:
            errors.append(
                self._make_error(
                    ErrorCode.MALFORMED_TELEMETRY,
                    f"Topology input must be a mapping, ConnectivityInput, or TopologyGraph, got {type(topology_input).__name__}.",
                )
            )
            return None

        allowed_top_keys = {
            "devices",
            "links",
            "incident_context",
            "affected_device_ids",
            "affected_link_ids",
            "affected_segment_ids",
            "upstream_findings",
            "source_devices",
            "target_devices",
        }
        unknown_top_keys = set(raw_dict.keys()) - allowed_top_keys
        if unknown_top_keys and not ("devices" in raw_dict or "links" in raw_dict):
            errors.append(
                self._make_error(
                    ErrorCode.MALFORMED_TELEMETRY,
                    f"Topology input is missing 'devices'/'links' and contains unrecognized keys: {sorted(unknown_top_keys)}.",
                )
            )
            return None

        raw_devices = raw_dict.get("devices", [])
        raw_links = raw_dict.get("links", [])

        if not isinstance(raw_devices, Sequence) or isinstance(raw_devices, (str, bytes)):
            errors.append(
                self._make_error(
                    ErrorCode.MALFORMED_TELEMETRY,
                    "'devices' must be a list/sequence of device records.",
                )
            )
            raw_devices = []

        if not isinstance(raw_links, Sequence) or isinstance(raw_links, (str, bytes)):
            errors.append(
                self._make_error(
                    ErrorCode.MALFORMED_TELEMETRY,
                    "'links' must be a list/sequence of link records.",
                )
            )
            raw_links = []

        # Parse incident context (merging top-level convenience keys with explicit incident_context)
        merged_ctx_dict: dict[str, Any] = {}
        inline_ctx = raw_dict.get("incident_context")
        if isinstance(inline_ctx, IncidentContext):
            merged_ctx_dict.update(inline_ctx.model_dump())
        elif isinstance(inline_ctx, Mapping):
            merged_ctx_dict.update(dict(inline_ctx))
        elif inline_ctx is not None:
            errors.append(
                self._make_error(
                    ErrorCode.MALFORMED_TELEMETRY,
                    "'incident_context' must be a mapping or IncidentContext.",
                )
            )

        for key in ("affected_device_ids", "affected_link_ids", "affected_segment_ids", "upstream_findings", "source_devices", "target_devices"):
            if key in raw_dict and raw_dict[key] is not None:
                existing = list(merged_ctx_dict.get(key, []))
                val = raw_dict[key]
                if isinstance(val, list):
                    merged_ctx_dict[key] = [*existing, *val]
                else:
                    merged_ctx_dict[key] = val

        if explicit_context is not None:
            if isinstance(explicit_context, IncidentContext):
                ext_dict = explicit_context.model_dump()
            elif isinstance(explicit_context, Mapping):
                ext_dict = dict(explicit_context)
            else:
                errors.append(
                    self._make_error(
                        ErrorCode.MALFORMED_TELEMETRY,
                        f"incident_context must be a mapping or IncidentContext, got {type(explicit_context).__name__}.",
                    )
                )
                ext_dict = {}
            for k, v in ext_dict.items():
                if v:
                    merged_ctx_dict[k] = v

        ctx = self._parse_incident_context(merged_ctx_dict, errors) if merged_ctx_dict else IncidentContext()

        graph = TopologyGraph()

        # Validate and load devices
        seen_devices: dict[str, TopologyDevice] = {}
        for idx, raw_dev in enumerate(raw_devices):
            try:
                dev = raw_dev if isinstance(raw_dev, TopologyDevice) else TopologyDevice.model_validate(raw_dev)
            except (ValidationError, ValueError, TypeError) as exc:
                errors.append(
                    self._make_error(
                        ErrorCode.MALFORMED_TELEMETRY,
                        f"Device record at index {idx} failed validation: {exc}",
                        device_index=idx,
                    )
                )
                continue

            if dev.device_id in seen_devices:
                prev_dev = seen_devices[dev.device_id]
                if prev_dev.device_type != dev.device_type and dev.device_type != "unknown" and prev_dev.device_type != "unknown":
                    warnings.append(
                        f"Conflicting duplicate device definition for '{dev.device_id}' "
                        f"(device_type '{prev_dev.device_type}' vs '{dev.device_type}'); retaining first definition and merging segments."
                    )
                else:
                    warnings.append(f"Duplicate device record for '{dev.device_id}' at index {idx}; deduplicated.")
                # Merge any additional segment_ids explicitly declared
                merged_segs = list(dict.fromkeys([*prev_dev.segment_ids, *dev.segment_ids]))
                prev_dev.segment_ids = merged_segs
                graph.add_device(prev_dev)
                continue

            seen_devices[dev.device_id] = dev
            graph.add_device(dev)

        # Validate and load links (detecting exact duplicates and contradictory link records)
        seen_links_by_id: dict[str, TopologyLink] = {}
        seen_links_by_endpoints: dict[tuple[str, str, Optional[str], Optional[str]], TopologyLink] = {}

        for idx, raw_lnk in enumerate(raw_links):
            try:
                lnk = raw_lnk if isinstance(raw_lnk, TopologyLink) else TopologyLink.model_validate(raw_lnk)
            except (ValidationError, ValueError, TypeError) as exc:
                errors.append(
                    self._make_error(
                        ErrorCode.MALFORMED_TELEMETRY,
                        f"Link record at index {idx} failed validation: {exc}",
                        link_index=idx,
                    )
                )
                continue

            # Check duplicate link_id
            if lnk.link_id in seen_links_by_id:
                existing_lnk = seen_links_by_id[lnk.link_id]
                is_contradictory = (
                    (existing_lnk.source_device, existing_lnk.target_device) != (lnk.source_device, lnk.target_device)
                    or (existing_lnk.status is not None and lnk.status is not None and existing_lnk.status != lnk.status)
                    or (existing_lnk.source_interface != lnk.source_interface)
                    or (existing_lnk.target_interface != lnk.target_interface)
                )
                if is_contradictory:
                    warnings.append(
                        f"Contradictory duplicate link_id '{lnk.link_id}' at index {idx}: "
                        f"existing=({existing_lnk.source_device}->{existing_lnk.target_device}, status={existing_lnk.status}) "
                        f"vs new=({lnk.source_device}->{lnk.target_device}, status={lnk.status})."
                    )
                    self._emit_contradictory_link_finding(existing_lnk, lnk, findings, completed_checks)
                else:
                    warnings.append(f"Duplicate link record '{lnk.link_id}' at index {idx} was deduplicated.")
                continue

            # Check same physical endpoint/interface pair with conflicting operational status
            norm_key = (
                (lnk.source_device, lnk.target_device, lnk.source_interface, lnk.target_interface)
                if lnk.directed or lnk.source_device <= lnk.target_device
                else (lnk.target_device, lnk.source_device, lnk.target_interface, lnk.source_interface)
            )
            if norm_key in seen_links_by_endpoints:
                prev_lnk = seen_links_by_endpoints[norm_key]
                if prev_lnk.status is not None and lnk.status is not None and prev_lnk.status != lnk.status:
                    warnings.append(
                        f"Contradictory operational status between link '{prev_lnk.link_id}' (status='{prev_lnk.status}') "
                        f"and link '{lnk.link_id}' (status='{lnk.status}') on the same endpoint interface pair."
                    )
                    self._emit_contradictory_link_finding(prev_lnk, lnk, findings, completed_checks)
                    continue
                if prev_lnk.source_interface is not None or prev_lnk.target_interface is not None:
                    # Exact same device+interface pair repeated under a different link_id
                    warnings.append(
                        f"Duplicate physical interface link '{lnk.link_id}' matches existing link '{prev_lnk.link_id}'; deduplicated."
                    )
                    continue

            seen_links_by_id[lnk.link_id] = lnk
            seen_links_by_endpoints[norm_key] = lnk
            graph.add_link(lnk)

        return graph, ctx, len(raw_devices), len(raw_links)

    def _emit_contradictory_link_finding(
        self,
        first: TopologyLink,
        second: TopologyLink,
        findings: list[AgentFinding],
        completed_checks: list[str],
    ) -> None:
        completed_checks.append(f"topology_consistency:{first.link_id}")
        ev1 = Evidence(
            evidence_type=EvidenceType.TOPOLOGY_LINK,
            metric_name="topology_link_record",
            observed_value=(
                f"{first.link_id}: {first.source_device}"
                f"{':' + first.source_interface if first.source_interface else ''} -> "
                f"{first.target_device}{':' + first.target_interface if first.target_interface else ''} "
                f"(status={first.status or 'unspecified'})"
            ),
            device_id=first.source_device,
            interface_id=first.source_interface,
            source_agent=AgentName.CONNECTIVITY,
            telemetry_record_id=first.record_id,
            description=f"First topology record for link '{first.link_id}'.",
            timestamp=first.timestamp,
        )
        ev2 = Evidence(
            evidence_type=EvidenceType.TOPOLOGY_LINK,
            metric_name="conflicting_topology_link_record",
            observed_value=(
                f"{second.link_id}: {second.source_device}"
                f"{':' + second.source_interface if second.source_interface else ''} -> "
                f"{second.target_device}{':' + second.target_interface if second.target_interface else ''} "
                f"(status={second.status or 'unspecified'})"
            ),
            device_id=second.source_device,
            interface_id=second.source_interface,
            source_agent=AgentName.CONNECTIVITY,
            telemetry_record_id=second.record_id,
            description=f"Conflicting topology record for link '{second.link_id}'.",
            timestamp=second.timestamp,
        )
        affected_devs = list(dict.fromkeys([first.source_device, first.target_device, second.source_device, second.target_device]))
        findings.append(
            AgentFinding(
                agent_source=AgentName.CONNECTIVITY,
                finding_code="CONTRADICTORY_TOPOLOGY_LINK",
                finding_type=FindingType.CONNECTIVITY_SCOPE,
                severity=Severity.MEDIUM,
                summary=f"Contradictory topology link records detected for {first.link_id} / {second.link_id}.",
                description=(
                    f"Topology input contains conflicting link records between "
                    f"'{first.source_device}' and '{first.target_device}' "
                    f"(first status='{first.status}', second status='{second.status}'). "
                    f"Actual link state requires verification."
                ),
                confidence=0.90,
                affected_devices=affected_devs,
                evidence=[ev1, ev2],
                limitations=[
                    "Conflicting link telemetry prevents deterministic verification of link operational state."
                ],
            )
        )

    # -----------------------------------------------------------------
    # CONNECTIVITY SCOPE & IMPACT CHECKS
    # -----------------------------------------------------------------

    def _evaluate_requested_reachability(
        self,
        graph: TopologyGraph,
        ctx: IncidentContext,
        findings: list[AgentFinding],
        warnings: list[str],
        completed_checks: list[str],
    ) -> None:
        if not ctx.source_devices or not ctx.target_devices:
            return

        for src in ctx.source_devices:
            if not graph.has_node(src):
                warnings.append(
                    f"Source device '{src}' is not present in the supplied topology; cannot evaluate reachability from '{src}'."
                )
                continue
            for dst in ctx.target_devices:
                if src == dst:
                    continue
                if not graph.has_node(dst):
                    warnings.append(
                        f"Target device '{dst}' is not present in the supplied topology; "
                        f"cannot claim '{dst}' is unreachable merely because it is absent from topology."
                    )
                    continue

                completed_checks.append(f"reachability:{src}->{dst}")
                usable_path = graph.find_shortest_path(src, dst, usable_only=True)
                physical_path = graph.find_shortest_path(src, dst, usable_only=False)

                if usable_path is None and physical_path is not None:
                    # Physical path exists, but blocked/down link breaks usable path
                    ev = Evidence(
                        evidence_type=EvidenceType.TOPOLOGY_LINK,
                        metric_name="severed_usable_path",
                        observed_value=f"Physical path {' -> '.join(physical_path)} is interrupted by down/blocked link(s).",
                        device_id=src,
                        source_agent=AgentName.CONNECTIVITY,
                        description=f"No usable operational path exists from '{src}' to '{dst}' despite physical adjacency.",
                    )
                    findings.append(
                        AgentFinding(
                            agent_source=AgentName.CONNECTIVITY,
                            finding_code="PATH_INTERRUPTED",
                            finding_type=FindingType.CONNECTIVITY_SCOPE,
                            severity=Severity.HIGH,
                            summary=f"Usable connectivity path between {src} and {dst} is interrupted.",
                            description=(
                                f"Physical path ({' -> '.join(physical_path)}) between '{src}' and '{dst}' "
                                f"contains one or more down or blocked links, interrupting active reachability."
                            ),
                            confidence=0.88,
                            affected_devices=physical_path,
                            evidence=[ev],
                            limitations=[
                                "Topology reachability reflects reported link status; dynamic routing tables were not directly inspected."
                            ],
                        )
                    )

    def _evaluate_affected_devices(
        self,
        graph: TopologyGraph,
        ctx: IncidentContext,
        upstream_finding_ids: list[UUID],
        findings: list[AgentFinding],
        warnings: list[str],
        completed_checks: list[str],
    ) -> None:
        for dev_id in ctx.affected_device_ids:
            if not graph.has_node(dev_id):
                warnings.append(
                    f"Reported affected device '{dev_id}' is not present in the supplied topology; "
                    f"downstream connectivity impact cannot be inferred."
                )
                continue

            completed_checks.append(f"device_impact:{dev_id}")
            impact = graph.analyze_device_failure_impact(dev_id)
            incident_links = graph.get_incident_links(dev_id)
            direct_neighbors = impact["direct_neighbors"]
            isolated_devices = impact["isolated_devices"]
            affected_devices = impact["potentially_affected_devices"]
            affected_segments = impact["potentially_affected_segments"]

            evidence_list: list[Evidence] = []
            for lnk in incident_links:
                nbr = lnk.target_device if lnk.source_device == dev_id else lnk.source_device
                evidence_list.append(
                    Evidence(
                        evidence_type=EvidenceType.TOPOLOGY_LINK,
                        metric_name="incident_topology_link",
                        observed_value=(
                            f"Link '{lnk.link_id}' ({lnk.link_type}) connects '{dev_id}' and '{nbr}' "
                            f"(status={lnk.status or 'unspecified'})."
                        ),
                        device_id=dev_id,
                        interface_id=lnk.source_interface if lnk.source_device == dev_id else lnk.target_interface,
                        segment_id=affected_segments[0] if affected_segments else None,
                        source_agent=AgentName.CONNECTIVITY,
                        telemetry_record_id=lnk.record_id,
                        description=(
                            f"Verified topology link '{lnk.link_id}' establishes adjacency between "
                            f"'{dev_id}' and '{nbr}'."
                        ),
                        timestamp=lnk.timestamp,
                    )
                )

            if not evidence_list:
                dev_obj = graph.devices.get(dev_id)
                evidence_list.append(
                    Evidence(
                        evidence_type=EvidenceType.TOPOLOGY_LINK,
                        metric_name="device_segment_association",
                        observed_value=(
                            f"Device '{dev_id}' is registered in topology with segments {affected_segments or 'none'} "
                            f"and 0 known links."
                        ),
                        device_id=dev_id,
                        segment_id=affected_segments[0] if affected_segments else None,
                        source_agent=AgentName.CONNECTIVITY,
                        telemetry_record_id=dev_obj.record_id if dev_obj else None,
                        description=f"Topology inventory record for '{dev_id}'.",
                    )
                )

            severity = Severity.HIGH if isolated_devices or len(direct_neighbors) >= 2 else Severity.MEDIUM
            confidence = 0.85 if incident_links else 0.65

            limitations = [
                "Potential impact is inferred from topological adjacency and segment membership; "
                "physical adjacency does not by itself prove active forwarding state or root cause."
            ]
            if graph.implicit_devices:
                limitations.append(
                    "Some topology nodes lack explicit device inventory records, so segment impact may be incomplete."
                )

            findings.append(
                AgentFinding(
                    agent_source=AgentName.CONNECTIVITY,
                    finding_code="DEVICE_FAILURE_IMPACT_SCOPE",
                    finding_type=FindingType.CONNECTIVITY_SCOPE,
                    severity=severity,
                    summary=(
                        f"Issue on {dev_id} potentially affects {len(affected_devices)} device(s) "
                        f"and {len(affected_segments)} segment(s)."
                    ),
                    description=(
                        f"Topological impact analysis for affected device '{dev_id}': "
                        f"direct neighbors={direct_neighbors}, potentially isolated downstream devices={isolated_devices}, "
                        f"associated segments={affected_segments}."
                    ),
                    confidence=confidence,
                    affected_devices=affected_devices,
                    affected_segments=affected_segments,
                    evidence=evidence_list,
                    supporting_finding_ids=upstream_finding_ids,
                    limitations=limitations,
                )
            )

    def _evaluate_affected_links(
        self,
        graph: TopologyGraph,
        ctx: IncidentContext,
        upstream_finding_ids: list[UUID],
        findings: list[AgentFinding],
        warnings: list[str],
        completed_checks: list[str],
    ) -> None:
        for link_id in ctx.affected_link_ids:
            if link_id not in graph.links:
                warnings.append(
                    f"Reported affected link '{link_id}' is not present in the supplied topology."
                )
                continue

            completed_checks.append(f"link_impact:{link_id}")
            impact = graph.analyze_link_failure_impact(link_id)
            link: TopologyLink = impact["link"]
            has_alt = impact["has_alternate_physical_path"]
            alt_paths = impact["alternate_paths"]
            severed = impact["severed_devices"]
            affected_devices = impact["potentially_affected_devices"]
            affected_segments = impact["potentially_affected_segments"]

            ev = Evidence(
                evidence_type=EvidenceType.TOPOLOGY_LINK,
                metric_name="affected_topology_link",
                observed_value=(
                    f"Link '{link.link_id}' ({link.source_device} <-> {link.target_device}, "
                    f"type={link.link_type}, status={link.status or 'affected'})"
                ),
                device_id=link.source_device,
                interface_id=link.source_interface,
                segment_id=affected_segments[0] if affected_segments else None,
                source_agent=AgentName.CONNECTIVITY,
                telemetry_record_id=link.record_id,
                description=(
                    f"Link '{link.link_id}' between '{link.source_device}' and '{link.target_device}' "
                    f"was evaluated for failure impact."
                ),
                timestamp=link.timestamp,
            )

            severity = Severity.HIGH if severed or not has_alt else Severity.MEDIUM
            alt_note = (
                f"Alternate physical path(s) exist ({[' -> '.join(p) for p in alt_paths]}), "
                f"but physical adjacency alone does not verify STP forwarding or routing readiness."
                if has_alt
                else "No alternate physical path exists in the provided topology."
            )

            findings.append(
                AgentFinding(
                    agent_source=AgentName.CONNECTIVITY,
                    finding_code="LINK_FAILURE_IMPACT_SCOPE",
                    finding_type=FindingType.CONNECTIVITY_SCOPE,
                    severity=severity,
                    summary=(
                        f"Failure/degradation of link {link.link_id} ({link.source_device} - {link.target_device}) "
                        f"potentially affects {len(affected_devices)} device(s)."
                    ),
                    description=(
                        f"Impact analysis for link '{link.link_id}' between '{link.source_device}' and '{link.target_device}': "
                        f"severed devices={severed}, potentially affected segments={affected_segments}. {alt_note}"
                    ),
                    confidence=0.88,
                    affected_devices=affected_devices,
                    affected_segments=affected_segments,
                    evidence=[ev],
                    supporting_finding_ids=upstream_finding_ids,
                    limitations=[
                        "Link impact scope is derived from known topology; STP forwarding state and routing failover readiness require separate verification."
                    ],
                )
            )

    def _evaluate_affected_segments(
        self,
        graph: TopologyGraph,
        ctx: IncidentContext,
        upstream_finding_ids: list[UUID],
        findings: list[AgentFinding],
        warnings: list[str],
        completed_checks: list[str],
    ) -> None:
        for seg_id in ctx.affected_segment_ids:
            seg_devices = graph.get_devices_for_segment(seg_id)
            if not seg_devices:
                warnings.append(
                    f"Reported affected segment '{seg_id}' has no associated devices in the supplied topology."
                )
                continue

            completed_checks.append(f"segment_impact:{seg_id}")
            # If already covered by a device impact finding for all devices, only emit if no device impact was requested
            if ctx.affected_device_ids and set(seg_devices).issubset(set(ctx.affected_device_ids)):
                continue

            ev = Evidence(
                evidence_type=EvidenceType.TOPOLOGY_LINK,
                metric_name="segment_device_membership",
                observed_value=f"Segment '{seg_id}' is explicitly associated with devices: {', '.join(seg_devices)}.",
                device_id=seg_devices[0],
                segment_id=seg_id,
                source_agent=AgentName.CONNECTIVITY,
                description=f"Verified segment-to-device membership for '{seg_id}'.",
            )
            findings.append(
                AgentFinding(
                    agent_source=AgentName.CONNECTIVITY,
                    finding_code="SEGMENT_CONNECTIVITY_SCOPE",
                    finding_type=FindingType.CONNECTIVITY_SCOPE,
                    severity=Severity.MEDIUM,
                    summary=f"Segment {seg_id} spans {len(seg_devices)} associated device(s).",
                    description=(
                        f"Segment '{seg_id}' is explicitly associated with devices {seg_devices}. "
                        f"Issues scoped to '{seg_id}' may involve or impact these devices."
                    ),
                    confidence=0.85,
                    affected_devices=seg_devices,
                    affected_segments=[seg_id],
                    evidence=[ev],
                    supporting_finding_ids=upstream_finding_ids,
                    limitations=[
                        "Segment scope reflects explicit segment_ids declarations; VLAN trunking state is not assumed for unannotated devices."
                    ],
                )
            )

    def _evaluate_shared_dependencies(
        self,
        graph: TopologyGraph,
        ctx: IncidentContext,
        upstream_finding_ids: list[UUID],
        findings: list[AgentFinding],
        completed_checks: list[str],
    ) -> None:
        # Candidate devices to check for shared upstream dependencies:
        # 1. If 2+ known affected devices are provided, check if they share a common upstream/neighbor dependency
        # 2. If an affected segment has 2+ devices, check if they share a common upstream/neighbor dependency
        focal_groups: list[tuple[str, list[str]]] = []
        known_affected = [d for d in ctx.affected_device_ids if graph.has_node(d)]
        if len(known_affected) >= 2:
            focal_groups.append(("affected_devices", known_affected))
        for seg_id in ctx.affected_segment_ids:
            seg_devs = graph.get_devices_for_segment(seg_id)
            if len(seg_devs) >= 2:
                focal_groups.append((f"segment:{seg_id}", seg_devs))

        reported_shared_nodes: set[str] = set()
        for group_label, group_devices in focal_groups:
            completed_checks.append(f"shared_dependency:{group_label}")
            shared_map = graph.find_shared_dependencies(group_devices)
            for shared_dev, dependents in shared_map.items():
                if shared_dev in reported_shared_nodes:
                    continue
                reported_shared_nodes.add(shared_dev)

                supporting_links = [
                    lnk
                    for lnk in graph.get_incident_links(shared_dev)
                    if lnk.source_device in dependents or lnk.target_device in dependents
                ]
                if not supporting_links:
                    supporting_links = graph.get_incident_links(shared_dev)

                evidence_items = [
                    Evidence(
                        evidence_type=EvidenceType.TOPOLOGY_LINK,
                        metric_name="shared_upstream_dependency_link",
                        observed_value=(
                            f"Shared node '{shared_dev}' connects to dependent device via link '{lnk.link_id}' "
                            f"({lnk.source_device} <-> {lnk.target_device})."
                        ),
                        device_id=shared_dev,
                        interface_id=lnk.source_interface if lnk.source_device == shared_dev else lnk.target_interface,
                        source_agent=AgentName.CONNECTIVITY,
                        telemetry_record_id=lnk.record_id,
                        description=(
                            f"Link '{lnk.link_id}' attaches '{shared_dev}' as a common topological dependency "
                            f"for {dependents}."
                        ),
                        timestamp=lnk.timestamp,
                    )
                    for lnk in supporting_links
                ]

                shared_segments: list[str] = []
                for d in [shared_dev, *dependents]:
                    for s in graph.get_segments_for_device(d):
                        if s not in shared_segments:
                            shared_segments.append(s)

                findings.append(
                    AgentFinding(
                        agent_source=AgentName.CONNECTIVITY,
                        finding_code="SHARED_TOPOLOGY_DEPENDENCY",
                        finding_type=FindingType.CONNECTIVITY_SCOPE,
                        severity=Severity.MEDIUM,
                        summary=(
                            f"Device {shared_dev} is a shared topological dependency for "
                            f"{len(dependents)} devices ({', '.join(dependents)})."
                        ),
                        description=(
                            f"Devices {dependents} share '{shared_dev}' as a common adjacent or transit dependency "
                            f"in the network topology. A fault or congestion on '{shared_dev}' can simultaneously "
                            f"affect traffic across these dependent devices."
                        ),
                        confidence=0.86,
                        affected_devices=[shared_dev, *dependents],
                        affected_segments=shared_segments,
                        evidence=evidence_items,
                        supporting_finding_ids=upstream_finding_ids,
                        limitations=[
                            "Shared topological dependency identifies a common structural node; correlate with performance and infrastructure telemetry before assigning root cause."
                        ],
                    )
                )

    def _evaluate_alternate_physical_links(
        self,
        graph: TopologyGraph,
        ctx: IncidentContext,
        findings: list[AgentFinding],
        completed_checks: list[str],
    ) -> None:
        """
        Identifies redundant/alternate physical connections relevant to the incident scope
        (or explicitly marked standby/blocked/lldp backup links) and reports them with
        explicit caveats that physical adjacency does NOT prove active forwarding readiness.
        """
        candidate_devices = {d for d in ctx.affected_device_ids if graph.has_node(d)}
        for seg_id in ctx.affected_segment_ids:
            candidate_devices.update(graph.get_devices_for_segment(seg_id))
        for link_id in ctx.affected_link_ids:
            if link_id in graph.links:
                lnk = graph.links[link_id]
                candidate_devices.update([lnk.source_device, lnk.target_device])

        has_any_requested_scope = bool(
            ctx.affected_device_ids or ctx.affected_link_ids or ctx.affected_segment_ids
        )

        # Also inspect links that are explicitly LLDP/CDP or standby/blocked or parallel links when no scope was requested
        if not candidate_devices and not has_any_requested_scope:
            for lnk in graph.links.values():
                if lnk.link_type in {"lldp", "cdp"} or lnk.status in BLOCKED_OR_STANDBY_LINK_STATUSES:
                    candidate_devices.update([lnk.source_device, lnk.target_device])
                else:
                    # Check if parallel/cycle alternate path exists between endpoints
                    alt = graph.find_all_simple_paths(
                        lnk.source_device,
                        lnk.target_device,
                        usable_only=False,
                        excluded_links={lnk.link_id},
                    )
                    if alt:
                        candidate_devices.update([lnk.source_device, lnk.target_device])

        visited_pairs: set[tuple[str, str]] = set()
        for dev_id in sorted(candidate_devices):
            if not graph.has_node(dev_id):
                continue
            for nbr, primary_link in graph.adjacency.get(dev_id, []):
                pair = (dev_id, nbr) if dev_id <= nbr else (nbr, dev_id)
                if pair in visited_pairs:
                    continue

                alt_paths = graph.find_all_simple_paths(
                    dev_id,
                    nbr,
                    usable_only=False,
                    excluded_links={primary_link.link_id},
                )
                is_unverified_discovery = primary_link.link_type in {"lldp", "cdp"} and primary_link.status is None
                is_standby_link = primary_link.status in BLOCKED_OR_STANDBY_LINK_STATUSES

                if not alt_paths and not is_unverified_discovery and not is_standby_link:
                    continue

                visited_pairs.add(pair)
                completed_checks.append(f"alternate_path:{pair[0]}<->{pair[1]}")

                if alt_paths:
                    alt_step = alt_paths[0][-1][1]
                    alt_nodes = [dev_id, *[step[0] for step in alt_paths[0]]]
                    obs = (
                        f"Alternate physical path {' -> '.join(alt_nodes)} (via link '{alt_step.link_id}', "
                        f"type={alt_step.link_type}, status={alt_step.status or 'unverified'}) exists between "
                        f"'{dev_id}' and '{nbr}'; forwarding readiness is not established by physical adjacency alone."
                    )
                    ref_link = alt_step
                    involved_devs = list(dict.fromkeys([dev_id, nbr, *alt_nodes]))
                else:
                    obs = (
                        f"Link '{primary_link.link_id}' ({primary_link.source_device} <-> {primary_link.target_device}, "
                        f"type={primary_link.link_type}, status={primary_link.status or 'unverified'}) "
                        f"confirms physical adjacency only; active forwarding readiness is not established."
                    )
                    ref_link = primary_link
                    involved_devs = [primary_link.source_device, primary_link.target_device]

                segs: list[str] = []
                for d in involved_devs:
                    for s in graph.get_segments_for_device(d):
                        if s not in segs:
                            segs.append(s)

                ev = Evidence(
                    evidence_type=EvidenceType.TOPOLOGY_LINK,
                    metric_name="redundant_physical_aggregation_link",
                    observed_value=obs,
                    device_id=ref_link.source_device,
                    interface_id=ref_link.source_interface,
                    segment_id=segs[0] if segs else None,
                    source_agent=AgentName.CONNECTIVITY,
                    telemetry_record_id=ref_link.record_id,
                    description=(
                        "Physical adjacency or alternate physical path is confirmed in topology; "
                        "STP forwarding state and routing reachability are not established by this record."
                    ),
                    timestamp=ref_link.timestamp,
                )

                findings.append(
                    AgentFinding(
                        agent_source=AgentName.CONNECTIVITY,
                        finding_code="ALTERNATE_PHYSICAL_PATH_IDENTIFIED",
                        finding_type=FindingType.CONNECTIVITY_SCOPE,
                        severity=Severity.INFO,
                        summary=(
                            f"Alternate or unverified physical connection identified involving "
                            f"{', '.join(involved_devs)}."
                        ),
                        description=(
                            f"{obs} Physical connectivity or LLDP neighbor discovery does not prove that "
                            f"STP is in a forwarding state, that VLANs are trunked identically, or that "
                            f"routing tables actively forward traffic over the backup path."
                        ),
                        confidence=0.90,
                        affected_devices=involved_devs,
                        affected_segments=segs,
                        evidence=[ev],
                        limitations=[
                            "Physical adjacency does not prove active forwarding; verify STP state, interface counters, and routing state before assuming failover readiness."
                        ],
                    )
                )


def analyze_connectivity(
    topology_input: Union[Mapping[str, Any], ConnectivityInput, TopologyGraph],
    incident_context: Optional[Union[Mapping[str, Any], IncidentContext]] = None,
) -> AgentResponse:
    """Convenience entry point for orchestrator and tests to run the Connectivity Analysis Agent."""
    return ConnectivityAgent().analyze(topology_input, incident_context=incident_context)


run_connectivity_analysis = analyze_connectivity
