# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Binary-wide MITRE ATT&CK aggregation over per-cluster analyses.

The LLM cluster analyzer attaches a ``mitre_attack`` list to each cluster
(see :class:`xrefer.llm.dspy_modules.MitreAttackTechnique`), but the data
is purely per-cluster: the same technique can recur across clusters and
nothing rolls it up to the binary level. This module performs that
roll-up so the TUI ATT&CK matrix view can present one kill-chain-ordered
matrix for the whole sample, with each unique technique remembering the
cluster(s) that ground it (so a technique can be linked back to the
responsible code).

Pure data layer: no IDA, no Qt, no disassembler state. Everything here is
driven off the already-computed ``cluster_analysis`` dict plus the
``FunctionalCluster`` tree, which keeps it headless-testable and lets the
GUI stay a thin renderer.
"""

from __future__ import annotations

import csv
import io
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

from xrefer.core.helpers import find_cluster_analysis

# Canonical ATT&CK Enterprise kill-chain order. Single source of truth for
# the TUI matrix (and, eventually, the HTML report, which currently
# hard-codes the same list in ``report_tmpl.html``). Tactics outside this
# list sort after it.
MITRE_TACTIC_ORDER: List[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Bucket for techniques the LLM returned without a tactic. Kept (not
# dropped) so a grounded technique never silently vanishes; sorted last.
UNSPECIFIED_TACTIC = "Unspecified"

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def mitre_attack_url(technique_id: str) -> Optional[str]:
    """Stable attack.mitre.org URL for a technique id, or ``None`` when the
    id is not canonical. ``'T1059.003'`` maps to
    ``.../techniques/T1059/003/``; ``'T1027'`` to ``.../techniques/T1027/``.
    Mirrors the report template's ``mitreAttackUrl`` so the TUI and HTML
    agree on link targets.
    """
    if not technique_id:
        return None
    trimmed = str(technique_id).strip().upper()
    if not _TECHNIQUE_ID_RE.match(trimmed):
        return None
    parent, _, sub = trimmed.partition(".")
    return (
        f"https://attack.mitre.org/techniques/{parent}/{sub}/"
        if sub
        else f"https://attack.mitre.org/techniques/{parent}/"
    )


@dataclass
class TechniqueGrounding:
    """One cluster's evidence for a technique."""

    cluster_id: int
    cluster_label: str
    rationale: str


@dataclass
class TechniqueRollup:
    """A unique technique aggregated across every cluster that exhibits it."""

    id: str
    name: str
    tactic: str
    groundings: List[TechniqueGrounding] = field(default_factory=list)

    @property
    def cluster_ids(self) -> List[int]:
        """Contributing cluster ids, de-duplicated, in first-seen order."""
        seen: set = set()
        out: List[int] = []
        for g in self.groundings:
            if g.cluster_id not in seen:
                seen.add(g.cluster_id)
                out.append(g.cluster_id)
        return out

    @property
    def cluster_count(self) -> int:
        return len(self.cluster_ids)

    @property
    def representative_rationale(self) -> str:
        """First non-empty rationale (sleek view shows one). The per-cluster
        rationales remain available via :attr:`groundings`."""
        for g in self.groundings:
            if g.rationale:
                return g.rationale
        return ""

    @property
    def url(self) -> Optional[str]:
        return mitre_attack_url(self.id)


@dataclass
class TacticGroup:
    """Techniques sharing a tactic, in display order."""

    tactic: str
    techniques: List[TechniqueRollup] = field(default_factory=list)


@dataclass
class MitreMatrix:
    """The binary-wide (or cluster-scoped) ATT&CK roll-up.

    ``tactics`` holds only covered tactics in kill-chain order (for the
    detail list); ``coverage`` holds every canonical tactic plus any
    extras with its unique-technique count (for the coverage strip).
    """

    tactics: List[TacticGroup]
    coverage: List[Tuple[str, int]]
    technique_count: int
    tactic_count: int
    clusters_with_techniques: int
    total_clusters: int
    scope_cluster_id: Optional[int] = None

    @property
    def is_empty(self) -> bool:
        return self.technique_count == 0

    @property
    def uncovered_tactics(self) -> List[str]:
        """Canonical tactics with zero mapped techniques, in kill-chain order."""
        return [t for t, n in self.coverage if n == 0 and t in MITRE_TACTIC_ORDER]

    @property
    def max_tactic_count(self) -> int:
        """Largest per-tactic count (the coverage bar's full-scale value)."""
        return max((n for _, n in self.coverage), default=0)


def _normalize_entry(entry: Any) -> Optional[Dict[str, str]]:
    """Coerce one ``mitre_attack`` entry (Pydantic model or dict) to a plain
    ``{id, tactic, name, rationale}`` dict, or ``None`` when it lacks an id.
    Mirrors the normalization in ``analyzer.generate_report_data`` but keeps
    tactic-less entries (they fall into :data:`UNSPECIFIED_TACTIC`)."""
    if hasattr(entry, "model_dump"):
        d = entry.model_dump()
    elif isinstance(entry, dict):
        d = entry
    else:
        return None
    tid = str(d.get("id", "") or "").strip()
    if not tid:
        return None
    return {
        "id": tid,
        "tactic": str(d.get("tactic", "") or "").strip(),
        "name": str(d.get("name", "") or "").strip(),
        "rationale": str(d.get("rationale", "") or "").strip(),
    }


def _walk(cluster: Any, hide_library: bool) -> Iterator[Any]:
    """Yield a cluster and its subclusters depth-first, optionally pruning
    library clusters (and their subtrees)."""
    if hide_library and getattr(cluster, "is_library", False):
        return
    yield cluster
    for sub in getattr(cluster, "subclusters", None) or []:
        yield from _walk(sub, hide_library)


def _find_cluster(clusters: List[Any], cluster_id: int) -> Optional[Any]:
    """Locate a cluster by id anywhere in the tree."""
    for c in clusters:
        if getattr(c, "id", None) == cluster_id:
            return c
        found = _find_cluster(getattr(c, "subclusters", None) or [], cluster_id)
        if found is not None:
            return found
    return None


def _iter_scope(
    clusters: List[Any], scope_cluster_id: Optional[int], hide_library: bool
) -> Iterator[Any]:
    """Iterate the clusters in scope. ``None`` scope walks every top-level
    cluster (respecting ``hide_library``); an explicit scope walks that
    cluster and its subclusters only (library pruning does not apply once
    the user has deliberately drilled into a cluster)."""
    if scope_cluster_id is None:
        for c in clusters:
            yield from _walk(c, hide_library)
        return
    target = _find_cluster(clusters, scope_cluster_id)
    if target is not None:
        yield from _walk(target, hide_library=False)


def _winning_tactic(votes: Dict[str, int]) -> str:
    """Pick a technique's tactic when clusters disagree: most votes, ties
    broken by earliest kill-chain position then name."""

    def rank(t: str) -> Tuple[int, int, str]:
        try:
            ko = MITRE_TACTIC_ORDER.index(t)
        except ValueError:
            ko = len(MITRE_TACTIC_ORDER) + 1
        return (-votes[t], ko, t)

    return sorted(votes.keys(), key=rank)[0]


def _order_tactics(tactics: List[str]) -> List[str]:
    """Canonical tactics first in kill-chain order, then any extras
    (alphabetical, with :data:`UNSPECIFIED_TACTIC` always last)."""
    canonical = [t for t in MITRE_TACTIC_ORDER if t in tactics]
    extras = [t for t in tactics if t not in MITRE_TACTIC_ORDER]
    extras.sort(key=lambda t: (t == UNSPECIFIED_TACTIC, t))
    return canonical + extras


def aggregate_mitre_matrix(
    clusters: List[Any],
    cluster_analysis: Optional[Dict[str, Any]],
    scope_cluster_id: Optional[int] = None,
    hide_library: bool = False,
) -> MitreMatrix:
    """Roll per-cluster ``mitre_attack`` lists up into a binary-wide (or
    cluster-scoped) :class:`MitreMatrix`.

    Args:
        clusters: top-level :class:`FunctionalCluster` objects (subclusters
            are walked recursively).
        cluster_analysis: the analyzer's ``cluster_analysis`` dict
            (``{"clusters": {key: {..., "mitre_attack": [...]}}}``).
        scope_cluster_id: restrict to this cluster + its subclusters; when
            ``None``, aggregate the whole binary.
        hide_library: when aggregating the whole binary, skip library
            clusters (mirrors the clusters view's L toggle). Ignored when a
            scope is given.

    Returns:
        A :class:`MitreMatrix`; ``is_empty`` is ``True`` when nothing maps.
    """
    rollups: Dict[str, TechniqueRollup] = {}
    name_candidates: Dict[str, str] = {}
    tactic_votes: Dict[str, Dict[str, int]] = {}
    total_clusters = 0
    clusters_with = 0

    for cluster in _iter_scope(clusters, scope_cluster_id, hide_library):
        total_clusters += 1
        analysis = find_cluster_analysis(cluster_analysis or {}, cluster.id)
        if not analysis:
            continue
        if isinstance(analysis, dict):
            raw = analysis.get("mitre_attack") or []
            label = str(analysis.get("label") or "")
        else:
            raw = getattr(analysis, "mitre_attack", None) or []
            label = str(getattr(analysis, "label", "") or "")

        got_one = False
        for entry in raw:
            norm = _normalize_entry(entry)
            if not norm:
                continue
            got_one = True
            key = norm["id"].upper()
            tactic = norm["tactic"] or UNSPECIFIED_TACTIC
            roll = rollups.get(key)
            if roll is None:
                roll = TechniqueRollup(id=norm["id"], name=norm["name"], tactic=tactic)
                rollups[key] = roll
            roll.groundings.append(
                TechniqueGrounding(cluster.id, label, norm["rationale"])
            )
            if len(norm["name"]) > len(name_candidates.get(key, "")):
                name_candidates[key] = norm["name"]
            tactic_votes.setdefault(key, {})
            tactic_votes[key][tactic] = tactic_votes[key].get(tactic, 0) + 1
        if got_one:
            clusters_with += 1

    # Finalize the canonical name + tactic for each unique technique.
    for key, roll in rollups.items():
        if name_candidates.get(key):
            roll.name = name_candidates[key]
        votes = tactic_votes.get(key)
        if votes:
            roll.tactic = _winning_tactic(votes)

    # Group techniques by their resolved tactic.
    groups: Dict[str, List[TechniqueRollup]] = {}
    for roll in rollups.values():
        groups.setdefault(roll.tactic, []).append(roll)

    # Within a tactic: broadest coverage first, then technique id.
    for techs in groups.values():
        techs.sort(key=lambda t: (-t.cluster_count, t.id))

    ordered = _order_tactics(list(groups.keys()))
    tactic_groups = [TacticGroup(t, groups[t]) for t in ordered]

    counted = {t: len(techs) for t, techs in groups.items()}
    coverage: List[Tuple[str, int]] = [(t, counted.get(t, 0)) for t in MITRE_TACTIC_ORDER]
    for t in ordered:
        if t not in MITRE_TACTIC_ORDER:
            coverage.append((t, counted.get(t, 0)))

    return MitreMatrix(
        tactics=tactic_groups,
        coverage=coverage,
        technique_count=len(rollups),
        tactic_count=len(tactic_groups),
        clusters_with_techniques=clusters_with,
        total_clusters=total_clusters,
        scope_cluster_id=scope_cluster_id,
    )


# =============================================================================
# Standard-format export (Navigator layer / STIX 2.1 / CSV)
# =============================================================================

# ATT&CK spec / layer versions stamped into exports. The Navigator is lenient
# about these; layer 4.5 is widely supported.
_ATTACK_SPEC_VERSION = "15"
_NAVIGATOR_VERSION = "4.9.5"
_LAYER_VERSION = "4.5"

# Fixed namespace so STIX ids are deterministic (uuid5) — re-exporting the same
# technique yields a stable id (good for TIP de-dup) and keeps tests stable.
_STIX_NAMESPACE = uuid.UUID("6ba7b814-9dad-11d1-80b4-00c04fd430c8")


def _tactic_shortname(tactic: str) -> str:
    """ATT&CK tactic shortname (``'Defense Evasion'`` -> ``'defense-evasion'``).
    Empty for non-canonical buckets like :data:`UNSPECIFIED_TACTIC`."""
    if tactic in MITRE_TACTIC_ORDER:
        return tactic.strip().lower().replace(" ", "-")
    return ""


def _max_score(matrix: "MitreMatrix") -> int:
    return max((t.cluster_count for g in matrix.tactics for t in g.techniques), default=1)


def has_any_techniques(cluster_analysis: Optional[Dict[str, Any]]) -> bool:
    """Cheap predicate (no full aggregation): does any cluster carry at least
    one technique with an id? Gates the 'View ATT&CK matrix' menu/popup
    actions so they only enable when there's actually a matrix to render."""
    if not cluster_analysis:
        return False
    clusters = cluster_analysis.get("clusters") if isinstance(cluster_analysis, dict) else None
    if not isinstance(clusters, dict):
        return False
    for entry in clusters.values():
        raw = entry.get("mitre_attack") if isinstance(entry, dict) else getattr(entry, "mitre_attack", None)
        for tech in raw or []:
            if _normalize_entry(tech):
                return True
    return False


def to_navigator_layer(matrix: "MitreMatrix", name: str = "xrefer ATT&CK matrix",
                       description: str = "") -> Dict[str, Any]:
    """Serialize to a MITRE ATT&CK Navigator layer (schema 4.5).

    Per technique: ``score`` = number of grounding clusters (drives the heat
    gradient), ``comment`` = representative rationale, ``metadata`` = name +
    clusters, ``tactic`` = the kill-chain shortname so the cell lands in the
    right column. Import the resulting JSON into the ATT&CK Navigator web app.
    """
    techniques: List[Dict[str, Any]] = []
    for group in matrix.tactics:
        shortname = _tactic_shortname(group.tactic)
        for t in group.techniques:
            entry: Dict[str, Any] = {
                "techniqueID": t.id,
                "score": t.cluster_count,
                "enabled": True,
                "metadata": [
                    {"name": "name", "value": t.name or ""},
                    {"name": "clusters", "value": ", ".join(f"{c:04d}" for c in t.cluster_ids)},
                ],
            }
            if t.representative_rationale:
                entry["comment"] = t.representative_rationale
            if shortname:
                entry["tactic"] = shortname
            techniques.append(entry)
    return {
        "name": name,
        "versions": {
            "attack": _ATTACK_SPEC_VERSION,
            "navigator": _NAVIGATOR_VERSION,
            "layer": _LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": description,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe8e8", "#ff8a8a", "#b30000"],
            "minValue": 0,
            "maxValue": _max_score(matrix),
        },
        "legendItems": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "hideDisabled": False,
    }


def to_stix_bundle(matrix: "MitreMatrix", created: Optional[str] = None,
                   name: str = "xrefer ATT&CK matrix") -> Dict[str, Any]:
    """Serialize to a STIX 2.1 bundle of ``attack-pattern`` SDOs.

    Each technique becomes an attack-pattern with a ``mitre-attack`` external
    reference (so consumers resolve the T-id), a kill-chain phase, and custom
    ``x_xrefer_*`` properties carrying the grounding clusters. Ids are
    deterministic (uuid5). ``created`` should be an ISO-8601 UTC timestamp;
    the GUI passes the current time, tests pass a fixed one.
    """
    stamp = created or "1970-01-01T00:00:00.000Z"
    objects: List[Dict[str, Any]] = []
    for group in matrix.tactics:
        phase = _tactic_shortname(group.tactic)
        for t in group.techniques:
            ap_id = "attack-pattern--" + str(
                uuid.uuid5(_STIX_NAMESPACE, f"attack-pattern:{t.id.upper()}")
            )
            ref: Dict[str, Any] = {"source_name": "mitre-attack", "external_id": t.id}
            if t.url:
                ref["url"] = t.url
            obj: Dict[str, Any] = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": stamp,
                "modified": stamp,
                "name": t.name or t.id,
                "external_references": [ref],
                "x_xrefer_clusters": [f"{c:04d}" for c in t.cluster_ids],
                "x_xrefer_cluster_count": t.cluster_count,
            }
            if t.representative_rationale:
                obj["description"] = t.representative_rationale
            if phase:
                obj["kill_chain_phases"] = [
                    {"kill_chain_name": "mitre-attack", "phase_name": phase}
                ]
            objects.append(obj)
    return {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid5(_STIX_NAMESPACE, f"bundle:{name}")),
        "objects": objects,
    }


def to_csv(matrix: "MitreMatrix") -> str:
    """Flat CSV: tactic, technique id, name, #clusters, clusters, rationale."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["tactic", "technique_id", "name", "cluster_count", "clusters", "rationale"])
    for group in matrix.tactics:
        for t in group.techniques:
            writer.writerow([
                group.tactic,
                t.id,
                t.name,
                t.cluster_count,
                " ".join(f"{c:04d}" for c in t.cluster_ids),
                t.representative_rationale,
            ])
    return buf.getvalue()
