#!/usr/bin/env python3
"""chain-merger.py — attack-path graph construction for the attack-path-stitcher skill.

Read-only: consumes validated findings + an org-surface graph, emits
attack-paths.json / attack-paths.dot / attack-paths.md per the SKILL.md schema.

Edge detectors are data-driven: the analyst derives detector rows per
reference/edge-detectors.md and records them as sections in org-surface.json
(credential_reuse, shared_secrets, ad_hops, iam_chains, ssrf_reach,
trust_edges, supply_chains). This tool enforces the schema, dedups, computes
reachability closure, and splits confirmed vs inferred paths.

Usage:
  chain-merger.py --surface artifacts/org-surface.json \
                  --validated artifacts/validated \
                  --out artifacts [--max-depth 8] [--edge-cap 50000] [--topn 10]
"""
import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone

VALID_FEASIBILITY = {1.0, 0.5, 0.25}

# org-surface.json section -> detector id
SECTION_DETECTOR = {
    "credential_reuse": "credential-reuse",
    "shared_secrets": "shared-secret",
    "trust_edges": "trust-zone-transitive",
    "ad_hops": "ad-path",
    "iam_chains": "cloud-iam-chain",
    "ssrf_reach": "ssrf-reach",
    "supply_chains": "supply-chain",
}


def warn(msg):
    print(f"WARN: {msg}", file=sys.stderr)


def load_validated(validated_dir):
    """Rule 9: drop rows missing finding_id/asset(asset_tag) or verdict != VALID."""
    rows = []
    for path in sorted(glob.glob(os.path.join(validated_dir, "*.json"))):
        try:
            with open(path) as fh:
                d = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            warn(f"{path}: unreadable ({exc}) — dropped")
            continue
        fid = d.get("finding_id")
        asset = d.get("asset") or d.get("asset_tag")
        if not fid or not asset:
            warn(f"{path}: missing finding_id or asset — dropped")
            continue
        if d.get("verdict") != "VALID":
            warn(f"{fid}: verdict={d.get('verdict')!r} != VALID — dropped")
            continue
        rows.append({
            "finding_id": fid,
            "asset_tag": asset,
            "cvss": d.get("cvss_score") or 0.0,
            "severity": d.get("severity", ""),
            "title": (d.get("report_fields") or {}).get("title", ""),
        })
    return rows


def build_graph(surface, findings):
    by_id = {f["finding_id"]: f for f in findings}
    finding_assets = surface.get("finding_assets", {})

    nodes = {}
    for a in surface.get("assets", []):
        nid = a.get("id")
        if not nid:
            warn("surface asset without id — dropped")
            continue
        fids = a.get("findings", [])
        known = [f for f in fids if f in by_id]
        unknown = [f for f in fids if f not in by_id]
        for f in unknown:
            warn(f"{nid}: finding {f} not in validated tree — kept as label only")
        nodes[nid] = {
            "id": nid,
            "tier": a.get("tier", "unknown"),
            "services": a.get("services", []),
            "zone": a.get("zone", "unknown"),
            "external": bool(a.get("external", False)),
            "findings": fids,
            "max_cvss": max([by_id[f]["cvss"] for f in known], default=0.0),
        }

    edges = []
    seen = set()
    edge_cap = 0  # enforced by caller arg later
    for section, detector in SECTION_DETECTOR.items():
        for row in surface.get(section, []):
            src, dst = row.get("src"), row.get("dst")
            if not src or not dst:
                warn(f"{section}: edge row missing src/dst — dropped")
                continue
            for node in (src, dst):
                if node not in nodes:
                    warn(f"{section}: edge references unknown node {node} — dropped")
                    break
            else:
                feas = float(row.get("feasibility", 0.25))
                if feas not in VALID_FEASIBILITY:
                    warn(f"{section}: feasibility {feas} not in {sorted(VALID_FEASIBILITY)} — snapped to 0.25")
                    feas = 0.25
                key = (src, dst, detector)
                if key in seen:
                    for e in edges:
                        if (e["src"], e["dst"], e["detector"]) == key:
                            for f in row.get("findings", []):
                                if f not in e["via_findings"]:
                                    e["via_findings"].append(f)
                            break
                    continue
                seen.add(key)
                edges.append({
                    "src": src,
                    "dst": dst,
                    "detector": detector,
                    "via_findings": list(row.get("findings", [])),
                    "evidence": row.get("evidence", ""),
                    "feasibility": feas,
                })
    return nodes, edges


def backward_paths(nodes, edges, jewel, max_depth):
    """All simple external->jewel paths (reverse DFS enumeration, depth-capped)."""
    rev = {}
    for e in edges:
        rev.setdefault(e["dst"], []).append(e)
    results = []
    truncated = [0]

    def walk(node, trail, edge_trail):
        if edge_trail and nodes[node]["external"]:
            results.append((list(reversed(trail)), list(reversed(edge_trail))))
        if len(trail) - 1 >= max_depth:
            if rev.get(node):
                truncated[0] += 1
            return
        for e in rev.get(node, []):
            if e["src"] in trail:
                continue
            walk(e["src"], trail + [e["src"]], edge_trail + [e])

    walk(jewel, [jewel], [])
    return results, truncated[0]


def classify_and_rank(nodes, edges, jewels, max_depth, topn):
    confirmed, inferred = [], []
    dropped = depth_truncated = 0
    for jewel in jewels:
        if jewel not in nodes:
            warn(f"crown jewel {jewel} not in assets — skipped")
            continue
        conf_paths, inf_paths = [], []
        paths, trunc = backward_paths(nodes, edges, jewel, max_depth)
        depth_truncated += trunc
        for hops, edge_trail in paths:
            feas = min(e["feasibility"] for e in edge_trail)
            max_cvss = max(nodes[n]["max_cvss"] for n in hops)
            entry = {
                "hops": hops,
                "edges": [{k: e[k] for k in ("src", "dst", "detector", "feasibility", "via_findings")}
                          for e in edge_trail],
                "feasibility": feas,
                "max_cvss": max_cvss,
                "hop_count": len(edge_trail),
            }
            is_confirmed = all(
                e["feasibility"] == 1.0 and e["via_findings"] for e in edge_trail)
            entry["path_class"] = "confirmed" if is_confirmed else "inferred"
            (conf_paths if is_confirmed else inf_paths).append(entry)
        key = lambda p: p["feasibility"] * p["max_cvss"] / p["hop_count"]
        for bucket, lst in (("confirmed", conf_paths), ("inferred", inf_paths)):
            lst.sort(key=key, reverse=True)
            dropped += max(0, len(lst) - topn)
            trimmed = lst[:topn]
            if bucket == "confirmed" and trimmed:
                confirmed.append({"jewel": jewel, "paths": trimmed})
            elif bucket == "inferred" and trimmed:
                inferred.append({"jewel": jewel, "paths": trimmed})
    return confirmed, inferred, dropped, depth_truncated


def entry_points(nodes, edges, confirmed, inferred):
    starts = set()
    for group in (confirmed, inferred):
        for j in group:
            for p in j["paths"]:
                starts.add(p["hops"][0])
    return sorted(n for n in starts if nodes[n]["external"])


def write_dot(nodes, edges, jewels, path):
    lines = ["digraph attack_paths {", '  rankdir=LR;']
    for n in nodes.values():
        shape = "doubleoctagon" if n["id"] in jewels else ("box" if n["external"] else "ellipse")
        style = ", style=filled, fillcolor=gold" if n["id"] in jewels else ""
        label = f'{n["id"]}\\n[{n["tier"]}] {len(n["findings"])}f cvss{n["max_cvss"]}'
        lines.append(f'  "{n["id"]}" [shape={shape}{style}, label="{label}"];')
    for e in edges:
        color = "green" if e["feasibility"] == 1.0 else ("orange" if e["feasibility"] == 0.5 else "gray")
        lines.append(f'  "{e["src"]}" -> "{e["dst"]}" [color={color}, '
                     f'label="{e["detector"]} f={e["feasibility"]}"];')
    lines.append("}")
    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


def write_md(nodes, edges, confirmed, inferred, path):
    out = ["# Attack Paths — ranked (generated by chain-merger.py)", ""]
    out.append(f"*Nodes: {len(nodes)} · edges: {len(edges)} · "
               f"confirmed path groups: {len(confirmed)} · inferred path groups: {len(inferred)}*")
    out.append("")
    out.append("## Confirmed attack paths (every edge feasibility 1.0 with validated findings)")
    if not confirmed:
        out.append("")
        out.append("_None — no multi-hop pivot was demonstrated end-to-end. Every candidate "
                   "chain contains at least one conditional hop (see inferred below)._")
    for j in confirmed:
        out.append(f"\n### → {j['jewel']}")
        for p in j["paths"]:
            fids = sorted({f for e in p["edges"] for f in e["via_findings"]})
            out.append(f"- **{' → '.join(p['hops'])}** (f={p['feasibility']}, "
                       f"max_cvss={p['max_cvss']}, {p['hop_count']} hop(s)) — via {', '.join(fids)}")
    out.append("\n## Inferred attack paths (analyst review; excluded from confirmed SLA buckets)")
    for j in inferred:
        out.append(f"\n### → {j['jewel']}")
        for p in j["paths"]:
            fids = sorted({f for e in p["edges"] for f in e["via_findings"]})
            det = ", ".join(sorted({e["detector"] for e in p["edges"]}))
            out.append(f"- **{' → '.join(p['hops'])}** (f={p['feasibility']}, "
                       f"max_cvss={p['max_cvss']}, {p['hop_count']} hop(s)) — detectors: {det}; "
                       f"via {', '.join(fids) or 'no findings (topology only)'}")
    out.append("\n## Edge inventory")
    for e in edges:
        out.append(f"- `{e['src']}` → `{e['dst']}` [{e['detector']}, f={e['feasibility']}] "
                   f"via {', '.join(e['via_findings']) or '—'} — {e['evidence']}")
    with open(path, "w") as fh:
        fh.write("\n".join(out) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--surface", required=True)
    ap.add_argument("--validated", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-depth", type=int, default=8)
    ap.add_argument("--edge-cap", type=int, default=50000)
    ap.add_argument("--topn", type=int, default=10)
    args = ap.parse_args()

    with open(args.surface) as fh:
        surface = json.load(fh)
    findings = load_validated(args.validated)
    nodes, edges = build_graph(surface, findings)

    edge_cap_hit = False
    if len(edges) > args.edge_cap:
        edges = edges[:args.edge_cap]
        edge_cap_hit = True

    jewels = surface.get("crown_jewels", [])
    confirmed, inferred, topn_dropped, depth_truncated = classify_and_rank(
        nodes, edges, jewels, args.max_depth, args.topn)

    graph = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nodes": list(nodes.values()),
        "edges": edges,
        "entry_points": entry_points(nodes, edges, confirmed, inferred),
        "confirmed_paths": confirmed,
        "inferred_paths": inferred,
        "truncation": {
            "edge_cap_hit": edge_cap_hit,
            "depth_truncated_count": depth_truncated,
            "topn_dropped_count": topn_dropped,
            "max_depth": args.max_depth,
            "edge_cap": args.edge_cap,
        },
    }
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "attack-paths.json"), "w") as fh:
        json.dump(graph, fh, indent=2)
    write_dot(nodes, edges, jewels, os.path.join(args.out, "attack-paths.dot"))
    write_md(nodes, edges, confirmed, inferred, os.path.join(args.out, "attack-paths.md"))
    print(f"OK nodes={len(nodes)} edges={len(edges)} confirmed_groups={len(confirmed)} "
          f"inferred_groups={len(inferred)} entry_points={graph['entry_points']}")


if __name__ == "__main__":
    main()
