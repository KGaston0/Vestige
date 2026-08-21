# VESTIGE — System Context & North Star Vision

**Version:** 2.0.0 — Graph Engine Pivot  
**Date:** August 2026  
**Status:** Active Development — UX/UI Core Redesign  

---

## 1. Project Identity

Vestige is a **tactical, offline, ephemeral visual forensic tool** for post-incident analysis. It ingests raw Linux server logs (`auth.log`, Apache/Nginx `access.log`), constructs a multi-layer directed network topology, and renders an interactive **Kill Chain graph** in the browser to help forensic auditors detect lateral movement, privilege escalation, and web exploitation paths.

### Tech Stack

| Layer | Technology | Role |
| :--- | :--- | :--- |
| **Backend** | Python 3.11+, FastAPI, Uvicorn | REST API, SSE streaming, session management |
| **ETL Engine** | Polars (Rust-backed SIMD) | Multi-threaded log parsing & schema normalization |
| **Graph Analytics** | Rustworkx / NetworkX, SciPy | Topology construction, anomaly scoring, clustering |
| **Frontend** | React 18, Vite, TypeScript | Dashboard shell, state management |
| **Graph Renderer** | Sigma.js + Graphology (WebGL) | Hardware-accelerated canvas, 60 FPS rendering |
| **Layout** | Graphology plugins, Web Workers | ForceAtlas2 (optional), deterministic DAG positioning |

### Data Model

Fully ephemeral. No persistent storage. Upload → parse → visualize → export → wipe.

- **SSH stream:** `[timestamp, src_ip, dest_host, user, auth_method, auth_result]`
- **HTTP stream:** `[timestamp, src_ip, uri, verb, status_code, bytes_sent]`
- Both normalized to: `[timestamp, source_ip, protocol, action, target, metadata]`

---

## 2. The Problem: Why We Are Pivoting

### What Is Broken

The current graph rendering pipeline sends **every** noise-reduced node and edge to the frontend in a single payload. On real-world forensic logs (200MB+ `auth.log` + `access.log`), this produces **5,000+ nodes** arranged in three rigid vertical columns with thousands of crossing edges. The result:

1. **The "Hairball" Effect.** Thousands of edges overlap into an opaque vertical stripe. The forensic topology is completely illegible.
2. **Instant Cognitive Overload.** An auditor opening the graph is confronted with thousands of unlabeled dots. There is no entry point, no narrative, no hierarchy. Critical attack chains are buried in noise.
3. **Performance Cliff.** While Sigma.js handles 5,000 nodes at 60 FPS technically, the *visual* performance is zero — the auditor cannot extract any actionable intelligence from the rendering.
4. **No Progressive Disclosure.** The system exposes all detail at the same zoom level. There is no way to start with the big picture and drill into specifics.

### What The Backend Already Does Right

The existing backend has strong foundations that the pivot builds upon:

- **`AlgorithmicNoiseReducer`** already performs aggressive static-asset pruning, semantic URI collapsing (`/users/42/profile` → `/users/*`), brute-force detection, privilege-pivot flagging, and high-frequency baseline suppression.
- **`GraphBuilderEngine`** already collapses benign GET-only external IPs into a `host:background_web_noise` super-node.
- **Multi-Layer X-Band positioning** (External at X=0, Web at X=500, Internal at X=1000) is already deterministic.
- **The `/api/v1/expand/{session_id}/{super_node_id}` endpoint** already exists and the frontend `GraphCanvas.tsx` already handles `doubleClickNode` → `expandSuperNode()` flow.

**The gap is not in noise reduction — it is in *aggregation depth*.** The backend prunes noise but still emits individual nodes. It needs to go one level further and **cluster the surviving nodes into semantic Super-Nodes** before sending the initial payload.

---

## 3. The North Star: "Red Thread / Signal vs. Noise"

### Core Principle

> **The initial graph load must NEVER show thousands of raw nodes.**
> It must render instantly with a highly aggregated, high-level tactical overview:
> **The Signal (Red Thread)** — individual high-risk nodes and anomalous edges are preserved at full visibility.
> **The Noise** — all low-risk/benign traffic is aggressively aggregated into exactly 3 massive background Super-Nodes.

The auditor's workflow is:

```
┌────────────────┐     ┌─────────────────┐     ┌────────────────────┐
│  1. OVERVIEW   │ ──▶ │  2. INVESTIGATE  │ ──▶ │  3. DEEP INSPECT   │
│  ~30-50 nodes  │     │  Expand cluster  │     │  Raw events, IPs   │
│  Kill Chain    │     │  ~50-200 nodes   │     │  Timeline, export  │
│  Super-Nodes   │     │  within context  │     │                    │
└────────────────┘     └─────────────────┘     └────────────────────┘
```

1. **Overview (Level 0):** The auditor sees a clean, readable Kill Chain DAG with ~30–50 Super-Nodes. Each Super-Node has a semantic label (e.g., "External Scanners (47 IPs)", "Subnet 10.0.4.0/24 (12 hosts)", "API Endpoints (8 URIs)"). Attack chains between clusters are immediately visible as bold, colored edges.
2. **Investigate (Level 1):** The auditor double-clicks a Super-Node. The frontend calls `GET /api/v1/expand/{session_id}/{super_node_id}`. The cluster unfurls in-place, revealing its individual child nodes and internal edges, while the rest of the graph remains collapsed. The Kill Chain spatial context is preserved.
3. **Deep Inspect (Level 2):** The auditor clicks an individual node to view its detail panel: raw log lines, timestamps, user accounts, HTTP verbs, and status codes. Future: timeline scrubbing and PDF export.

---

## 4. Semantic Clustering Strategy

### 4.0 Signal vs. Noise Bifurcation Rule (The Red Thread)

This is the top-level architectural law applied *before* any other clustering:
1. **THE SIGNAL (Red Thread):** Any node with `risk_score >= 3.0` OR connected to at least one `is_anomalous=True` edge is **exempt** from clustering. They are kept as individual high-prominence nodes.
2. **THE NOISE:** All remaining benign/low-risk nodes are grouped into exactly **3 massive background Super-Nodes**, one per Kill Chain layer: `super:external_noise`, `super:web_surface`, and `super:internal_baseline`. 

The legacy sub-rules below (4.1–4.3) are superseded by this rule for the initial overview, but may be used when expanding one of the 3 massive background Super-Nodes.

### 4.1 External IP Clustering

All non-RFC1918 source IPs are clustered into semantic groups:

| Cluster Rule | Super-Node ID | Label Example | Criteria |
| :--- | :--- | :--- | :--- |
| **Background Web Noise** | `super:background_noise` | "Background Web Noise (312 IPs)" | GET-only, 200-status, no SSH, no anomalies (already implemented) |
| **External Scanners** | `super:external_scanners` | "External Scanners (47 IPs)" | IPs triggering ≥5 distinct 4xx paths OR probing multiple URI prefixes |
| **Active Threats** | `super:active_threats` | "Active Threats (3 IPs)" | IPs with `is_anomalous=true` edges: POST exploits, SSH brute-force, privilege pivots. **These remain as individual nodes, NOT clustered**, because each attacker IP is forensically significant |
| **Benign SSH Sources** | `super:benign_ssh` | "Routine SSH (8 IPs)" | External IPs with pure-baseline SSH (100% success, single user, high frequency) |

> **Critical Rule:** IPs involved in a `FULL_ATTACK_CHAIN` anomaly flag must **never** be clustered. They remain as individual nodes at the top of the External column with maximum visual prominence.

### 4.2 Internal Host Clustering

All RFC-1918 destination hosts are grouped by `/24` subnet:

| Cluster Rule | Super-Node ID | Label Example | Criteria |
| :--- | :--- | :--- | :--- |
| **Subnet Cluster** | `super:subnet:10.0.4.0/24` | "Subnet 10.0.4.0/24 (12 hosts)" | All hosts sharing the first 3 octets |
| **Isolated High-Risk** | *(individual node)* | "10.0.9.88 (Crown Jewel)" | Hosts with `risk_score ≥ 7.0` are excluded from clustering and rendered individually |

### 4.3 Web Layer Clustering

URL nodes are grouped by top-level path prefix:

| Cluster Rule | Super-Node ID | Label Example | Criteria |
| :--- | :--- | :--- | :--- |
| **API Prefix Group** | `super:url:/api` | "API Endpoints /api/* (23 URIs)" | All URL nodes sharing the first path segment |
| **Admin Panel** | `super:url:/admin` | "Admin Panel /admin/* (5 URIs)" | Grouped if ≥2 URL nodes share the prefix |
| **Anomalous Endpoints** | *(individual node)* | "POST /api/v1/upload" | URL nodes with `risk_score ≥ 5.0` remain individual |

### 4.4 Clustering Output Model

Each Super-Node in the presentation payload must include:

```typescript
interface SuperNodeModel extends NodeModel {
  node_type: 'SUPER_NODE';
  child_count: number;          // Number of individual nodes inside
  child_node_ids: string[];     // List of collapsed node IDs (for expand query)
  cluster_rule: string;         // Machine-readable rule key: 'subnet:/24', 'external_scanners', 'url_prefix:/api'
  is_expanded: boolean;         // Always false in initial payload
  aggregated_risk: number;      // Max risk_score among children
  aggregated_edge_count: number; // Total edges collapsed into/out of this cluster
}
```

---

## 5. Interactive Drill-Down Protocol

### 5.1 Expand Flow

```
Frontend                              Backend
   │                                     │
   │  GET /api/v1/expand/{sid}/{snid}    │
   │────────────────────────────────────▶│
   │                                     │  1. Retrieve session DataFrame
   │                                     │  2. Filter events matching cluster children
   │                                     │  3. Build individual nodes + internal edges
   │                                     │  4. Re-run noise reduction on the subset
   │                                     │  5. Assign X/Y coordinates within parent's
   │                                     │     spatial band (same layer X, spread on Y)
   │◀────────────────────────────────────│
   │  ExpandResponse { nodes, edges }    │
   │                                     │
   │  6. Remove Super-Node from canvas   │
   │  7. Insert child nodes at parent    │
   │     position, fanning on Y-axis     │
   │  8. Reconnect edges from neighbors  │
   │     to newly revealed children      │
   │  9. Sigma.refresh()                 │
```

### 5.2 Expand Response Contract

```json
{
  "parent_super_node_id": "super:subnet:10.0.4.0/24",
  "nodes": [
    {
      "id": "host:10.0.4.15",
      "label": "10.0.4.15 (Web Server)",
      "node_type": "HOST",
      "risk_score": 6.2,
      "x": 1000.0,
      "y": -30.0,
      "size": 3.0,
      "color": "#3B82F6",
      "metadata": { "layer": "internal", "subnet": "10.0.4.0/24" }
    }
  ],
  "edges": [
    {
      "id": "edge:198.51.100.42->host:10.0.4.15",
      "source": "host:198.51.100.42",
      "target": "host:10.0.4.15",
      "edge_type": "SSH_AUTH",
      "is_anomalous": true,
      "anomaly_flags": ["SSH_PRIVILEGE_PIVOT"]
    }
  ]
}
```

### 5.3 Context Preservation Rules

When a Super-Node is expanded:

1. **Kill Chain position is preserved.** Child nodes inherit the parent's X-band (layer column). They fan out vertically along the Y-axis within the parent's spatial slot.
2. **External edges are reconnected.** Any edge that previously connected a neighbor node to the Super-Node is redistributed: if the edge's original source/target exists among the child nodes, it is reconnected to the specific child. Otherwise, it connects to all children (fan-out).
3. **Collapse is supported.** The auditor should be able to re-collapse an expanded cluster back into its Super-Node (future feature, but the data model must support it).

---

## 6. Spatial Organization & Layout

### 6.1 Multi-Layer Kill Chain DAG

The X-axis represents the **attack progression** (Kill Chain stages):

```
X = 0                    X = 500                   X = 1000
┌──────────────┐         ┌──────────────┐          ┌──────────────┐
│   EXTERNAL   │  ────▶  │     WEB      │  ────▶   │   INTERNAL   │
│              │         │              │          │              │
│ Attacker IPs │         │ URL Nodes    │          │ SSH Targets  │
│ Scanners     │         │ Web Servers  │          │ Databases    │
│ Background   │         │ API Groups   │          │ Subnets      │
└──────────────┘         └──────────────┘          └──────────────┘
```

Node X-coordinates are **deterministic** — assigned by the backend based on layer classification. The frontend does **not** run force-directed layout by default.

### 6.2 Y-Axis Distribution (Anti-Overlap)

The current implementation spaces nodes along Y with a fixed `Y_SPACING = 18.0`. This fails at scale because 200 nodes × 18px = 3,600px of vertical span, pushing most nodes off-screen.

**New Y-axis strategy:**

1. **Dynamic spacing:** `Y_SPACING = min(18.0, canvas_height / node_count_in_layer)`. The spacing shrinks dynamically to fit all nodes within the visible viewport.
2. **Risk-weighted ordering:** Within each column, nodes are sorted by `risk_score` descending (highest risk at vertical center = visual focal point), with lower-risk nodes fanning outward.
3. **Sub-column jitter:** Nodes in dense layers get a slight X-offset (±15px) based on their risk tier to prevent perfect vertical alignment and improve edge readability.

### 6.3 Edge Bundling & Visual Hierarchy

Edges are the primary bottleneck of the "hairball" problem. The solution is a strict **two-tier visual hierarchy**:

| Edge Category | Size | Opacity | Color | Z-Index | Rendering |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Anomalous** (attack chain, brute force, privilege pivot) | `3.5` | `1.0` | Neon red/orange (`SIGNAL_EDGE_COLOR` / `SIGNAL_GLOW_COLOR`) | `3` | Curved arrow, always visible |
| **Normal** (benign traffic, baseline connections) | `0.3` | `0.05` | `rgba(30, 41, 59, 0.05)` (`NOISE_EDGE_COLOR`) — near-invisible | `0` | Curved arrow, visible only on hover/zoom |

**Edge Bundling (future enhancement):**
- Edges between the same two Super-Nodes should be merged into a single weighted bundle-edge with thickness proportional to `total_attempts`.
- When a Super-Node is expanded, the bundle-edge splits into individual child edges.

### 6.4 Label Culling

Labels are hidden by default (`labelRenderedSizeThreshold: 8`) and only appear:
- On **hover** (tooltip at bottom-left of canvas)
- On **zoom** into a region (labels emerge as nodes exceed the size threshold)
- For **Super-Nodes** (always show label since there are ≤50 of them)
- For **critical anomalous nodes** (risk_score ≥ 7.0)

---

## 7. Presentation Payload Contract (v2 — Clustered)

The initial payload sent from backend to frontend now contains **Super-Nodes** instead of raw nodes. Individual high-risk nodes are included alongside Super-Nodes.

```json
{
  "meta": {
    "session_id": "vestige_sess_1723150200",
    "timestamp": "2026-08-09T03:30:00Z",
    "log_filename": "auth.log, access.log",
    "total_lines_parsed": 85400,
    "valid_ssh_events": 12400,
    "valid_http_events": 73000,
    "processing_time_ms": 312.5,
    "noise_reduction_ratio": 0.94,
    "clustering_ratio": 0.97
  },
  "summary": {
    "total_nodes": 38,
    "total_edges": 52,
    "total_raw_nodes_before_clustering": 1247,
    "anomalous_edges_count": 7,
    "high_risk_nodes_count": 4,
    "detected_lateral_chains": 2,
    "super_node_count": 31,
    "individual_node_count": 7
  },
  "graph": {
    "nodes": [
      {
        "id": "host:198.51.100.42",
        "label": "198.51.100.42 (Active Threat)",
        "node_type": "HOST",
        "risk_score": 8.8,
        "x": 0.0,
        "y": 0.0,
        "size": 5.0,
        "color": "#EF4444",
        "metadata": {
          "layer": "external",
          "is_internal": false,
          "anomaly_flags_summary": ["WEB_EXPLOIT_POST", "SSH_PRIVILEGE_PIVOT", "FULL_ATTACK_CHAIN"]
        }
      },
      {
        "id": "super:external_scanners",
        "label": "External Scanners (47 IPs)",
        "node_type": "SUPER_NODE",
        "risk_score": 3.2,
        "x": 0.0,
        "y": 60.0,
        "size": 6.0,
        "color": "#7C3AED",
        "metadata": { "layer": "external" },
        "child_count": 47,
        "child_node_ids": ["host:203.0.113.10", "host:203.0.113.22", "..."],
        "cluster_rule": "external_scanners",
        "is_expanded": false,
        "aggregated_risk": 3.2,
        "aggregated_edge_count": 284
      },
      {
        "id": "super:background_noise",
        "label": "Background Web Noise (312 IPs)",
        "node_type": "SUPER_NODE",
        "risk_score": 0.5,
        "x": 0.0,
        "y": 120.0,
        "size": 8.0,
        "color": "#64748B",
        "metadata": { "layer": "external" },
        "child_count": 312,
        "child_node_ids": [],
        "cluster_rule": "background_noise",
        "is_expanded": false,
        "aggregated_risk": 0.5,
        "aggregated_edge_count": 4200
      },
      {
        "id": "url:/api/v1/upload",
        "label": "POST /api/v1/upload",
        "node_type": "URL",
        "risk_score": 7.5,
        "x": 500.0,
        "y": -30.0,
        "size": 4.0,
        "color": "#F59E0B",
        "metadata": { "layer": "web", "primary_verb": "POST" }
      },
      {
        "id": "super:url:/api",
        "label": "API Endpoints /api/* (23 URIs)",
        "node_type": "SUPER_NODE",
        "risk_score": 2.1,
        "x": 500.0,
        "y": 30.0,
        "size": 5.0,
        "color": "#7C3AED",
        "metadata": { "layer": "web" },
        "child_count": 23,
        "child_node_ids": ["url:/api/v1/users", "url:/api/v1/config", "..."],
        "cluster_rule": "url_prefix:/api",
        "is_expanded": false
      },
      {
        "id": "super:subnet:10.0.4.0/24",
        "label": "Subnet 10.0.4.0/24 (12 hosts)",
        "node_type": "SUPER_NODE",
        "risk_score": 4.5,
        "x": 1000.0,
        "y": -20.0,
        "size": 5.0,
        "color": "#7C3AED",
        "metadata": { "layer": "internal", "subnet": "10.0.4.0/24" },
        "child_count": 12,
        "child_node_ids": ["host:10.0.4.1", "host:10.0.4.15", "..."],
        "cluster_rule": "subnet:/24",
        "is_expanded": false
      },
      {
        "id": "host:10.0.9.88",
        "label": "10.0.9.88 (Crown Jewel DB)",
        "node_type": "HOST",
        "risk_score": 9.5,
        "x": 1000.0,
        "y": 60.0,
        "size": 5.0,
        "color": "#DC2626",
        "metadata": { "layer": "internal", "is_internal": true }
      }
    ],
    "edges": [
      {
        "id": "edge:198.51.100.42->url:/api/v1/upload",
        "source": "host:198.51.100.42",
        "target": "url:/api/v1/upload",
        "edge_type": "HTTP_REQUEST",
        "weight": 3.8,
        "total_attempts": 15,
        "is_anomalous": true,
        "anomaly_flags": ["WEB_EXPLOIT_POST"],
        "size": 3.0,
        "color": "#F59E0B"
      },
      {
        "id": "edge:198.51.100.42->host:10.0.9.88",
        "source": "host:198.51.100.42",
        "target": "host:10.0.9.88",
        "edge_type": "SSH_AUTH",
        "weight": 5.8,
        "total_attempts": 6,
        "successful_auths": 1,
        "failed_auths": 5,
        "distinct_users": ["root"],
        "is_anomalous": true,
        "anomaly_flags": ["SSH_PRIVILEGE_PIVOT", "FULL_ATTACK_CHAIN"],
        "size": 3.0,
        "color": "#DC2626",
        "style": "dashed"
      },
      {
        "id": "edge:super:external_scanners->super:url:/api",
        "source": "super:external_scanners",
        "target": "super:url:/api",
        "edge_type": "HTTP_REQUEST",
        "weight": 1.5,
        "total_attempts": 284,
        "is_anomalous": false,
        "anomaly_flags": [],
        "size": 0.3,
        "color": "rgba(55, 65, 81, 0.03)"
      }
    ]
  },
  "timeline": []
}
```

---

## 8. Implementation Inventory — What Exists vs. What's Needed

### ✅ Already Implemented

| Component | File | Status |
| :--- | :--- | :--- |
| Polars SSH parser | `backend/app/engine/log_parser.py` | ✅ Production-ready |
| Polars HTTP parser | `backend/app/engine/log_parser.py` | ✅ Production-ready |
| SSH noise reduction (brute-force, priv-pivot, baseline collapse) | `backend/app/engine/noise_reduction.py` | ✅ Vectorized Polars |
| HTTP noise reduction (static pruning, URI collapse, scanner detection) | `backend/app/engine/noise_reduction.py` | ✅ Vectorized Polars |
| Multi-layer X-band layout (3 columns) | `backend/app/engine/graph_builder.py` | ✅ Deterministic |
| Background web noise super-node | `backend/app/engine/graph_builder.py` | ✅ Single super-node |
| **Signal vs. Noise Bifurcation (Red Thread)** | `backend/app/engine/graph_builder.py` | ✅ Implemented |
| Expand API endpoint | `backend/app/api/v1/expand.py` | ✅ Wired up |
| Frontend Super-Node type + expand flow | `frontend/src/components/GraphCanvas.tsx` | ✅ Double-click → expand |
| **Red Thread Visual Hierarchy** | `frontend/src/components/GraphCanvas.tsx` | ✅ Implemented |
| Frontend `SuperNodeModel` TypeScript type | `frontend/src/types/graph.ts` | ✅ Defined |
| SSE streaming chunked ingestion | `backend/app/api/v1/ingest.py` | ✅ Working |
| Ephemeral session store | `backend/app/core/session_store.py` | ✅ In-memory DataFrame retention |

### 🔲 Needs Implementation

| Component | File | Description |
| :--- | :--- | :--- |
| **Y-axis dynamic spacing** | `backend/app/engine/graph_builder.py` | Replace fixed `Y_SPACING = 18.0` with dynamic spacing based on node count per layer (§6.2). |
| **Super-Node visual program** | `frontend/src/components/GraphCanvas.tsx` | The `SuperNodeProgram` (border ring) is already defined. Enhance: Super-Nodes should always show labels, have pulsing border animation for expandable clusters, and show child count badge. |
| **Cluster collapse (re-fold)** | `frontend/src/components/GraphCanvas.tsx` | Allow re-collapsing an expanded cluster back to its Super-Node. Button in detail panel or right-click context menu. |
| **Edge bundling** | `frontend/src/components/GraphCanvas.tsx` | Merge parallel edges between the same Super-Node pair into a single thick bundle. Split on expand. |
| **Pydantic v2 schema updates** | `backend/app/models/schema.py` | Add `SuperNodeModel` fields to the backend schema: `child_count`, `child_node_ids`, `cluster_rule`, `aggregated_risk`, `aggregated_edge_count`. Update `SummaryData` with `super_node_count`, `individual_node_count`, `total_raw_nodes_before_clustering`, `clustering_ratio` in `SessionMeta`. |

---

## 9. Critical Constraints & Non-Negotiables

1. **≤ 50 nodes on initial load.** If the clustering engine produces more than 50 nodes (Super-Nodes + individual high-risk nodes combined), it must increase aggregation aggressiveness (e.g., merge scanner + benign SSH into a single "Low-Risk External" super-node, or collapse all URL prefixes into a single "Web Endpoints" super-node).

2. **Attack chains must NEVER be hidden.** Individual nodes involved in `FULL_ATTACK_CHAIN` or `SSH_PRIVILEGE_PIVOT` anomaly flags are exempt from clustering. They must always render as individual, high-prominence nodes in the initial view.

3. **Expand must preserve spatial context.** When a Super-Node is expanded, child nodes must appear at the same X-band (Kill Chain layer) as the parent. They must not teleport to random positions or trigger a full graph re-layout.

4. **No force-directed layout by default.** ForceAtlas2 is available as an optional toggle (the atom button in the toolbar) but must NOT run automatically. The deterministic multi-layer DAG is the primary layout.

5. **Ephemeral architecture is sacred.** The session DataFrame is held in RAM only. There is no database. Session data is wiped when the auditor closes the browser tab or the session expires.

6. **Sub-second initial render.** The clustering engine + payload serialization must complete in < 500ms for a 200MB log file. The frontend must render the ~50-node graph in < 100ms. Total time from upload completion to visible graph: < 1 second.

---

## 10. Current File Map

```
Vestige/
├── ARCHITECTURE.md                      # Detailed technical specification (§1-5 of system design)
├── VESTIGE_CONTEXT.md                   # ← This file. North Star vision & implementation status.
├── README.md                            # Quickstart guide
├── run_dev.sh                           # Dev launcher (backend:8080 + frontend:3001)
├── run_prod.sh                          # Production build script
│
├── backend/
│   ├── main.py                          # FastAPI app entrypoint
│   ├── pyproject.toml                   # Python dependencies
│   └── app/
│       ├── api/v1/
│       │   ├── ingest.py                # POST /api/v1/analyze (SSE streaming)
│       │   └── expand.py                # GET /api/v1/expand/{sid}/{snid}
│       ├── core/
│       │   ├── config.py                # App configuration
│       │   └── session_store.py         # Ephemeral in-memory session manager
│       ├── engine/
│       │   ├── log_parser.py            # Polars SIMD dual-format parser
│       │   ├── noise_reduction.py       # Vectorized anomaly scoring & pruning
│       │   ├── graph_builder.py         # Multi-layer topology constructor
│       │   └── clustering.py            # 🔲 Semantic Super-Node clustering engine
│       └── models/
│           └── schema.py                # Pydantic v2 data contracts
│
├── frontend/
│   ├── package.json
│   ├── vite.config.ts
│   └── src/
│       ├── App.tsx                      # Main dashboard layout
│       ├── components/
│       │   └── GraphCanvas.tsx          # Sigma.js WebGL canvas + drill-down
│       └── types/
│           └── graph.ts                 # TypeScript payload type definitions
│
└── data/
    └── samples/                         # Test log files
```

---

## 11. Success Criteria

The pivot is successful when:

- [ ] An auditor uploads a 200MB combined `auth.log` + `access.log` and sees a clean, readable graph with ≤ 50 nodes within 1 second.
- [ ] Critical attack chains (web exploit → SSH pivot → internal host) are immediately visible as bold, colored edges between prominently-sized nodes — without any interaction.
- [ ] Double-clicking any Super-Node smoothly reveals its children within 200ms, with spatial context preserved.
- [ ] The expanded graph remains navigable at up to 500 visible nodes without performance degradation.
- [ ] Benign background noise (scanners, CDN traffic, cron jobs) is invisible unless the auditor explicitly drills into the corresponding Super-Node.