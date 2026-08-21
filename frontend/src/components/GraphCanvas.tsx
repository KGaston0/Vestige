import React, { useRef, useEffect, useState, useCallback, useMemo } from 'react';
import Graph from 'graphology';
import Sigma from 'sigma';
import FA2LayoutSupervisor from 'graphology-layout-forceatlas2/worker';
import forceAtlas2 from 'graphology-layout-forceatlas2';
import { EdgeCurvedArrowProgram } from '@sigma/edge-curve';
import { createNodeBorderProgram } from '@sigma/node-border';
import { NodeModel, EdgeModel, GraphData, SuperNodeModel, ExpandResponse, isSuperNode } from '../types/graph';
import { ZoomIn, ZoomOut, Maximize2, Loader2, Atom, Eye, EyeOff, Activity, X } from 'lucide-react';

interface GraphCanvasProps {
  graph: GraphData;
  selectedNode: NodeModel | null;
  onSelectNode: (node: NodeModel | null) => void;
  sessionId: string | null;
}

const API_BASE = 'http://localhost:8080';

// Maximum nodes to spawn in a starburst expansion.
// The backend already caps at 75; this is the frontend safety floor.
// Above this count the hub-edges alone would create a WebGL tube artifact.
const MAX_STARBURST_NODES = 60;

// Maximum hub-edges (parent → child) to draw.
// Set to 0 to disable hub edges entirely — they are the primary
// source of the white-tube artifact when hundreds of nodes expand.
const MAX_HUB_EDGES = 0;

// ── Multi-Layer X-Band Constants (must match backend LAYER_X) ─────────
const LAYER_X: Record<string, number> = {
  external: -800,
  web: 0,
  internal: 800,
};

// ── Color Palette (flat, no glow) ─────────────────────────────────────
const NODE_COLORS: Record<string, string> = {
  HOST: '#4B8BF5',
  JUMPBOX: '#E05252',
  SUBNET_GATEWAY: '#34B77F',
  USER_ACCOUNT: '#9B6FE8',
  URL: '#D4943A',
  WEB_SERVER: '#22A7C3',
  SUPER_NODE: '#9D5CE5',
};

// ── Red Thread: Signal vs. Noise visual constants ──────────────────────
//
// THE NOISE — background super-nodes and their edges render in very dark,
// nearly-invisible colours so they don't compete with the attack path.
const NOISE_NODE_COLOR   = '#1E293B';   // very dark slate — recessive mass
const NOISE_EDGE_COLOR   = 'rgba(30, 41, 59, 0.05)';
const NOISE_BORDER_COLOR = '#334155';   // slightly lighter slate border

// Aliases to fix reference errors from legacy code sections
const NORMAL_EDGE_COLOR = NOISE_EDGE_COLOR;
const SUPER_NODE_BORDER_COLOR = NOISE_BORDER_COLOR;

// THE SIGNAL (Red Thread) — anomalous nodes + edges at full opacity, z=3.
const SIGNAL_NODE_COLOR  = '#EF4444';   // solid red
const SIGNAL_EDGE_COLOR  = '#DC2626';   // deep red
const SIGNAL_GLOW_COLOR  = '#FF2D55';   // bright red for FULL_ATTACK_CHAIN


// Curvature constants for edge bundling
const BASE_CURVATURE = 0.18;
const CURVATURE_SPREAD = 0.12;  // max deviation from base

// Deterministic hash for reproducible curvature per edge
function hashString(str: string): number {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h + str.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

// ── Edge Bundling Thickness: log10-scaled on total_attempts ───────────
// An edge with 1 attempt → 0.3 px (noise floor).
// An edge with 100 attempts → ~1.5 px.
// An edge with 10 000 attempts → ~3 px.
// An edge with 100 000 attempts → ~3.75 px (cap at 4 px).
// The log scale prevents massive edges from dominating the screen.
function edgeSizeFromAttempts(totalAttempts: number, isAnomalous: boolean): number {
  const base = isAnomalous ? 1.2 : 0.3;
  const scale = Math.log10(Math.max(1, totalAttempts)) * 0.75;
  return Math.min(4.0, base + scale);
}

// ── Custom Node Border Program for Super-Nodes ────────────────────────
// We use a thin ABSOLUTE-PIXEL border (not relative) so the ring stays
// razor-thin regardless of node size. This eliminates the large halos
// that appeared when the border was a fraction of the node radius.
const SuperNodeProgram = createNodeBorderProgram({
  borders: [
    {
      size: { value: 2, mode: 'pixels' },  // 2 px fixed — never scales with node
      color: { attribute: 'borderColor' },
    },
  ],
});

export const GraphCanvas: React.FC<GraphCanvasProps> = ({
  graph: graphData,
  selectedNode,
  onSelectNode,
  sessionId,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const graphRef = useRef<Graph | null>(null);
  const sigmaRef = useRef<Sigma | null>(null);
  const fa2Ref = useRef<FA2LayoutSupervisor | null>(null);
  const animFrameRef = useRef<number>(0);
  const gridCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const expandSuperNodeRef = useRef<(id: string) => void>(() => {});
  const collapseFocusedClusterRef = useRef<() => void>(() => {});

  const [hoveredNode, setHoveredNode] = useState<NodeModel | null>(null);
  const [expandingNode, setExpandingNode] = useState<string | null>(null);
  const [layoutRunning, setLayoutRunning] = useState(false);
  const [showNoise, setShowNoise] = useState(false);
  const [showScans, setShowScans] = useState(false);

  // ── Starburst Focus Mode State ───────────────────────────────────────
  const [focusedCluster, setFocusedCluster] = useState<{
    parentId: string;
    parentX: number;
    parentY: number;
    childIds: Set<string>;         // all children (pre-existing + newly added)
    freshlyAddedIds: Set<string>;  // only nodes we spawned; safe to dropNode
    childEdgeIds: Set<string>;
    connectedNodeIds: Set<string>;
    wasCapped: boolean;
    totalAvailable: number;
  } | null>(null);

  // Memoized set for fast lookup in reducers
  const focusSet = useMemo(() => {
    if (!focusedCluster) return null;
    const all = new Set<string>(focusedCluster.childIds);
    all.add(focusedCluster.parentId);
    focusedCluster.connectedNodeIds.forEach((id) => all.add(id));
    return all;
  }, [focusedCluster]);

  // ── Collapse: Remove starburst children, reset camera ────────────────
  const collapseFocusedCluster = useCallback(() => {
    if (!focusedCluster || !graphRef.current) {
      setFocusedCluster(null);
      return;
    }
    const graph = graphRef.current;

    // Drop only FRESH child edges (starburst-spawned)
    focusedCluster.childEdgeIds.forEach((eid) => {
      if (graph.hasEdge(eid)) graph.dropEdge(eid);
    });

    // Drop only FRESHLY-ADDED nodes (never drop pre-existing base-topology nodes)
    focusedCluster.freshlyAddedIds.forEach((nid) => {
      if (graph.hasNode(nid)) graph.dropNode(nid);
    });

    // Strip starburst metadata from pre-existing nodes that were tagged
    focusedCluster.childIds.forEach((nid) => {
      if (!focusedCluster.freshlyAddedIds.has(nid) && graph.hasNode(nid)) {
        const meta = graph.getNodeAttribute(nid, 'metadata') || {};
        const { _starburst_child: _, _parent_cluster: __, ...cleanMeta } = meta;
        graph.setNodeAttribute(nid, 'metadata', cleanMeta);
      }
    });

    setFocusedCluster(null);

    if (sigmaRef.current) {
      sigmaRef.current.getCamera().animate(
        { x: 0.5, y: 0.5, ratio: 1, angle: 0 },
        { duration: 400 }
      );
      sigmaRef.current.refresh();
    }
  }, [focusedCluster]);

  // ── Starburst Drill-Down: Expand a Super-Node ────────────────────────
  const expandSuperNode = useCallback(async (superNodeId: string) => {
    if (!sessionId || !graphRef.current) return;

    // If same cluster is already focused, collapse it (toggle)
    if (focusedCluster?.parentId === superNodeId) {
      collapseFocusedCluster();
      return;
    }

    // If a different cluster is focused, collapse it first
    if (focusedCluster) {
      collapseFocusedCluster();
      // Small delay for visual clarity
      await new Promise((r) => setTimeout(r, 150));
    }

    const graph = graphRef.current;
    if (!graph.hasNode(superNodeId)) return;

    setExpandingNode(superNodeId);

    try {
      const response = await fetch(
        `${API_BASE}/api/v1/expand/${encodeURIComponent(sessionId)}/${encodeURIComponent(superNodeId)}`
      );

      if (!response.ok) {
        console.error(`Expand failed: ${response.status}`);
        return;
      }

      const data: ExpandResponse = await response.json();
      if (!data.nodes.length) {
        console.warn('Expand returned 0 nodes for', superNodeId);
        return;
      }

      const parentX = graph.getNodeAttribute(superNodeId, 'x') || 0;
      const parentY = graph.getNodeAttribute(superNodeId, 'y') || 0;

      // ── Hard cap: take only the first MAX_STARBURST_NODES (backend already sorted)
      const cappedNodes = data.nodes.slice(0, MAX_STARBURST_NODES);
      const cappedIds = new Set(cappedNodes.map((n) => n.id));
      const wasCapped = data.nodes.length > cappedNodes.length;

      // ── Multi-ring spiral layout ─────────────────────────────────────
      // Distribute nodes across concentric rings so no ring is crowded.
      // Ring 0 (inner): up to 8 nodes, Ring 1: up to 16, Ring 2: remainder.
      const RING_CAPACITY = [8, 16, 999];
      const RING_RADII    = [70, 130, 195];
      const childCount = cappedNodes.length;
      const angleOffset = -Math.PI / 2; // start from top

      // Sort: highest-risk to inner ring. Note: uses cappedNodes, not data.nodes.
      const sortedChildren = [...cappedNodes].sort((a, b) => b.risk_score - a.risk_score);

      const newChildIds = new Set<string>();
      const newChildEdgeIds = new Set<string>();
      const connectedNodeIds = new Set<string>();

      // freshlyAddedIds: only nodes we create here (not pre-existing base-topology nodes).
      // Used by collapseFocusedCluster to safely drop only the newly spawned nodes.
      const freshlyAddedIds = new Set<string>();

      // Ring cursor — advances across RING_CAPACITY buckets as nodes are placed
      let ringIdx = 0;
      let ringSlot = 0;

      sortedChildren.forEach((n) => {
        // Advance ring when current is full
        while (ringSlot >= RING_CAPACITY[ringIdx] && ringIdx < RING_RADII.length - 1) {
          ringIdx++;
          ringSlot = 0;
        }

        const nodesInThisRing = Math.min(
          RING_CAPACITY[ringIdx],
          childCount - RING_CAPACITY.slice(0, ringIdx).reduce((a, b) => a + b, 0)
        );
        const angle = angleOffset + (2 * Math.PI * ringSlot) / Math.max(1, nodesInThisRing);
        const r = RING_RADII[ringIdx];
        const cx = parentX + r * Math.cos(angle);
        const cy = parentY + r * Math.sin(angle);
        ringSlot++;

        const isHighRisk = n.risk_score >= 3.0;

        if (!graph.hasNode(n.id)) {
          // Brand-new node: spawn at starburst ring position with grow animation
          graph.addNode(n.id, {
            label: n.label || n.id,
            x: cx,
            y: cy,
            size: 0.1,
            _targetSize: isHighRisk ? 4.0 : 2.5,
            color: n.color || (isHighRisk ? SIGNAL_NODE_COLOR : '#4B8BF5'),
            borderColor: isHighRisk ? SIGNAL_NODE_COLOR : '#4B8BF5',
            risk_score: n.risk_score,
            node_type: n.node_type,
            metadata: { ...n.metadata, _starburst_child: true, _parent_cluster: superNodeId },
          });
          freshlyAddedIds.add(n.id);
        } else {
          // Pre-existing node (already in base topology): keep position, just tag it
          // so focal dimming treats it as part of this cluster.
          const existingMeta = graph.getNodeAttribute(n.id, 'metadata') || {};
          graph.setNodeAttribute(n.id, 'metadata', {
            ...existingMeta,
            _starburst_child: true,
            _parent_cluster: superNodeId,
          });
        }

        // Always register as a cluster child — this is what makes focal dimming work
        // for both newly spawned AND pre-existing nodes.
        newChildIds.add(n.id);
      });

      // Add child↔child edges (from expand API)
      data.edges.forEach((e) => {
        if (
          cappedIds.has(e.source) &&
          cappedIds.has(e.target) &&
          graph.hasNode(e.source) &&
          graph.hasNode(e.target) &&
          !graph.hasEdge(e.id)
        ) {
          const eCurvature = BASE_CURVATURE + (hashString(e.id) % 100) / 100 * CURVATURE_SPREAD;
          graph.addEdgeWithKey(e.id, e.source, e.target, {
            size: edgeSizeFromAttempts(e.total_attempts ?? 1, e.is_anomalous),
            color: e.is_anomalous ? getAnomalyEdgeColor(e.anomaly_flags) : 'rgba(148, 163, 184, 0.4)',
            weight: e.weight,
            is_anomalous: e.is_anomalous,
            edge_type: e.edge_type,
            anomaly_flags: e.anomaly_flags,
            total_attempts: e.total_attempts,
            type: 'curvedArrow',
            curvature: eCurvature,
            _starburst_edge: true,
          });
          newChildEdgeIds.add(e.id);

          // Track nodes connected to children that aren't children themselves
          if (!newChildIds.has(e.source)) connectedNodeIds.add(e.source);
          if (!newChildIds.has(e.target)) connectedNodeIds.add(e.target);
        }
      });

      // Hub edges: parent → child — intentionally disabled (MAX_HUB_EDGES = 0).
      // Drawing hundreds of hub edges from a single point creates the white-tube
      // WebGL artifact. We rely on focal dimming to show cluster membership instead.
      if (MAX_HUB_EDGES > 0) {
        let hubCount = 0;
        newChildIds.forEach((childId) => {
          if (hubCount >= MAX_HUB_EDGES) return;
          const hubEdgeId = `starburst:${superNodeId}->${childId}`;
          if (!graph.hasEdge(hubEdgeId)) {
            graph.addEdgeWithKey(hubEdgeId, superNodeId, childId, {
              size: 0.4,
              color: 'rgba(148, 163, 184, 0.15)',
              weight: 0.5,
              is_anomalous: false,
              type: 'curvedArrow',
              curvature: 0.05,
              _starburst_edge: true,
            });
            newChildEdgeIds.add(hubEdgeId);
            hubCount++;
          }
        });
      }

      // Set focused cluster state — include freshlyAddedIds so collapse knows
      // which nodes to drop (pre-existing nodes must NOT be dropped).
      setFocusedCluster({
        parentId: superNodeId,
        parentX,
        parentY,
        childIds: newChildIds,
        freshlyAddedIds,
        childEdgeIds: newChildEdgeIds,
        connectedNodeIds,
        wasCapped,
        totalAvailable: data.nodes.length,
      });

      // ── Spawn Animation: grow child nodes from 0 → target size ───────
      const animStart = performance.now();
      const ANIM_DURATION = 350;
      const animateSpawn = (now: number) => {
        const elapsed = now - animStart;
        const t = Math.min(1, elapsed / ANIM_DURATION);
        // Ease-out cubic
        const ease = 1 - Math.pow(1 - t, 3);

        newChildIds.forEach((nid) => {
          if (graph.hasNode(nid)) {
            const target = graph.getNodeAttribute(nid, '_targetSize') || 3;
            graph.setNodeAttribute(nid, 'size', target * ease);
          }
        });

        if (t < 1) {
          requestAnimationFrame(animateSpawn);
        }
      };
      requestAnimationFrame(animateSpawn);

      // ── Animate Camera to focus on the cluster ───────────────────────
      if (sigmaRef.current) {
        const viewCoords = sigmaRef.current.graphToViewport({ x: parentX, y: parentY });
        const normX = viewCoords.x / sigmaRef.current.getDimensions().width;
        const normY = viewCoords.y / sigmaRef.current.getDimensions().height;
        sigmaRef.current.getCamera().animate(
          { x: normX, y: normY, ratio: 0.25 },
          { duration: 500 }
        );
        sigmaRef.current.refresh();
      }
    } catch (err) {
      console.error('Failed to expand super-node:', err);
    } finally {
      setExpandingNode(null);
    }
  }, [sessionId, focusedCluster, collapseFocusedCluster]);

  // Keep refs in sync so init-time Sigma handlers always call latest version
  useEffect(() => {
    expandSuperNodeRef.current = expandSuperNode;
  }, [expandSuperNode]);
  useEffect(() => {
    collapseFocusedClusterRef.current = collapseFocusedCluster;
  }, [collapseFocusedCluster]);

  // ── ForceAtlas2 Layout (Y-axis only — X is locked to Kill Chain) ──────
  const restartLayout = useCallback((durationMs: number = 6000) => {
    if (!graphRef.current || graphRef.current.order < 2) return;

    if (fa2Ref.current) {
      fa2Ref.current.kill();
      fa2Ref.current = null;
    }

    const graph = graphRef.current;
    const order = graph.order;

    // Snapshot every node's X coordinate (Kill Chain layer position)
    const frozenX = new Map<string, number>();
    graph.forEachNode((nodeId, attrs) => {
      frozenX.set(nodeId, attrs.x || 0);
    });

    const settings = {
      gravity: 0.02,
      scalingRatio: 40,
      barnesHutOptimize: true,
      barnesHutTheta: 0.5,
      slowDown: 4 + Math.log10(Math.max(2, order)),
      adjustSizes: false,
      strongGravityMode: false,
      linLogMode: false,
      outboundAttractionDistribution: false,
      edgeWeightInfluence: 0.3,
    };

    const supervisor = new FA2LayoutSupervisor(graph, {
      settings,
      getEdgeWeight: 'weight',
    });

    fa2Ref.current = supervisor;
    setLayoutRunning(true);
    supervisor.start();

    // Continuously restore X coordinates while FA2 runs —
    // this constrains the physics to Y-axis only
    const xLockInterval = setInterval(() => {
      if (!graphRef.current) return;
      frozenX.forEach((x, nodeId) => {
        if (graphRef.current!.hasNode(nodeId)) {
          graphRef.current!.setNodeAttribute(nodeId, 'x', x);
        }
      });
    }, 50);

    setTimeout(() => {
      clearInterval(xLockInterval);
      if (fa2Ref.current === supervisor && supervisor.isRunning()) {
        supervisor.stop();
        // Final X-lock pass
        frozenX.forEach((x, nodeId) => {
          if (graphRef.current?.hasNode(nodeId)) {
            graphRef.current.setNodeAttribute(nodeId, 'x', x);
          }
        });
        setLayoutRunning(false);
      }
    }, durationMs);
  }, []);

  // ── Get anomaly edge color from flags (Red Thread palette) ──────────
  function getAnomalyEdgeColor(flags: string[] = []): string {
    if (!flags) flags = [];
    // Priority order: most severe anomaly wins
    const ANOMALY_COLORS: Record<string, string> = {
      FULL_ATTACK_CHAIN:        SIGNAL_GLOW_COLOR,  // '#FF2D55' brightest
      SSH_PRIVILEGE_PIVOT:      SIGNAL_GLOW_COLOR,
      PRIVILEGE_PIVOT:          '#FF3B30',
      BRUTE_FORCE_BURST:        '#FF3B30',
      WEB_EXPLOIT_POST:         '#E88A2D',
      RARE_PIVOT_PATH:          '#FF453A',
      HTTP_4XX_SCAN:            '#E88A2D',
      OFF_HOURS_ACCESS:         '#C4A020',
      HIGH_FREQUENCY_COLLAPSED: '#D06030',
    };
    for (const flag of Object.keys(ANOMALY_COLORS)) {
      if (flags.includes(flag)) return ANOMALY_COLORS[flag];
    }
    return SIGNAL_EDGE_COLOR;   // '#DC2626' — default signal red
  }

  // ── Infer layer from node data ───────────────────────────────────────
  function inferLayer(n: NodeModel): string {
    // Prefer backend-assigned layer
    if (n.metadata?.layer) return n.metadata.layer;
    // Fallback: infer from node_type
    if (n.node_type === 'URL' || n.node_type === 'WEB_SERVER') return 'web';
    if (n.node_type === 'SUPER_NODE') return 'external';
    // For HOSTs, check if label looks internal (RFC-1918)
    const label = n.label || n.id;
    if (label.startsWith('10.') || label.startsWith('192.168.') || label.startsWith('172.')) {
      return 'internal';
    }
    return 'external';
  }

  // ── Initialize Graph and Sigma renderer ──────────────────────────────
  useEffect(() => {
    if (!containerRef.current) return;

    const graph = new Graph({ multi: true, type: 'directed' });
    graphRef.current = graph;

    const sigma = new Sigma(graph, containerRef.current, {
      minCameraRatio: 0.005,
      maxCameraRatio: 20,
      renderEdgeLabels: false,
      labelFont: '"JetBrains Mono", "Fira Code", monospace',
      labelSize: 11,
      labelWeight: 'bold',
      labelColor: { color: '#CBD5E1' },

      // ── Label culling for density ────────────────────────────────────
      labelRenderedSizeThreshold: 9999, // NEVER render labels automatically (only on hover)
      labelDensity: 0.15,
      labelGridCellSize: 150,
      hideLabelsOnMove: true,

      defaultNodeColor: '#4B8BF5',
      defaultEdgeColor: NORMAL_EDGE_COLOR,
      defaultEdgeType: 'curvedArrow',
      minEdgeThickness: 0.2,
      zIndex: true,
      enableEdgeEvents: false,
      hideEdgesOnMove: false, // Keep edges visible during pan (fewer edges now)
      autoRescale: true,
      autoCenter: true,
      stagePadding: 50,

      nodeProgramClasses: {
        border: SuperNodeProgram,
      },
      edgeProgramClasses: {
        curvedArrow: EdgeCurvedArrowProgram,
      },

    });
    sigmaRef.current = sigma;

    // ── Event handlers ─────────────────────────────────────────────────
    sigma.on('clickNode', (event) => {
      const nodeId = event.node;
      const attrs = graph.getNodeAttributes(nodeId);
      onSelectNode({
        id: nodeId,
        label: attrs.label || nodeId,
        node_type: attrs.node_type || 'HOST',
        in_degree: graph.inDegree(nodeId),
        out_degree: graph.outDegree(nodeId),
        risk_score: attrs.risk_score || 1.0,
        x: attrs.x || 0,
        y: attrs.y || 0,
        size: attrs.size || 10,
        color: attrs.color || '#4B8BF5',
        metadata: attrs.metadata || {},
        ...(attrs.node_type === 'SUPER_NODE'
          ? {
              child_count: attrs.child_count || 0,
              child_node_ids: attrs.child_node_ids || [],
              cluster_rule: attrs.cluster_rule || '',
              is_expanded: false,
            }
          : {}),
      });
    });

    sigma.on('doubleClickNode', (event) => {
      event.preventSigmaDefault();
      const nodeId = event.node;
      const attrs = graph.getNodeAttributes(nodeId);
      if (attrs.node_type === 'SUPER_NODE' || attrs.metadata?.is_noise_super) {
        expandSuperNodeRef.current(nodeId);
      }
    });

    // ── Grid Rendering Hook ────────────────────────────────────────────
    const drawGrid = () => {
      const canvas = gridCanvasRef.current;
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      if (!ctx) return;

      // Match canvas size to display size
      const rect = canvas.getBoundingClientRect();
      if (canvas.width !== rect.width || canvas.height !== rect.height) {
        canvas.width = rect.width;
        canvas.height = rect.height;
      }

      ctx.clearRect(0, 0, canvas.width, canvas.height);

      const drawLine = (x1: number, y1: number, x2: number, y2: number) => {
        const p1 = sigma.graphToViewport({ x: x1, y: y1 });
        const p2 = sigma.graphToViewport({ x: x2, y: y2 });
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.stroke();
      };

      ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
      ctx.lineWidth = 1;
      ctx.setLineDash([8, 8]);

      // X lines (column separators)
      drawLine(-400, -2000, -400, 2000);
      drawLine(400, -2000, 400, 2000);

      // Y lines (row separators)
      drawLine(-2000, -400, 2000, -400);
      drawLine(-2000, 400, 2000, 400);

      // Labels
      const drawLabel = (x: number, y: number, text: string) => {
        const p = sigma.graphToViewport({ x, y });
        ctx.fillStyle = 'rgba(255, 255, 255, 0.15)';
        ctx.font = '11px monospace';
        ctx.textAlign = 'center';
        ctx.fillText(text, p.x, p.y);
      };

      // 3x3 Grid Zones
      drawLabel(-800, -850, "EXTERNAL : CRITICAL");
      drawLabel(0, -850, "WEB : CRITICAL");
      drawLabel(800, -850, "INTERNAL : CRITICAL");

      drawLabel(-800, -50, "EXTERNAL : SUSPICIOUS");
      drawLabel(0, -50, "WEB : SUSPICIOUS");
      drawLabel(800, -50, "INTERNAL : SUSPICIOUS");

      drawLabel(-800, 750, "EXTERNAL : NOISE");
      drawLabel(0, 750, "WEB : NOISE");
      drawLabel(800, 750, "INTERNAL : NOISE");
    };

    sigma.on('afterRender', drawGrid);

    // Resize observer to ensure grid canvas stays synced if window resizes
    const resizeObserver = new ResizeObserver(() => {
      if (sigmaRef.current) {
        sigmaRef.current.refresh();
      }
    });
    if (containerRef.current) {
      resizeObserver.observe(containerRef.current);
    }

    sigma.on('clickStage', () => {
      onSelectNode(null);
      // If a cluster is focused, collapse it on background click
      collapseFocusedClusterRef.current();
    });

    sigma.on('enterNode', (event) => {
      const nodeId = event.node;
      const attrs = graph.getNodeAttributes(nodeId);
      setHoveredNode({
        id: nodeId,
        label: attrs.label || nodeId,
        node_type: attrs.node_type || 'HOST',
        in_degree: graph.inDegree(nodeId),
        out_degree: graph.outDegree(nodeId),
        risk_score: attrs.risk_score || 1.0,
        x: attrs.x || 0,
        y: attrs.y || 0,
        size: attrs.size || 10,
        color: attrs.color || '#4B8BF5',
        metadata: attrs.metadata || {},
      });
    });

    sigma.on('leaveNode', () => { setHoveredNode(null); });

    return () => {
      if (fa2Ref.current) {
        fa2Ref.current.kill();
        fa2Ref.current = null;
      }
      resizeObserver.disconnect();
      sigma.off('afterRender', drawGrid);
      sigma.kill();
      graphRef.current = null;
      sigmaRef.current = null;
    };
  }, []);

  // ── Dynamic Reducers for Interaction, Noise Toggle & Focal Dimming ──
  useEffect(() => {
    if (!sigmaRef.current) return;

    sigmaRef.current.setSetting('nodeReducer', (node: string, data: any) => {
      // ── FOCAL DIMMING MODE ─────────────────────────────────────────
      if (focusedCluster && focusSet) {
        const isParent = node === focusedCluster.parentId;
        const isChild = focusedCluster.childIds.has(node);
        const isConnected = focusSet.has(node);

        if (isParent) {
          // Parent: show as a subtle anchor point, no border ring
          return {
            ...data,
            color: 'rgba(100, 116, 139, 0.3)',
            size: 5,
            zIndex: 2,
            type: 'circle',
            label: data.label,
          };
        }

        if (isChild) {
          // Starburst children: full prominence with forensic colors
          const isHighRisk = data.risk_score >= 3.0;
          return {
            ...data,
            color: 'transparent',
            size: data.size || 3,
            zIndex: 3,
            type: 'border',
            borderColor: isHighRisk ? SIGNAL_NODE_COLOR : '#4B8BF5',
            borderSize: 0.2,
            forceLabel: true,
          };
        }

        if (isConnected) {
          // Directly connected to a child: dimmed but visible
          return {
            ...data,
            color: 'rgba(51, 65, 85, 0.15)',
            size: Math.max(1.5, (data.size || 3) * 0.5),
            zIndex: 1,
            type: 'circle',
            label: '',
          };
        }

        // Everything else: aggressively dimmed
        return {
          ...data,
          color: 'rgba(30, 41, 59, 0.06)',
          size: 1,
          zIndex: 0,
          type: 'circle',
          label: '',
        };
      }

      // ── NORMAL MODE (no cluster focused) ───────────────────────────
      const isNoise = data.metadata?.is_noise_super || data.risk_score < 3.0;
      
      if (isNoise) {
        return { 
          ...data, 
          color: 'transparent', 
          size: data.metadata?.is_noise_super ? 8 : (data.size || 3.5), 
          zIndex: 1, 
          type: 'border', 
          borderColor: '#4B8BF5',
          borderSize: 0.2 
        };
      }
      
      // Signal nodes (Red Thread)
      return { 
        ...data, 
        color: 'transparent', 
        size: data.size || 5, 
        zIndex: 3, 
        type: 'border', 
        borderColor: SIGNAL_NODE_COLOR, 
        borderSize: 0.2 
      };
    });

    sigmaRef.current.setSetting('edgeReducer', (edge: string, data: any) => {
      const graph = graphRef.current;
      if (!graph) return data;

      const source = graph.source(edge);
      const target = graph.target(edge);

      // ── FOCAL DIMMING MODE ───────────────────────────────────────────
      if (focusedCluster && focusSet) {
        const isStarburstEdge = data._starburst_edge === true;
        const srcInFocus = focusedCluster.childIds.has(source) || source === focusedCluster.parentId;
        const tgtInFocus = focusedCluster.childIds.has(target) || target === focusedCluster.parentId;

        if (isStarburstEdge) {
          // Starburst hub/child edges: always show
          return { ...data, zIndex: 3, type: 'curvedArrow' };
        }

        if (srcInFocus && tgtInFocus) {
          // Edge between two focused nodes
          return { ...data, zIndex: 3, type: 'curvedArrow' };
        }

        if (srcInFocus || tgtInFocus) {
          // Edge connecting a focused node to the outside: dim but visible
          return {
            ...data,
            color: 'rgba(148, 163, 184, 0.12)',
            size: 0.4,
            zIndex: 1,
            type: 'curvedArrow',
          };
        }

        // Unrelated edge: hidden
        return { ...data, hidden: true, zIndex: 0, type: 'curvedArrow' };
      }

      // ── NORMAL MODE ─────────────────────────────────────────────────
      let isInteracted = false;
      const isConnectedToSelected = selectedNode && (source === selectedNode.id || target === selectedNode.id);
      const isConnectedToHovered = hoveredNode && (source === hoveredNode.id || target === hoveredNode.id);
      isInteracted = !!(isConnectedToSelected || isConnectedToHovered);

      if (data.is_anomalous) {
        const edgeColor = getAnomalyEdgeColor(data.anomaly_flags || []);
        
        const isScanEdge = edgeColor === '#E88A2D' || edgeColor === '#C4A020' || edgeColor === '#D06030';
        
        if (isScanEdge && !showScans && !isInteracted) {
          return { ...data, color: edgeColor, size: 0.5, zIndex: 1, type: 'curvedArrow', hidden: true };
        }

        // Preserve the log-scaled bundling thickness; floor at 1.5 so anomalous
        // edges are always clearly visible even with low attempt counts.
        const anomalySize = Math.max(1.5, data.size ?? edgeSizeFromAttempts(data.total_attempts ?? 1, true));
        return { ...data, color: edgeColor, size: anomalySize, zIndex: 3, type: 'curvedArrow' };
      }

      const shouldShow = showNoise || isInteracted;
      return { ...data, color: NOISE_EDGE_COLOR, size: 0.3, zIndex: 0, type: 'curvedArrow', hidden: !shouldShow };
    });
  }, [showNoise, showScans, selectedNode, hoveredNode, focusedCluster, focusSet]);

  // ── Incremental Graph Data Updates ───────────────────────────────────
  useEffect(() => {
    const graph = graphRef.current;
    if (!graph || !graphData) return;

    // Load ALL nodes — backend has already pruned to manageable count
    const displayNodes = graphData.nodes;

    // 1. Process Nodes — use backend-assigned multi-layer coordinates
    displayNodes.forEach((n) => {
      if (!graph.hasNode(n.id)) {
        // Use backend coordinates directly (multi-layer X-band layout)
        let initX = n.x;
        let initY = n.y;

        // Fallback ONLY if backend completely failed to assign coords (undefined)
        if (initX === undefined || initY === undefined) {
          const layer = inferLayer(n);
          initX = LAYER_X[layer] ?? 0;
          initY = (Math.random() - 0.5) * 800;
        }

        const isSuperNodeType = n.node_type === 'SUPER_NODE' || ('child_count' in n);

        graph.addNode(n.id, {
          label: n.label || n.id,
          x: initX,
          y: initY,
          size: n.size || 2,
          color: NODE_COLORS[n.node_type] || (n.risk_score >= 3.0 ? '#E05252' : '#4B8BF5'),
          borderColor: isSuperNodeType ? SUPER_NODE_BORDER_COLOR : undefined,
          risk_score: n.risk_score,
          node_type: isSuperNodeType ? 'SUPER_NODE' : n.node_type,
          metadata: n.metadata,
          ...(isSuperNodeType
            ? {
                child_count: (n as any).child_count || 0,
                child_node_ids: (n as any).child_node_ids || [],
                cluster_rule: (n as any).cluster_rule || '',
              }
            : {}),
        });
      } else {
        graph.setNodeAttribute(n.id, 'risk_score', n.risk_score);
        if (n.color) graph.setNodeAttribute(n.id, 'color', n.color);
        if (n.size) graph.setNodeAttribute(n.id, 'size', n.size);
      }
    });

    // 2. Process Edges — deterministic curvature with parallel-edge offset
    //    Track pair counts so parallel edges between the same nodes spread
    const pairCounts = new Map<string, number>();

    graphData.edges.forEach((e) => {
      if (graph.hasNode(e.source) && graph.hasNode(e.target)) {
        if (!graph.hasEdge(e.id)) {
          // Parallel-edge offset: each additional edge between same pair
          // gets progressively more curvature to avoid z-fighting
          const pairKey = `${e.source}|${e.target}`;
          const pairIdx = pairCounts.get(pairKey) || 0;
          pairCounts.set(pairKey, pairIdx + 1);

          const baseCurv = BASE_CURVATURE + (hashString(e.id) % 100) / 100 * CURVATURE_SPREAD;
          const parallelOffset = pairIdx * 0.08;
          const finalCurvature = baseCurv + parallelOffset;

          graph.addEdgeWithKey(e.id, e.source, e.target, {
            // ── Bundling thickness: log10-scale on total_attempts ────────
            // Computed once at insertion; edgeReducer may override for
            // interaction highlights but reads this as the baseline.
            size: edgeSizeFromAttempts(e.total_attempts ?? 1, e.is_anomalous),
            color: e.is_anomalous
              ? getAnomalyEdgeColor(e.anomaly_flags)
              : NORMAL_EDGE_COLOR,
            weight: e.weight,
            is_anomalous: e.is_anomalous,
            edge_type: e.edge_type,
            http_verb: e.http_verb,
            status_code: e.status_code,
            uri_path: e.uri_path,
            total_attempts: e.total_attempts,
            successful_auths: e.successful_auths,
            failed_auths: e.failed_auths,
            distinct_users: e.distinct_users,
            anomaly_flags: e.anomaly_flags,
            first_timestamp: e.first_timestamp,
            last_timestamp: e.last_timestamp,
            type: 'curvedArrow',
            curvature: finalCurvature,
          });
        }
      }
    });

    // No FA2 by default — backend provides clean column positions
    if (sigmaRef.current) {
      sigmaRef.current.refresh();
    }
  }, [graphData, showNoise]);

  // ── Camera Controls ──────────────────────────────────────────────────
  const handleZoomIn = () => {
    sigmaRef.current?.getCamera().animatedZoom({ duration: 200 });
  };
  const handleZoomOut = () => {
    sigmaRef.current?.getCamera().animatedUnzoom({ duration: 200 });
  };
  const handleResetCamera = () => {
    sigmaRef.current?.getCamera().animatedReset({ duration: 300 });
  };
  const handleToggleLayout = () => {
    if (fa2Ref.current && fa2Ref.current.isRunning()) {
      fa2Ref.current.stop();
      setLayoutRunning(false);
    } else {
      restartLayout(8000);
    }
  };

  return (
    <div className="relative w-full h-full bg-slate-950 overflow-hidden">
      <canvas ref={gridCanvasRef} className="absolute inset-0 w-full h-full pointer-events-none z-0" />
      <div ref={containerRef} className="absolute inset-0 w-full h-full z-10" />

      {/* Top Left Canvas Legend — Red Thread terminology */}
      <div className="absolute top-3 left-3 bg-slate-900/80 backdrop-blur-md px-3 py-1.5 rounded-lg border border-slate-800 flex items-center gap-4 text-[11px] font-mono text-slate-300 pointer-events-auto z-30">
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-[2px] inline-block rounded-full" style={{ backgroundColor: SIGNAL_GLOW_COLOR }}></span>
          <span className="text-red-400 font-semibold">Red Thread (Attack Path)</span>
        </span>
        <span className="flex items-center gap-1.5 border-l border-slate-700 pl-3">
          <span className="w-2.5 h-2.5 rounded-sm inline-block" style={{ backgroundColor: NOISE_NODE_COLOR, border: `1px solid ${NOISE_BORDER_COLOR}` }}></span>
          Background Noise
        </span>
        <span className="flex items-center gap-1.5 border-l border-slate-700 pl-3">
          <span className="w-2 h-2 rounded-full inline-block" style={{ backgroundColor: SIGNAL_NODE_COLOR }}></span>
          Signal Node (Individual threat actor)
        </span>
      </div>

      {/* Top Right Controls */}
      <div className="absolute top-3 right-3 flex items-center gap-2 pointer-events-auto z-30">
        {layoutRunning && (
          <div className="layout-indicator bg-cyan-950/80 backdrop-blur-md px-2.5 py-1 rounded-lg border border-cyan-500/40 text-[10px] font-mono text-cyan-300 flex items-center gap-1.5">
            <Atom className="w-3.5 h-3.5 animate-spin" />
            FA2 Y-Relax…
          </div>
        )}

        <div className="bg-slate-900/80 backdrop-blur-md px-2.5 py-1 rounded-lg border border-slate-800 text-[10px] font-mono text-slate-400">
          {focusedCluster
            ? `Starburst: ${focusedCluster.childIds.size} nodes`
            : 'Kill Chain View'}
        </div>

        <button
          onClick={() => setShowScans(!showScans)}
          title={showScans ? 'Hide Mass Scans (Orange)' : 'Show Mass Scans (Orange)'}
          className={`p-1.5 backdrop-blur-md border rounded-lg text-xs font-mono transition-all cursor-pointer ${
            showScans
              ? 'bg-orange-950/80 border-orange-500/40 text-orange-300 hover:bg-orange-900'
              : 'bg-slate-900/80 border-slate-800 text-slate-300 hover:bg-slate-800'
          }`}
        >
          <Activity className="w-4 h-4" />
        </button>
        <button
          onClick={() => setShowNoise(!showNoise)}
          title={showNoise ? 'Hide Background Noise' : 'Show Background Noise'}
          className={`p-1.5 backdrop-blur-md border rounded-lg text-xs font-mono transition-all cursor-pointer ${
            showNoise
              ? 'bg-purple-950/80 border-purple-500/40 text-purple-300 hover:bg-purple-900'
              : 'bg-slate-900/80 border-slate-800 text-slate-300 hover:bg-slate-800'
          }`}
        >
          {showNoise ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
        </button>
        <button
          onClick={handleToggleLayout}
          title={layoutRunning ? 'Stop FA2' : 'Relax Y-axis (columns locked)'}
          className={`p-1.5 backdrop-blur-md border rounded-lg text-xs font-mono transition-all cursor-pointer ${
            layoutRunning
              ? 'bg-cyan-950/80 border-cyan-500/40 text-cyan-300 hover:bg-cyan-900'
              : 'bg-slate-900/80 border-slate-800 text-slate-300 hover:bg-slate-800'
          }`}
        >
          <Atom className="w-4 h-4" />
        </button>
        <button onClick={handleZoomIn} title="Zoom In"
          className="p-1.5 bg-slate-900/80 hover:bg-slate-800 border border-slate-800 text-slate-300 rounded-lg text-xs transition-all cursor-pointer">
          <ZoomIn className="w-4 h-4" />
        </button>
        <button onClick={handleZoomOut} title="Zoom Out"
          className="p-1.5 bg-slate-900/80 hover:bg-slate-800 border border-slate-800 text-slate-300 rounded-lg text-xs transition-all cursor-pointer">
          <ZoomOut className="w-4 h-4" />
        </button>
        <button onClick={handleResetCamera} title="Reset Camera"
          className="p-1.5 bg-slate-900/80 hover:bg-slate-800 border border-slate-800 text-slate-300 rounded-lg text-xs transition-all cursor-pointer">
          <Maximize2 className="w-4 h-4" />
        </button>
      </div>

      {/* Expansion Loading Overlay */}
      {expandingNode && (
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-slate-900/95 border border-cyan-500/40 backdrop-blur-lg px-5 py-3 rounded-xl text-xs font-mono text-cyan-300 flex items-center gap-3 shadow-2xl z-20 pointer-events-none">
          <Loader2 className="w-5 h-5 animate-spin text-cyan-400" />
          <div>
            <div className="font-bold text-cyan-200">Expanding Cluster</div>
            <div className="text-[10px] text-slate-400 mt-0.5">{expandingNode}</div>
          </div>
        </div>
      )}

      {/* Focused Cluster Info Badge */}
      {focusedCluster && !expandingNode && (
        <div className="absolute top-14 left-1/2 -translate-x-1/2 bg-slate-900/90 border border-cyan-500/30 backdrop-blur-lg px-4 py-2 rounded-xl text-xs font-mono text-cyan-300 flex items-center gap-3 shadow-2xl z-30 pointer-events-auto">
          <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          <span>
            <span className="font-bold text-cyan-200">{focusedCluster.childIds.size}</span> nodes expanded from{' '}
            <span className="text-slate-400">{focusedCluster.parentId.replace('super:', '')}</span>
            {focusedCluster.wasCapped && (
              <span className="ml-2 text-amber-400 font-semibold">
                (top {focusedCluster.childIds.size} of {focusedCluster.totalAvailable} — capped)
              </span>
            )}
          </span>
          <button
            onClick={collapseFocusedCluster}
            className="ml-2 p-1 hover:bg-slate-800 rounded transition-colors cursor-pointer"
            title="Collapse cluster"
          >
            <X className="w-3.5 h-3.5 text-slate-400 hover:text-white" />
          </button>
        </div>
      )}

      {/* Hover Tooltip */}
      {hoveredNode && (
        <div className="absolute bottom-3 left-3 bg-slate-900/90 border border-slate-800 backdrop-blur-md px-3 py-2 rounded-lg text-xs font-mono text-slate-200 pointer-events-none shadow-xl max-w-sm">
          <div className="font-bold text-cyan-400 truncate">{hoveredNode.label}</div>
          <div className="text-[10px] text-slate-400 mt-0.5">
            Type: <span className="text-slate-300">{hoveredNode.node_type}</span>
            {' | '}Risk: <span className={hoveredNode.risk_score >= 3.0 ? 'text-red-400 font-bold' : 'text-slate-300'}>{hoveredNode.risk_score.toFixed(1)}</span>
            {' | '}Links: <span className="text-slate-300">{hoveredNode.in_degree + hoveredNode.out_degree}</span>
            {hoveredNode.metadata?.layer && (
              <span className="text-slate-500"> | Layer: {hoveredNode.metadata.layer}</span>
            )}
            {hoveredNode.node_type === 'SUPER_NODE' && (
              <span className="text-purple-400"> | Double-click to expand</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
