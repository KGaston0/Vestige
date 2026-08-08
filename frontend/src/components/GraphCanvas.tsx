import React, { useRef, useEffect, useState, useCallback } from 'react';
import Graph from 'graphology';
import Sigma from 'sigma';
import FA2LayoutSupervisor from 'graphology-layout-forceatlas2/worker';
import forceAtlas2 from 'graphology-layout-forceatlas2';
import { EdgeCurvedArrowProgram } from '@sigma/edge-curve';
import { createNodeBorderProgram } from '@sigma/node-border';
import { NodeModel, EdgeModel, GraphData, SuperNodeModel, ExpandResponse, isSuperNode } from '../types/graph';
import { ZoomIn, ZoomOut, Maximize2, Loader2, Atom } from 'lucide-react';

interface GraphCanvasProps {
  graph: GraphData;
  selectedNode: NodeModel | null;
  onSelectNode: (node: NodeModel | null) => void;
  sessionId: string | null;
}

const API_BASE = 'http://localhost:8080';

// ── Multi-Layer X-Band Constants (must match backend LAYER_X) ─────────
const LAYER_X: Record<string, number> = {
  external: 0,
  web: 500,
  internal: 1000,
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

const ANOMALY_EDGE_COLORS: Record<string, string> = {
  FULL_ATTACK_CHAIN: '#FF2D55',
  SSH_PRIVILEGE_PIVOT: '#FF2D55',
  WEB_EXPLOIT_POST: '#E88A2D',
  HTTP_4XX_SCAN: '#E88A2D',
  BRUTE_FORCE_BURST: '#FF3B30',
  PRIVILEGE_PIVOT: '#FF3B30',
  HIGH_FREQUENCY_COLLAPSED: '#D06030',
  OFF_HOURS_ACCESS: '#C4A020',
  RARE_PIVOT_PATH: '#FF453A',
};

// Near-invisible for normal edge mass
const NORMAL_EDGE_COLOR = 'rgba(55, 65, 81, 0.03)';
const SUPER_NODE_BORDER_COLOR = '#B07CE8';

// ── Custom Node Border Program for Super-Nodes ────────────────────────
const SuperNodeProgram = createNodeBorderProgram({
  borders: [
    {
      size: { value: 0.2, mode: 'relative' },
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

  const [hoveredNode, setHoveredNode] = useState<NodeModel | null>(null);
  const [expandingNode, setExpandingNode] = useState<string | null>(null);
  const [expandedClusters, setExpandedClusters] = useState<Set<string>>(new Set());
  const [layoutRunning, setLayoutRunning] = useState(false);

  // ── Drill-Down: Expand a Super-Node ──────────────────────────────────
  const expandSuperNode = useCallback(async (superNodeId: string) => {
    if (!sessionId || !graphRef.current || expandedClusters.has(superNodeId)) return;

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
      const graph = graphRef.current;
      if (!graph || !data.nodes.length) return;

      let parentX = 0, parentY = 0;
      if (graph.hasNode(superNodeId)) {
        parentX = graph.getNodeAttribute(superNodeId, 'x') || 0;
        parentY = graph.getNodeAttribute(superNodeId, 'y') || 0;

        const superEdges = graph.edges(superNodeId);
        const edgeReconnections: Array<{
          source: string; target: string; attrs: Record<string, any>;
        }> = [];

        superEdges.forEach((edgeKey) => {
          const source = graph.source(edgeKey);
          const target = graph.target(edgeKey);
          const attrs = graph.getEdgeAttributes(edgeKey);
          if (source === superNodeId || target === superNodeId) {
            edgeReconnections.push({ source, target, attrs });
          }
        });

        graph.dropNode(superNodeId);

        const childCount = data.nodes.length;
        const ySpacing = 15;
        const yStart = parentY - (childCount * ySpacing) / 2;

        data.nodes.forEach((n, idx) => {
          if (!graph.hasNode(n.id)) {
            // Use backend-assigned X (layer-based), spread Y vertically
            const cx = n.x || parentX;
            const cy = yStart + idx * ySpacing;

            graph.addNode(n.id, {
              label: n.label || n.id,
              x: cx,
              y: cy,
              size: n.risk_score >= 3.0 ? 3.5 : 2.0,
              color: NODE_COLORS[n.node_type] || (n.risk_score >= 3.0 ? '#E05252' : '#4B8BF5'),
              borderColor: SUPER_NODE_BORDER_COLOR,
              risk_score: n.risk_score,
              node_type: n.node_type,
              metadata: n.metadata,
              _parent_cluster: superNodeId,
            });
          }
        });

        data.edges.forEach((e) => {
          if (graph.hasNode(e.source) && graph.hasNode(e.target)) {
            if (!graph.hasEdge(e.id)) {
              graph.addEdgeWithKey(e.id, e.source, e.target, {
                size: e.is_anomalous ? 2.0 : 0.3,
                color: e.is_anomalous
                  ? getAnomalyEdgeColor(e.anomaly_flags)
                  : NORMAL_EDGE_COLOR,
                weight: e.weight,
                is_anomalous: e.is_anomalous,
                edge_type: e.edge_type,
                anomaly_flags: e.anomaly_flags,
                type: 'curvedArrow',
                curvature: 0.15,
              });
            }
          }
        });

        edgeReconnections.forEach(({ source, target, attrs }) => {
          const childNodeIds = new Set(data.nodes.map((n) => n.id));
          if (source === superNodeId) {
            childNodeIds.forEach((childId) => {
              if (graph.hasNode(childId) && graph.hasNode(target)) {
                const reconnectId = `reconnect:${childId}->${target}`;
                if (!graph.hasEdge(reconnectId)) {
                  graph.addEdgeWithKey(reconnectId, childId, target, {
                    ...attrs, size: 0.3, color: NORMAL_EDGE_COLOR,
                    type: 'curvedArrow', curvature: 0.12,
                  });
                }
              }
            });
          } else if (target === superNodeId) {
            childNodeIds.forEach((childId) => {
              if (graph.hasNode(source) && graph.hasNode(childId)) {
                const reconnectId = `reconnect:${source}->${childId}`;
                if (!graph.hasEdge(reconnectId)) {
                  graph.addEdgeWithKey(reconnectId, source, childId, {
                    ...attrs, size: 0.3, color: NORMAL_EDGE_COLOR,
                    type: 'curvedArrow', curvature: 0.12,
                  });
                }
              }
            });
          }
        });
      }

      setExpandedClusters((prev) => new Set(prev).add(superNodeId));

      if (sigmaRef.current) {
        sigmaRef.current.refresh();
      }
    } catch (err) {
      console.error('Failed to expand super-node:', err);
    } finally {
      setExpandingNode(null);
    }
  }, [sessionId, expandedClusters]);

  // ── ForceAtlas2 Layout (optional toggle, not default) ────────────────
  const restartLayout = useCallback((durationMs: number = 6000) => {
    if (!graphRef.current || graphRef.current.order < 2) return;

    if (fa2Ref.current) {
      fa2Ref.current.kill();
      fa2Ref.current = null;
    }

    const graph = graphRef.current;
    const order = graph.order;

    const settings = {
      gravity: 0.05,
      scalingRatio: 80,
      barnesHutOptimize: true,
      barnesHutTheta: 0.6,
      slowDown: 2 + Math.log10(Math.max(2, order)),
      adjustSizes: false,
      strongGravityMode: false,
      linLogMode: true,
      outboundAttractionDistribution: true,
      edgeWeightInfluence: 0.5,
    };

    const supervisor = new FA2LayoutSupervisor(graph, {
      settings,
      getEdgeWeight: 'weight',
    });

    fa2Ref.current = supervisor;
    setLayoutRunning(true);
    supervisor.start();

    setTimeout(() => {
      if (fa2Ref.current === supervisor && supervisor.isRunning()) {
        supervisor.stop();
        setLayoutRunning(false);
      }
    }, durationMs);
  }, []);

  // ── Get anomaly edge color from flags ────────────────────────────────
  function getAnomalyEdgeColor(flags: string[]): string {
    const priority = [
      'FULL_ATTACK_CHAIN', 'SSH_PRIVILEGE_PIVOT', 'PRIVILEGE_PIVOT',
      'BRUTE_FORCE_BURST', 'WEB_EXPLOIT_POST', 'RARE_PIVOT_PATH',
      'HTTP_4XX_SCAN', 'OFF_HOURS_ACCESS', 'HIGH_FREQUENCY_COLLAPSED',
    ];
    for (const flag of priority) {
      if (flags.includes(flag)) {
        return ANOMALY_EDGE_COLORS[flag] || '#FF2D55';
      }
    }
    return '#E88A2D';
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
      labelRenderedSizeThreshold: 8,
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

      // ── Node Reducer ─────────────────────────────────────────────────
      nodeReducer: (node: string, data: any) => {
        const res = { ...data };

        if (data.node_type === 'SUPER_NODE') {
          res.type = 'border';
          res.borderColor = SUPER_NODE_BORDER_COLOR;
          res.color = '#7C3AED';
          res.size = 5;
          res.zIndex = 2;
        } else if (data.risk_score >= 7.0) {
          res.color = '#EF4444';
          res.size = 4;
          res.zIndex = 3;
          res.highlighted = true;
        } else if (data.risk_score >= 3.0) {
          res.color = '#E88A2D';
          res.size = 3;
          res.zIndex = 2;
        } else {
          res.color = NODE_COLORS[data.node_type] || '#4B8BF5';
          res.size = 2;
          res.zIndex = 1;
        }

        // Background noise super-node
        if (node === 'host:background_web_noise') {
          res.color = '#64748B';
          res.size = 6;
          res.zIndex = 0;
        }

        return res;
      },

      // ── Edge Reducer: Near-invisible normals, bold anomalous ─────────
      edgeReducer: (edge: string, data: any) => {
        const res = { ...data };

        if (data.is_anomalous) {
          const edgeColor = getAnomalyEdgeColor(data.anomaly_flags || []);
          res.color = edgeColor;
          res.size = 3.0;
          res.zIndex = 2;
          res.type = 'curvedArrow';
        } else {
          res.color = NORMAL_EDGE_COLOR;
          res.size = 0.3;
          res.zIndex = 0;
          res.type = 'curvedArrow';
        }

        return res;
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
      const nodeId = event.node;
      const attrs = graph.getNodeAttributes(nodeId);
      if (attrs.node_type === 'SUPER_NODE') {
        event.preventSigmaDefault();
        expandSuperNode(nodeId);
      }
    });

    sigma.on('clickStage', () => { onSelectNode(null); });

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
      if (animFrameRef.current) {
        cancelAnimationFrame(animFrameRef.current);
      }
      sigma.kill();
      graphRef.current = null;
      sigmaRef.current = null;
    };
  }, []);

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

        // Fallback if backend didn't assign coords
        if (initX === 0 && initY === 0) {
          const layer = inferLayer(n);
          initX = LAYER_X[layer] ?? 500;
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

    // 2. Process Edges
    graphData.edges.forEach((e) => {
      if (graph.hasNode(e.source) && graph.hasNode(e.target)) {
        if (!graph.hasEdge(e.id)) {
          graph.addEdgeWithKey(e.id, e.source, e.target, {
            size: e.is_anomalous ? 3.0 : 0.3,
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
            curvature: 0.15 + Math.random() * 0.08,
          });
        }
      }
    });

    // No FA2 by default — backend provides clean column positions
    if (sigmaRef.current) {
      sigmaRef.current.refresh();
    }
  }, [graphData]);

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
    <div className="w-full h-full relative overflow-hidden bg-slate-950 rounded-xl border border-slate-800">
      {/* Sigma.js Canvas Container */}
      <div ref={containerRef} className="w-full h-full cursor-crosshair block" />

      {/* Layer Column Headers */}
      <div className="absolute top-12 left-0 right-0 flex justify-between px-16 pointer-events-none z-10">
        <div className="text-[10px] font-mono text-orange-400/60 uppercase tracking-widest text-center">
          ← External IPs
        </div>
        <div className="text-[10px] font-mono text-amber-400/60 uppercase tracking-widest text-center">
          Web Layer
        </div>
        <div className="text-[10px] font-mono text-blue-400/60 uppercase tracking-widest text-center">
          Internal Hosts →
        </div>
      </div>

      {/* Top Left Canvas Legend */}
      <div className="absolute top-3 left-3 bg-slate-900/80 backdrop-blur-md px-3 py-1.5 rounded-lg border border-slate-800 flex items-center gap-4 text-[11px] font-mono text-slate-300 pointer-events-auto">
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full inline-block" style={{ backgroundColor: '#F97316' }}></span> External
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full inline-block" style={{ backgroundColor: '#D4943A' }}></span> URL
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full inline-block" style={{ backgroundColor: '#4B8BF5' }}></span> Internal
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full inline-block" style={{ backgroundColor: '#E05252' }}></span> Risk
        </span>
        <span className="flex items-center gap-1.5 border-l border-slate-700 pl-3">
          <span className="w-3 h-[2px] inline-block rounded-full" style={{ backgroundColor: '#FF2D55' }}></span> Alert
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-sm inline-block" style={{ backgroundColor: '#64748B' }}></span> Noise
        </span>
      </div>

      {/* Top Right Controls */}
      <div className="absolute top-3 right-3 flex items-center gap-2 pointer-events-auto">
        {layoutRunning && (
          <div className="layout-indicator bg-cyan-950/80 backdrop-blur-md px-2.5 py-1 rounded-lg border border-cyan-500/40 text-[10px] font-mono text-cyan-300 flex items-center gap-1.5">
            <Atom className="w-3.5 h-3.5 animate-spin" />
            FA2 Running…
          </div>
        )}

        <div className="bg-slate-900/80 backdrop-blur-md px-2.5 py-1 rounded-lg border border-slate-800 text-[10px] font-mono text-slate-400">
          {expandedClusters.size > 0
            ? `${expandedClusters.size} cluster(s) expanded`
            : 'Kill Chain View'}
        </div>

        <button
          onClick={handleToggleLayout}
          title={layoutRunning ? 'Stop FA2' : 'Run ForceAtlas2 (organic)'}
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

      {/* Expansion Overlay */}
      {expandingNode && (
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-slate-900/95 border border-cyan-500/40 backdrop-blur-lg px-5 py-3 rounded-xl text-xs font-mono text-cyan-300 flex items-center gap-3 shadow-2xl z-20 pointer-events-none">
          <Loader2 className="w-5 h-5 animate-spin text-cyan-400" />
          <div>
            <div className="font-bold text-cyan-200">Expanding Cluster</div>
            <div className="text-[10px] text-slate-400 mt-0.5">{expandingNode}</div>
          </div>
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
