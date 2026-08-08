import React from 'react';
import { X, ShieldAlert, Activity, Server, Hash, ArrowUpRight, ArrowDownLeft, Layers, MousePointerClick } from 'lucide-react';
import { NodeModel, EdgeModel } from '../types/graph';

interface NodeInspectorProps {
  node: NodeModel | null;
  edges: EdgeModel[];
  onClose: () => void;
  onExpandCluster?: (nodeId: string) => void;
}

export const NodeInspector: React.FC<NodeInspectorProps> = ({ node, edges, onClose, onExpandCluster }) => {
  if (!node) return null;

  const isSuperNode = node.node_type === 'SUPER_NODE';
  const childCount = (node as any).child_count || 0;
  const clusterRule = (node as any).cluster_rule || '';

  const connectedEdges = edges.filter(
    (e) => e.source === node.id || e.target === node.id
  );

  const riskBadgeColor =
    node.risk_score >= 3.0
      ? 'bg-red-500/20 text-red-400 border-red-500/40'
      : node.risk_score >= 1.5
      ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
      : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';

  return (
    <div className="w-80 bg-slate-900/95 border-l border-slate-800 p-4 flex flex-col gap-4 text-xs font-mono backdrop-blur-md overflow-y-auto z-10 shadow-2xl">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          {isSuperNode ? (
            <Layers className="w-4 h-4 text-purple-400" />
          ) : (
            <Server className="w-4 h-4 text-cyan-400" />
          )}
          <span className="font-bold text-slate-200 uppercase tracking-wider">
            {isSuperNode ? 'Cluster Details' : 'Node Details'}
          </span>
        </div>
        <button
          onClick={onClose}
          className="text-slate-400 hover:text-white p-1 rounded hover:bg-slate-800 transition"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Main Metadata */}
      <div className="bg-slate-950/70 border border-slate-800 p-3 rounded-lg flex flex-col gap-2">
        <div>
          <span className="text-[10px] text-slate-500 uppercase font-semibold">
            {isSuperNode ? 'Cluster Identifier' : 'Node Identifier'}
          </span>
          <p className="text-slate-100 font-bold text-sm break-all font-mono">{node.id}</p>
        </div>
        
        <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800/80">
          <div>
            <span className="text-[10px] text-slate-500 uppercase">Type</span>
            <p className={isSuperNode ? 'text-purple-400 font-semibold' : 'text-cyan-400 font-semibold'}>
              {isSuperNode ? 'SUPER_NODE' : node.node_type}
            </p>
          </div>
          <div>
            <span className="text-[10px] text-slate-500 uppercase">Risk Level</span>
            <div className={`mt-0.5 inline-block px-2 py-0.5 rounded text-[11px] font-bold border ${riskBadgeColor}`}>
              {node.risk_score.toFixed(1)} / 5.0
            </div>
          </div>
        </div>
      </div>

      {/* Super-Node Cluster Metadata */}
      {isSuperNode && (
        <div className="bg-purple-950/30 border border-purple-500/30 p-3 rounded-lg flex flex-col gap-2">
          <div className="flex items-center gap-2 text-purple-300 font-bold text-[11px] uppercase tracking-wider">
            <Layers className="w-3.5 h-3.5" />
            Cluster Info
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <span className="text-[10px] text-slate-500 uppercase">Child Nodes</span>
              <p className="text-lg font-bold text-purple-300">{childCount}</p>
            </div>
            <div>
              <span className="text-[10px] text-slate-500 uppercase">Cluster Rule</span>
              <p className="text-[11px] text-slate-300 font-semibold">{clusterRule}</p>
            </div>
          </div>

          {onExpandCluster && (
            <button
              onClick={() => onExpandCluster(node.id)}
              className="mt-1 w-full flex items-center justify-center gap-2 bg-purple-600/80 hover:bg-purple-500 text-white font-mono text-[11px] font-bold px-4 py-2 rounded-lg transition-all shadow-lg shadow-purple-600/20 active:scale-95 cursor-pointer"
            >
              <MousePointerClick className="w-4 h-4" />
              Expand Cluster ({childCount} nodes)
            </button>
          )}
        </div>
      )}

      {/* Degree Stats */}
      <div className="grid grid-cols-2 gap-2">
        <div className="bg-slate-950/50 border border-slate-800 p-2.5 rounded-lg flex items-center gap-2">
          <ArrowDownLeft className="w-4 h-4 text-emerald-400 shrink-0" />
          <div>
            <div className="text-slate-400 text-[10px] uppercase">In-Degree</div>
            <div className="text-sm font-bold text-slate-200">{node.in_degree}</div>
          </div>
        </div>
        <div className="bg-slate-950/50 border border-slate-800 p-2.5 rounded-lg flex items-center gap-2">
          <ArrowUpRight className="w-4 h-4 text-blue-400 shrink-0" />
          <div>
            <div className="text-slate-400 text-[10px] uppercase">Out-Degree</div>
            <div className="text-sm font-bold text-slate-200">{node.out_degree}</div>
          </div>
        </div>
      </div>

      {/* Connected Edges */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-[10px] uppercase font-bold tracking-wider">Topology Links ({connectedEdges.length})</span>
          <Activity className="w-3.5 h-3.5 text-slate-500" />
        </div>

        <div className="flex flex-col gap-1.5 max-h-48 overflow-y-auto pr-1">
          {connectedEdges.length === 0 ? (
            <p className="text-slate-500 text-[11px]">No active connections</p>
          ) : (
            connectedEdges.map((edge) => (
              <div
                key={edge.id}
                className={`p-2 rounded border text-[11px] flex flex-col gap-1 bg-slate-950/40 ${
                  edge.is_anomalous
                    ? 'border-amber-500/40 text-amber-300'
                    : 'border-slate-800/80 text-slate-300'
                }`}
              >
                <div className="flex items-center justify-between font-semibold">
                  <span className="truncate">{edge.source === node.id ? `-> ${edge.target}` : `<- ${edge.source}`}</span>
                  <span className="text-[10px] text-slate-400">{edge.edge_type}</span>
                </div>
                {edge.total_attempts > 1 && (
                  <div className="text-[10px] text-slate-400">
                    {edge.total_attempts} connections
                  </div>
                )}
                {edge.anomaly_flags.length > 0 && (
                  <div className="flex items-center gap-1 text-[10px] text-red-400 font-bold">
                    <ShieldAlert className="w-3 h-3" />
                    <span>{edge.anomaly_flags.join(', ')}</span>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
