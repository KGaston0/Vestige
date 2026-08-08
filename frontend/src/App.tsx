import React, { useState } from 'react';
import {
  Shield,
  Upload,
  Activity,
  AlertTriangle,
  Layers,
  Trash2,
  Cpu,
  FileText,
  Clock,
  Terminal,
  Zap,
  RotateCcw,
} from 'lucide-react';
import { PresentationPayload, NodeModel, EdgeModel, StreamChunkPayload, StreamingState } from './types/graph';
import { KPICard } from './components/KPICard';
import { GraphCanvas } from './components/GraphCanvas';
import { NodeInspector } from './components/NodeInspector';
import { ProgressBar } from './components/ProgressBar';

export default function App() {
  const [payload, setPayload] = useState<PresentationPayload | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<NodeModel | null>(null);
  const [streamingState, setStreamingState] = useState<StreamingState | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setLoading(true);
    setError(null);
    setSelectedNode(null);

    const initialStreamingState: StreamingState = {
      isStreaming: true,
      progress: 0,
      processedLines: 0,
      totalLines: 0,
      currentChunk: 0,
      totalChunks: 1,
      statusText: 'Connecting to Polars SSE Stream...',
    };
    setStreamingState(initialStreamingState);

    const formData = new FormData();
    formData.append('file', file);

    const nodesMap = new Map<string, NodeModel>();
    const edgesMap = new Map<string, EdgeModel>();

    try {
      const response = await fetch('http://localhost:8080/api/v1/analyze/stream', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Server returned error status: ${response.status}`);
      }

      if (!response.body) {
        throw new Error('ReadableStream not supported by browser.');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';

      let lastUIUpdate = 0;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split('\n\n');
        buffer = parts.pop() || '';

        for (const part of parts) {
          const line = part.trim();
          if (line.startsWith('data: ')) {
            const jsonStr = line.replace(/^data:\s*/, '');
            try {
              const chunk: StreamChunkPayload = JSON.parse(jsonStr);

              // Accumulate nodes and edges incrementally
              chunk.nodes.forEach((n) => nodesMap.set(n.id, n));
              chunk.edges.forEach((e) => edgesMap.set(e.id, e));

              const now = Date.now();
              // Throttle UI updates to max 1 per 150ms to prevent React Virtual DOM memory overload
              if (chunk.is_final || now - lastUIUpdate > 150) {
                lastUIUpdate = now;
                const accumulatedNodes = Array.from(nodesMap.values());
                const accumulatedEdges = Array.from(edgesMap.values());

                // Store session_id from meta for drill-down queries
                if (chunk.meta?.session_id) {
                  setSessionId(chunk.meta.session_id);
                }

                setPayload({
                  meta: chunk.meta || {
                    session_id: `vestige_sess_${Date.now()}`,
                    timestamp: new Date().toISOString(),
                    log_filename: file.name,
                    total_lines_parsed: chunk.total_lines,
                    valid_ssh_events: accumulatedNodes.filter((n) => n.node_type === 'HOST').length,
                    valid_http_events: accumulatedNodes.filter((n) => n.node_type === 'URL').length,
                    processing_time_ms: 0,
                    noise_reduction_ratio: 0,
                  },
                  summary: {
                    total_nodes: accumulatedNodes.length,
                    total_edges: accumulatedEdges.length,
                    anomalous_edges_count: chunk.summary.anomalous_edges_count,
                    high_risk_nodes_count: chunk.summary.high_risk_nodes_count,
                    detected_lateral_chains: chunk.summary.detected_lateral_chains,
                  },
                  graph: {
                    nodes: accumulatedNodes,
                    edges: accumulatedEdges,
                  },
                });

                setStreamingState({
                  isStreaming: !chunk.is_final,
                  progress: chunk.progress,
                  processedLines: chunk.processed_lines,
                  totalLines: chunk.total_lines,
                  currentChunk: chunk.chunk_index,
                  totalChunks: chunk.total_chunks,
                  statusText: chunk.is_final
                    ? 'ETL SIMD Stream Complete'
                    : `Processing batch ${chunk.chunk_index + 1} of ${chunk.total_chunks} (${chunk.progress.toFixed(1)}%)...`,
                });
              }
            } catch (err) {
              console.error('Failed to parse SSE payload:', err);
            }
          }
        }
      }

      // Flush remaining decoder buffer after stream closes
      buffer += decoder.decode();
      if (buffer.trim()) {
        const parts = buffer.split('\n\n');
        for (const part of parts) {
          const line = part.trim();
          if (line.startsWith('data: ')) {
            const jsonStr = line.replace(/^data:\s*/, '');
            try {
              const chunk: StreamChunkPayload = JSON.parse(jsonStr);
              chunk.nodes.forEach((n) => nodesMap.set(n.id, n));
              chunk.edges.forEach((e) => edgesMap.set(e.id, e));
              const accumulatedNodes = Array.from(nodesMap.values());
              const accumulatedEdges = Array.from(edgesMap.values());

              setPayload({
                meta: chunk.meta || {
                  session_id: `vestige_sess_${Date.now()}`,
                  timestamp: new Date().toISOString(),
                  log_filename: file.name,
                  total_lines_parsed: chunk.total_lines,
                  valid_ssh_events: accumulatedNodes.filter((n) => n.node_type === 'HOST').length,
                  valid_http_events: accumulatedNodes.filter((n) => n.node_type === 'URL').length,
                  processing_time_ms: 0,
                  noise_reduction_ratio: 0,
                },
                summary: {
                  total_nodes: accumulatedNodes.length,
                  total_edges: accumulatedEdges.length,
                  anomalous_edges_count: chunk.summary.anomalous_edges_count,
                  high_risk_nodes_count: chunk.summary.high_risk_nodes_count,
                  detected_lateral_chains: chunk.summary.detected_lateral_chains,
                },
                graph: {
                  nodes: accumulatedNodes,
                  edges: accumulatedEdges,
                },
              });

              setStreamingState({
                isStreaming: false,
                progress: chunk.progress,
                processedLines: chunk.processed_lines,
                totalLines: chunk.total_lines,
                currentChunk: chunk.chunk_index,
                totalChunks: chunk.total_chunks,
                statusText: 'ETL SIMD Stream Complete',
              });
            } catch (err) {
              console.error('Failed to parse trailing SSE payload:', err);
            }
          }
        }
      }
    } catch (err: any) {
      setError(err.message || 'Failed to stream and analyze log file.');
    } finally {
      setLoading(false);
    }
  };

  const handlePurgeSession = () => {
    setPayload(null);
    setSelectedNode(null);
    setError(null);
    setStreamingState(null);
    setSessionId(null);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans select-none">
      {/* Header Bar */}
      <header className="border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-md px-6 py-3.5 flex items-center justify-between z-20">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-red-950/40 border border-red-500/30 text-red-500 shadow-lg shadow-red-500/10">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-bold text-lg tracking-wider text-white font-mono">VESTIGE</h1>
              <span className="text-[10px] font-mono font-bold uppercase bg-slate-800/80 border border-slate-700 text-cyan-400 px-2 py-0.5 rounded">
                v1.2.0 Stream
              </span>
            </div>
            <p className="text-[11px] font-mono text-slate-400">
              Tactical Ephemeral Visual Forensic Engine
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {payload && (
            <div className="hidden md:flex items-center gap-3 text-[11px] font-mono text-slate-400 border-r border-slate-800 pr-4">
              <span className="flex items-center gap-1 text-slate-300">
                <FileText className="w-3.5 h-3.5 text-cyan-400" /> {payload.meta.log_filename}
              </span>
              <span className="flex items-center gap-1 text-slate-300">
                <Clock className="w-3.5 h-3.5 text-emerald-400" /> {payload.meta.processing_time_ms} ms
              </span>
            </div>
          )}

          <button
            onClick={handlePurgeSession}
            title="Release JavaScript RAM memory, clear active graphs and reset session state"
            className="flex items-center gap-2 bg-red-950/60 border border-red-500/50 text-red-400 hover:bg-red-900/80 hover:text-red-200 px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold transition-all duration-150 shadow-lg shadow-red-950/50 active:scale-95 cursor-pointer"
          >
            <RotateCcw className="w-4 h-4" /> Purge RAM / Soft Reset
          </button>
        </div>
      </header>

      {/* Main Content Workspace */}
      <main className="flex-1 flex flex-col p-4 md:p-6 max-w-[1600px] w-full mx-auto gap-4 overflow-hidden">
        {!payload && !streamingState?.isStreaming ? (
          /* Log Upload Dropzone Panel */
          <div className="flex-1 flex flex-col items-center justify-center border-2 border-dashed border-slate-800/90 rounded-2xl p-12 bg-slate-900/30 text-center relative overflow-hidden backdrop-blur-sm">
            <div className="w-16 h-16 rounded-2xl bg-blue-950/40 border border-blue-500/30 flex items-center justify-center text-blue-400 mb-5 shadow-xl shadow-blue-500/10">
              <Upload className="w-8 h-8 animate-bounce" />
            </div>

            <h2 className="text-xl font-bold text-slate-100 font-mono mb-2">
              Ingest Forensic Log Payload
            </h2>

            <p className="text-xs font-mono text-slate-400 max-w-lg mb-6 leading-relaxed">
              Automated format detection routes Linux auth logs (<code className="text-cyan-400 font-mono">auth.log</code>) or Nginx/Apache web access logs (<code className="text-amber-400 font-mono font-bold">access.log</code>) directly into Polars SIMD extractors. SSE streaming streams chunks in real-time.
            </p>

            <div className="flex flex-wrap items-center justify-center gap-3">
              <label className="cursor-pointer bg-blue-600 hover:bg-blue-500 text-white font-mono text-xs font-bold px-6 py-3 rounded-xl transition-all shadow-lg shadow-blue-600/30 active:scale-95 flex items-center gap-2">
                <Terminal className="w-4 h-4" /> Select Log File (.log, .txt)
                <input
                  type="file"
                  accept=".log,.txt,.csv"
                  className="hidden"
                  onChange={handleFileUpload}
                />
              </label>

              <button
                type="button"
                onClick={handlePurgeSession}
                title="Purge JavaScript RAM, clear garbage collector references and reset workspace"
                className="bg-slate-800/80 hover:bg-red-950/60 hover:text-red-300 text-slate-300 border border-slate-700 hover:border-red-500/50 font-mono text-xs font-bold px-5 py-3 rounded-xl transition-all shadow-md active:scale-95 flex items-center gap-2 cursor-pointer"
              >
                <RotateCcw className="w-4 h-4 text-red-400" /> Purge RAM / Soft Reset
              </button>
            </div>

            {error && (
              <div className="text-xs font-mono text-red-400 mt-6 bg-red-950/40 border border-red-500/40 px-4 py-2.5 rounded-lg flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}
          </div>
        ) : (
          /* Redesigned Tactical Forensic Dashboard */
          <div className="flex-1 flex flex-col gap-4 overflow-hidden">
            {/* Real-time Streaming Progress Bar */}
            {streamingState && (
              <ProgressBar
                state={streamingState}
                totalNodes={payload?.summary.total_nodes || 0}
                totalEdges={payload?.summary.total_edges || 0}
              />
            )}

            {/* KPI Dense Panel Grid */}
            {payload && (
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <KPICard
                  label="Topology Nodes"
                  value={payload.summary.total_nodes}
                  subtext={`Hosts & Endpoints`}
                  icon={<Layers className="w-4 h-4" />}
                  accentColor="blue"
                />
                <KPICard
                  label="Anomalous Links"
                  value={payload.summary.anomalous_edges_count}
                  subtext={`Flagged vectors`}
                  icon={<Activity className="w-4 h-4" />}
                  accentColor="amber"
                />
                <KPICard
                  label="High Risk Nodes"
                  value={payload.summary.high_risk_nodes_count}
                  subtext={`Score >= 3.0`}
                  icon={<AlertTriangle className="w-4 h-4" />}
                  accentColor="red"
                />
                <KPICard
                  label="Parsed Events"
                  value={payload.meta.total_lines_parsed.toLocaleString()}
                  subtext={`Raw lines parsed`}
                  icon={<FileText className="w-4 h-4" />}
                  accentColor="cyan"
                />
                <KPICard
                  label="ETL Latency"
                  value={`${payload.meta.processing_time_ms} ms`}
                  subtext={`Polars SIMD RAM`}
                  icon={<Zap className="w-4 h-4" />}
                  accentColor="emerald"
                />
              </div>
            )}

            {/* Interactive Graph Canvas Workspace */}
            {payload && (
              <div className="flex-1 flex border border-slate-800 rounded-xl overflow-hidden bg-slate-950 relative min-h-[480px]">
                <div className="flex-1 relative">
                  <GraphCanvas
                    graph={payload.graph}
                    selectedNode={selectedNode}
                    onSelectNode={setSelectedNode}
                    sessionId={sessionId}
                  />
                </div>

                {/* Monospace Node Inspector Side Panel */}
                <NodeInspector
                  node={selectedNode}
                  edges={payload.graph.edges}
                  onClose={() => setSelectedNode(null)}
                />
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
