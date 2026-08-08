import React from 'react';
import { Cpu, Activity, Database, CheckCircle2 } from 'lucide-react';
import { StreamingState } from '../types/graph';

interface ProgressBarProps {
  state: StreamingState;
  totalNodes: number;
  totalEdges: number;
}

export const ProgressBar: React.FC<ProgressBarProps> = ({
  state,
  totalNodes,
  totalEdges,
}) => {
  const { isStreaming, progress, processedLines, totalLines, currentChunk, totalChunks, statusText } = state;

  return (
    <div className="w-full bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-xl backdrop-blur-md font-mono flex flex-col gap-3">
      {/* Top Header Row */}
      <div className="flex items-center justify-between text-xs">
        <div className="flex items-center gap-2.5">
          {isStreaming ? (
            <div className="p-1.5 rounded-lg bg-cyan-950/60 border border-cyan-500/40 text-cyan-400">
              <Cpu className="w-4 h-4 animate-spin text-cyan-400" />
            </div>
          ) : (
            <div className="p-1.5 rounded-lg bg-emerald-950/60 border border-emerald-500/40 text-emerald-400">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            </div>
          )}
          <div>
            <span className="font-bold text-slate-200 tracking-wider">
              {isStreaming ? 'STREAMING POLARS ETL PIPELINE' : 'STREAMING COMPLETE'}
            </span>
            <p className="text-[11px] text-slate-400 mt-0.5">{statusText}</p>
          </div>
        </div>

        <div className="flex items-center gap-4 text-[11px] text-slate-300">
          <div className="flex items-center gap-1.5 bg-slate-950/60 px-2.5 py-1 rounded-md border border-slate-800">
            <Database className="w-3.5 h-3.5 text-cyan-400" />
            <span>
              {processedLines.toLocaleString()} / {totalLines ? totalLines.toLocaleString() : '...'} lines
            </span>
          </div>

          <div className="flex items-center gap-1.5 bg-slate-950/60 px-2.5 py-1 rounded-md border border-slate-800">
            <Activity className="w-3.5 h-3.5 text-amber-400" />
            <span>
              Batch {currentChunk + 1} / {totalChunks || 1}
            </span>
          </div>

          <span className="text-base font-bold text-cyan-400 w-16 text-right">
            {progress.toFixed(1)}%
          </span>
        </div>
      </div>

      {/* Main Tactical Progress Bar Container */}
      <div className="w-full h-3 bg-slate-950 rounded-full overflow-hidden border border-slate-800/80 relative p-0.5">
        <div
          className="h-full rounded-full transition-all duration-300 ease-out bg-gradient-to-r from-cyan-600 via-blue-500 to-emerald-400 shadow-md shadow-cyan-500/20 relative overflow-hidden"
          style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
        >
          {isStreaming && (
            <div className="absolute inset-0 bg-[linear-gradient(90deg,transparent_0%,rgba(255,255,255,0.4)_50%,transparent_100%)] animate-[shimmer_1.5s_infinite]" />
          )}
        </div>
      </div>

      {/* Bottom Counter Indicators */}
      <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800/60">
        <div className="flex items-center gap-3">
          <span>
            Topology Spawned: <strong className="text-cyan-400">{totalNodes}</strong> nodes,{' '}
            <strong className="text-amber-400">{totalEdges}</strong> edges
          </span>
        </div>
        <div>
          <span>Chunk Size: <strong className="text-slate-300">100,000 lines</strong></span>
        </div>
      </div>
    </div>
  );
};
