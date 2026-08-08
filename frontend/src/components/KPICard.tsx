import React from 'react';

interface KPICardProps {
  label: string;
  value: string | number;
  subtext?: string;
  icon: React.ReactNode;
  accentColor?: 'red' | 'amber' | 'blue' | 'emerald' | 'cyan';
}

export const KPICard: React.FC<KPICardProps> = ({
  label,
  value,
  subtext,
  icon,
  accentColor = 'blue',
}) => {
  const borderColors = {
    red: 'border-red-500/30 hover:border-red-500/60 bg-red-950/20 text-red-400',
    amber: 'border-amber-500/30 hover:border-amber-500/60 bg-amber-950/20 text-amber-400',
    blue: 'border-blue-500/30 hover:border-blue-500/60 bg-blue-950/20 text-blue-400',
    emerald: 'border-emerald-500/30 hover:border-emerald-500/60 bg-emerald-950/20 text-emerald-400',
    cyan: 'border-cyan-500/30 hover:border-cyan-500/60 bg-cyan-950/20 text-cyan-400',
  };

  const textColors = {
    red: 'text-red-400',
    amber: 'text-amber-400',
    blue: 'text-blue-400',
    emerald: 'text-emerald-400',
    cyan: 'text-cyan-400',
  };

  return (
    <div className={`border p-3.5 rounded-xl bg-slate-900/80 backdrop-blur-sm transition-all duration-200 shadow-lg shadow-slate-950/50 ${borderColors[accentColor]}`}>
      <div className="flex items-center justify-between text-slate-400 mb-1">
        <span className="text-[10px] font-mono font-semibold tracking-wider uppercase text-slate-400">{label}</span>
        <div className={`p-1 rounded-md bg-slate-800/80 ${textColors[accentColor]}`}>
          {icon}
        </div>
      </div>
      <div className={`text-2xl font-mono font-bold tracking-tight text-white flex items-baseline gap-1.5`}>
        {value}
      </div>
      {subtext && (
        <div className="text-[11px] font-mono text-slate-400 mt-1 truncate">
          {subtext}
        </div>
      )}
    </div>
  );
};
