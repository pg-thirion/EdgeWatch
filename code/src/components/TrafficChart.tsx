import React, { useState } from 'react';
import { TrafficDataPoint } from '../types/security';
import { AlertTriangle, Clock, Layers } from 'lucide-react';

interface TrafficChartProps {
  data: TrafficDataPoint[];
  selectedRange: string;
  onRangeChange: (range: string) => void;
  sampleRate: number;
}

export const TrafficChart: React.FC<TrafficChartProps> = ({
  data,
  selectedRange,
  onRangeChange,
  sampleRate,
}) => {
  const [hoveredPoint, setHoveredPoint] = useState<TrafficDataPoint | null>(null);
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  // Maximum value for scaling Y-axis
  const maxVal = Math.max(10, ...data.map((d) => d.total));

  return (
    <div className="bg-[#121215] border border-[#27272f] rounded-xl p-5 select-none">
      {/* Chart Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="font-semibold text-sm tracking-wide text-zinc-100 uppercase">
              Incoming Web Traffic & WAF Actions
            </h3>
            {sampleRate > 1 && (
              <span className="text-[11px] bg-amber-500/10 text-amber-400 border border-amber-500/20 px-2 py-0.5 rounded-full flex items-center gap-1 font-mono">
                <Layers className="w-3 h-3" /> Sampled (1:{sampleRate})
              </span>
            )}
          </div>
          <p className="text-xs text-zinc-400 mt-0.5">
            Real-time request distribution by security mitigation action
          </p>
        </div>

        {/* Time range selector pills matching Vercel */}
        <div className="flex items-center gap-1 bg-[#18181c] p-1 rounded-lg border border-zinc-800 text-xs">
          {['10m', '1h', '24h', '3d', '7d'].map((range) => (
            <button
              key={range}
              onClick={() => onRangeChange(range)}
              className={`px-2.5 py-1 rounded-md font-medium transition cursor-pointer ${
                selectedRange === range
                  ? 'bg-zinc-700 text-white shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800'
              }`}
            >
              {range}
            </button>
          ))}
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-4 text-xs text-zinc-400 mb-3 border-b border-zinc-800/60 pb-3">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500"></span>
          <span>Allowed</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-sm bg-red-500"></span>
          <span>Denied (WAF Block)</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-sm bg-amber-500"></span>
          <span>Challenged (JS/Managed)</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-sm bg-blue-500"></span>
          <span>Logged (Simulated)</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-sm bg-purple-500"></span>
          <span>Rate Limited</span>
        </div>
      </div>

      {/* Main Chart Graphic */}
      <div className="relative h-[220px] w-full flex items-end pt-4">
        {/* Y Axis Grid lines */}
        <div className="absolute inset-0 flex flex-col justify-between pointer-events-none text-[10px] text-zinc-600 font-mono">
          <div className="border-b border-zinc-800/40 w-full flex justify-between">
            <span>{maxVal} req/s</span>
          </div>
          <div className="border-b border-zinc-800/40 w-full flex justify-between">
            <span>{Math.round(maxVal * 0.66)}</span>
          </div>
          <div className="border-b border-zinc-800/40 w-full flex justify-between">
            <span>{Math.round(maxVal * 0.33)}</span>
          </div>
          <div className="border-b border-zinc-800/80 w-full flex justify-between">
            <span>0</span>
          </div>
        </div>

        {/* Stacked Bars */}
        <div className="relative w-full h-full flex items-end justify-between gap-1.5 z-10 px-2">
          {data.map((point, idx) => {
            const total = Math.max(1, point.total);
            const allowedPct = (point.allowed / total) * 100;
            const deniedPct = (point.denied / total) * 100;
            const challengedPct = (point.challenged / total) * 100;
            const loggedPct = (point.logged / total) * 100;
            const rateLimitedPct = (point.rateLimited / total) * 100;

            const isHovered = hoveredIndex === idx;

            return (
              <div
                key={idx}
                onMouseEnter={() => {
                  setHoveredPoint(point);
                  setHoveredIndex(idx);
                }}
                onMouseLeave={() => {
                  setHoveredPoint(null);
                  setHoveredIndex(null);
                }}
                className="relative flex-1 h-full flex flex-col justify-end items-center cursor-pointer group"
              >
                {/* Spike alert flag indicator above bar */}
                {point.isSpike && (
                  <div className="absolute -top-3 flex flex-col items-center">
                    <span className="flex h-2 w-2 relative">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
                    </span>
                  </div>
                )}

                {/* Stacked column */}
                <div
                  className={`w-full max-w-[24px] rounded-t flex flex-col justify-end overflow-hidden transition-all ${
                    isHovered ? 'ring-1 ring-white/60 brightness-125' : 'hover:brightness-110'
                  }`}
                  style={{ height: `${Math.min(100, Math.max(2, (point.total / maxVal) * 100))}%` }}
                >
                  {/* Rate limited segment */}
                  {rateLimitedPct > 0 && (
                    <div style={{ height: `${rateLimitedPct}%` }} className="bg-purple-500 w-full" />
                  )}
                  {/* Denied segment */}
                  {deniedPct > 0 && (
                    <div style={{ height: `${deniedPct}%` }} className="bg-red-500 w-full" />
                  )}
                  {/* Challenged segment */}
                  {challengedPct > 0 && (
                    <div style={{ height: `${challengedPct}%` }} className="bg-amber-500 w-full" />
                  )}
                  {/* Logged segment */}
                  {loggedPct > 0 && (
                    <div style={{ height: `${loggedPct}%` }} className="bg-blue-500 w-full" />
                  )}
                  {/* Allowed segment */}
                  {allowedPct > 0 && (
                    <div style={{ height: `${allowedPct}%` }} className="bg-emerald-500 w-full" />
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* Hover Tooltip Overlay */}
        {hoveredPoint && hoveredIndex !== null && (
          <div
            style={{
              left: `${Math.min(85, Math.max(15, (hoveredIndex / (data.length - 1)) * 100))}%`,
              top: '15px',
              transform: 'translateX(-50%)',
            }}
            className="absolute z-20 pointer-events-none bg-[#18181c] border border-zinc-700 shadow-2xl rounded-lg p-3 text-xs w-56 text-zinc-200"
          >
            <div className="flex items-center justify-between border-b border-zinc-800 pb-1 mb-2 font-mono text-[11px] text-zinc-400">
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3" /> {hoveredPoint.timeLabel}
              </span>
              <span className="font-semibold text-white">Total: {hoveredPoint.total}</span>
            </div>
            <div className="space-y-1 font-mono text-[11px]">
              <div className="flex justify-between text-emerald-400">
                <span>Allowed:</span>
                <span>{hoveredPoint.allowed}</span>
              </div>
              <div className="flex justify-between text-red-400">
                <span>Denied (WAF):</span>
                <span>{hoveredPoint.denied}</span>
              </div>
              <div className="flex justify-between text-amber-400">
                <span>Challenged:</span>
                <span>{hoveredPoint.challenged}</span>
              </div>
              <div className="flex justify-between text-purple-400">
                <span>Rate Limited:</span>
                <span>{hoveredPoint.rateLimited}</span>
              </div>
              <div className="flex justify-between text-blue-400">
                <span>Logged:</span>
                <span>{hoveredPoint.logged}</span>
              </div>
              {hoveredPoint.isSpike && (
                <div className="mt-1 pt-1 border-t border-red-500/30 flex items-center gap-1 text-red-400 text-[10px]">
                  <AlertTriangle className="w-3 h-3" />
                  <span>Traffic Spike Detected</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* X Axis Time Labels */}
      <div className="flex justify-between items-center text-[11px] text-zinc-500 font-mono mt-3 px-2 border-t border-zinc-800/60 pt-2">
        <span>{data[0]?.timeLabel || 'T-minus'}</span>
        <span>{data[Math.floor(data.length / 2)]?.timeLabel || 'Mid'}</span>
        <span>{data[data.length - 1]?.timeLabel || 'Now'}</span>
      </div>
    </div>
  );
};
