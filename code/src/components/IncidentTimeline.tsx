import React from 'react';
import {
  AlertTriangle,
  Search,
  Sliders,
  CheckCircle2,
  Clock,
  ShieldCheck,
  Activity,
} from 'lucide-react';
import { IncidentTimelineEvent } from '../types/security';

interface IncidentTimelineProps {
  events: IncidentTimelineEvent[];
}

export const IncidentTimeline: React.FC<IncidentTimelineProps> = ({ events }) => {
  const getPhaseIcon = (phase: IncidentTimelineEvent['phase']) => {
    switch (phase) {
      case 'anomaly_detected':
        return <AlertTriangle className="w-4 h-4 text-red-400" />;
      case 'investigation_started':
        return <Search className="w-4 h-4 text-blue-400" />;
      case 'rule_previewed':
        return <Sliders className="w-4 h-4 text-amber-400" />;
      case 'rule_approved':
        return <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
      case 'traffic_stabilized':
        return <ShieldCheck className="w-4 h-4 text-emerald-400" />;
      default:
        return <Activity className="w-4 h-4 text-zinc-400" />;
    }
  };

  const getPhaseBadge = (phase: IncidentTimelineEvent['phase']) => {
    switch (phase) {
      case 'anomaly_detected':
        return 'bg-red-500/15 text-red-400 border-red-500/30';
      case 'investigation_started':
        return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
      case 'rule_previewed':
        return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
      case 'rule_approved':
        return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
      default:
        return 'bg-zinc-800 text-zinc-300 border-zinc-700';
    }
  };

  return (
    <div className="bg-[#121215] border border-[#27272f] rounded-xl p-5">
      <div className="flex items-center justify-between mb-5 border-b border-zinc-800 pb-3">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-blue-400" />
          <h3 className="font-semibold text-sm tracking-wide text-zinc-100 uppercase">
            Incident Response Timeline
          </h3>
          <span className="text-xs bg-zinc-800 text-zinc-400 px-2 py-0.5 rounded-full border border-zinc-700">
            Audit Trail
          </span>
        </div>
        <span className="text-xs text-zinc-500 font-mono">
          {events.length} milestone events logged
        </span>
      </div>

      <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-[1px] before:bg-zinc-800">
        {events.map((evt) => (
          <div key={evt.id} className="relative group">
            {/* Timeline Pin */}
            <div className="absolute -left-[27px] top-1 w-6 h-6 rounded-full bg-[#18181c] border border-zinc-700 flex items-center justify-center shadow-sm">
              {getPhaseIcon(evt.phase)}
            </div>

            <div className="bg-[#18181c] border border-zinc-800/80 rounded-lg p-3.5 hover:border-zinc-700 transition">
              <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
                <div className="flex items-center gap-2">
                  <h4 className="text-xs font-semibold text-zinc-100">{evt.title}</h4>
                  <span
                    className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${getPhaseBadge(
                      evt.phase
                    )}`}
                  >
                    {evt.phase.replace('_', ' ').toUpperCase()}
                  </span>
                </div>
                <span className="text-[11px] text-zinc-400 font-mono">
                  {new Date(evt.timestamp).toLocaleTimeString()}
                </span>
              </div>

              <p className="text-xs text-zinc-300 mb-2 leading-relaxed">
                {evt.description}
              </p>

              <div className="flex flex-wrap items-center justify-between text-[11px] text-zinc-500 pt-2 border-t border-zinc-800/60 font-mono">
                <span>Actor: <strong className="text-zinc-400">{evt.actor}</strong></span>
                {evt.metadata && (
                  <div className="flex gap-2">
                    {Object.entries(evt.metadata).map(([k, v]) => (
                      <span key={k} className="bg-[#121215] px-1.5 py-0.5 rounded border border-zinc-800">
                        {k}: {String(v)}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
