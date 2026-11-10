import React from 'react';
import {
  X,
  ShieldAlert,
  Fingerprint,
  PlusCircle,
  Activity,
} from 'lucide-react';
import { WafEvent } from '../types/security';

interface IpInvestigationModalProps {
  ip: string;
  historicalEvents: WafEvent[];
  onClose: () => void;
  onProposeRuleForIp: (ip: string) => void;
}

export const IpInvestigationModal: React.FC<IpInvestigationModalProps> = ({
  ip,
  historicalEvents,
  onClose,
  onProposeRuleForIp,
}) => {
  // Aggregate IP intelligence from historical events
  const ipEvents = historicalEvents.filter((e) => e.clientIP === ip);
  const sampleEvent = ipEvents[0] || historicalEvents[0];

  const totalRequests = ipEvents.length * (sampleEvent?.sampleInterval || 5);
  const blockedCount = ipEvents.filter((e) => e.action === 'block').length * (sampleEvent?.sampleInterval || 5);
  const challengeFailures = ipEvents.filter((e) => e.action === 'challenge' || e.action === 'managed_challenge').length * (sampleEvent?.sampleInterval || 5);

  const threatScore = sampleEvent ? sampleEvent.threatScore : 85;

  let reputation: 'Malicious' | 'Suspicious' | 'Neutral' | 'Clean' = 'Suspicious';
  if (threatScore >= 80 || blockedCount > 50) reputation = 'Malicious';
  else if (threatScore < 20 && blockedCount === 0) reputation = 'Clean';

  // Extract distinct user agents and JA4 fingerprints
  const userAgents = Array.from(new Set(ipEvents.map((e) => e.userAgent))).filter(Boolean);
  const ja4Fingerprints = Array.from(new Set(ipEvents.map((e) => e.ja4Fingerprint))).filter(Boolean);

  // Group matched rules
  const ruleMap: Record<string, { name: string; count: number }> = {};
  ipEvents.forEach((e) => {
    if (e.ruleName) {
      if (!ruleMap[e.ruleName]) {
        ruleMap[e.ruleName] = { name: e.ruleName, count: 0 };
      }
      ruleMap[e.ruleName].count += 1;
    }
  });

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-[#121215] border border-[#27272f] w-full max-w-2xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-5 border-b border-[#27272f] bg-[#16161b] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className={`w-10 h-10 rounded-lg flex items-center justify-center border font-mono font-bold text-sm ${
                reputation === 'Malicious'
                  ? 'bg-red-500/15 border-red-500/30 text-red-400'
                  : reputation === 'Suspicious'
                  ? 'bg-amber-500/15 border-amber-500/30 text-amber-400'
                  : 'bg-emerald-500/15 border-emerald-500/30 text-emerald-400'
              }`}
            >
              IP
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-mono font-bold text-zinc-100">{ip}</h2>
                <span
                  className={`text-[11px] font-semibold px-2 py-0.5 rounded-full border ${
                    reputation === 'Malicious'
                      ? 'bg-red-500/15 text-red-400 border-red-500/30'
                      : reputation === 'Suspicious'
                      ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                      : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                  }`}
                >
                  {reputation}
                </span>
              </div>
              <p className="text-xs text-zinc-400 mt-0.5">
                {sampleEvent?.clientCountryName} ({sampleEvent?.clientCountry}) • ASN:{' '}
                {sampleEvent?.clientAsn} ({sampleEvent?.clientAsnName})
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-5 text-sm">
          {/* Top Metric Cards */}
          <div className="grid grid-cols-4 gap-3">
            <div className="bg-[#18181c] border border-zinc-800 rounded-lg p-3">
              <span className="text-zinc-500 text-[11px] block">Threat Score</span>
              <div className="text-lg font-bold font-mono text-red-400 mt-1">
                {threatScore} <span className="text-xs text-zinc-500">/ 100</span>
              </div>
            </div>
            <div className="bg-[#18181c] border border-zinc-800 rounded-lg p-3">
              <span className="text-zinc-500 text-[11px] block">Total Observed</span>
              <div className="text-lg font-bold font-mono text-zinc-100 mt-1">
                {totalRequests}
              </div>
            </div>
            <div className="bg-[#18181c] border border-zinc-800 rounded-lg p-3">
              <span className="text-zinc-500 text-[11px] block">Blocked</span>
              <div className="text-lg font-bold font-mono text-red-400 mt-1">
                {blockedCount}
              </div>
            </div>
            <div className="bg-[#18181c] border border-zinc-800 rounded-lg p-3">
              <span className="text-zinc-500 text-[11px] block">Failed Challenges</span>
              <div className="text-lg font-bold font-mono text-amber-400 mt-1">
                {challengeFailures}
              </div>
            </div>
          </div>

          {/* Historical Activity Breakdown */}
          <div className="bg-[#18181c] border border-zinc-800 rounded-lg p-4 space-y-3">
            <h4 className="text-xs uppercase tracking-wider font-semibold text-zinc-400 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-blue-400" /> Historical Activity & Ratio
            </h4>

            {/* Progress ratio bar */}
            <div>
              <div className="h-2.5 w-full bg-zinc-800 rounded-full overflow-hidden flex">
                <div
                  style={{
                    width: `${blockedCount > 0 ? Math.max(3, (blockedCount / Math.max(1, totalRequests)) * 100) : 0}%`,
                  }}
                  className="bg-red-500"
                />
                <div
                  style={{
                    width: `${challengeFailures > 0 ? Math.max(3, (challengeFailures / Math.max(1, totalRequests)) * 100) : 0}%`,
                  }}
                  className="bg-amber-500"
                />
                <div className="bg-emerald-500 flex-1" />
              </div>
              <div className="flex justify-between text-[11px] text-zinc-400 mt-1.5 font-mono">
                <span className="text-red-400">Blocked: {blockedCount}</span>
                <span className="text-amber-400">Challenged: {challengeFailures}</span>
                <span className="text-emerald-400">
                  Allowed: {Math.max(0, totalRequests - blockedCount - challengeFailures)}
                </span>
              </div>
            </div>
          </div>

          {/* Matched WAF Rules History */}
          <div className="bg-[#18181c] border border-zinc-800 rounded-lg p-4 space-y-3">
            <h4 className="text-xs uppercase tracking-wider font-semibold text-zinc-400 flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" /> Matched WAF Rules
            </h4>

            <div className="space-y-1.5">
              {Object.keys(ruleMap).length > 0 ? (
                Object.values(ruleMap).map((rule, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between p-2 rounded bg-[#121215] border border-zinc-800 text-xs"
                  >
                    <span className="text-zinc-200 font-medium">{rule.name}</span>
                    <span className="font-mono text-zinc-400 bg-zinc-800 px-2 py-0.5 rounded">
                      {rule.count} matches
                    </span>
                  </div>
                ))
              ) : (
                <div className="text-xs text-zinc-500 italic p-2">
                  No managed rule violations recorded.
                </div>
              )}
            </div>
          </div>

          {/* Observed JA4 TLS Fingerprints & User Agents */}
          <div className="bg-[#18181c] border border-zinc-800 rounded-lg p-4 space-y-3">
            <h4 className="text-xs uppercase tracking-wider font-semibold text-zinc-400 flex items-center gap-1.5">
              <Fingerprint className="w-3.5 h-3.5 text-purple-400" /> Fingerprints & User Agents
            </h4>

            <div className="space-y-2">
              <div>
                <span className="text-zinc-500 text-[11px] block mb-1">Observed JA4 Hashes:</span>
                <div className="space-y-1">
                  {ja4Fingerprints.map((ja4, i) => (
                    <div
                      key={i}
                      className="font-mono text-[11px] bg-[#121215] p-1.5 rounded border border-zinc-800 text-purple-300 select-all"
                    >
                      {ja4}
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <span className="text-zinc-500 text-[11px] block mb-1">User Agents:</span>
                <div className="space-y-1">
                  {userAgents.map((ua, i) => (
                    <div
                      key={i}
                      className="font-mono text-[11px] bg-[#121215] p-1.5 rounded border border-zinc-800 text-zinc-300 break-all select-all"
                    >
                      {ua}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-[#27272f] bg-[#16161b] flex items-center justify-between">
          <span className="text-xs text-zinc-400">
            Source: Cloudflare GraphQL Analytics <code className="text-zinc-300">firewallEventsAdaptive</code>
          </span>
          <button
            onClick={() => {
              onProposeRuleForIp(ip);
              onClose();
            }}
            className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold cursor-pointer shadow-sm transition"
          >
            <PlusCircle className="w-4 h-4" /> Propose WAF Rule for this IP
          </button>
        </div>
      </div>
    </div>
  );
};
