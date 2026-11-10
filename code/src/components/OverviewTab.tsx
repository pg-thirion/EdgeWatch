import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileCode,
  Terminal,
  Activity,
  Layers,
  Search,
  PlusCircle,
  ExternalLink,
  ChevronRight,
  TrendingUp,
} from 'lucide-react';
import {
  WafEvent,
  WafRule,
  CloudflareZone,
  SpikeAnomaly,
  TrafficDataPoint,
} from '../types/security';
import { TrafficChart } from './TrafficChart';
import { ThreatWorldMap } from './ThreatWorldMap';

interface OverviewTabProps {
  events: WafEvent[];
  rules: WafRule[];
  zones: CloudflareZone[];
  anomalies: SpikeAnomaly[];
  trafficData: TrafficDataPoint[];
  selectedRange: string;
  onRangeChange: (range: string) => void;
  selectedCountry: string | null;
  onSelectCountry: (country: string | null) => void;
  onInspectEvent: (event: WafEvent) => void;
  onInvestigateIp: (ip: string) => void;
  onProposeRuleFromEvent: (event: WafEvent) => void;
  onProposeNewRule: () => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  events,
  rules,
  zones,
  anomalies,
  trafficData,
  selectedRange,
  onRangeChange,
  selectedCountry,
  onSelectCountry,
  onInspectEvent,
  onInvestigateIp,
  onProposeRuleFromEvent,
  onProposeNewRule,
}) => {
  // Aggregate KPI stats
  const totalRequests = trafficData.reduce((acc, curr) => acc + curr.total, 0) || events.length * 5;
  const totalDenied = trafficData.reduce((acc, curr) => acc + curr.denied, 0) || events.filter((e) => e.action === 'block').length * 5;
  const totalChallenged = trafficData.reduce((acc, curr) => acc + curr.challenged, 0) || events.filter((e) => e.action === 'challenge' || e.action === 'managed_challenge').length * 5;
  const totalLogged = trafficData.reduce((acc, curr) => acc + curr.logged, 0) || events.filter((e) => e.action === 'log').length * 5;
  const totalRateLimited = trafficData.reduce((acc, curr) => acc + curr.rateLimited, 0) || events.filter((e) => e.action === 'rate_limit').length * 5;

  // Filter events if country selected
  const displayEvents = selectedCountry
    ? events.filter((e) => e.clientCountry.toUpperCase() === selectedCountry.toUpperCase())
    : events;

  // Aggregate Top Denied IPs
  const ipCounts: Record<string, { count: number; blocked: number; event: WafEvent }> = {};
  events.forEach((e) => {
    if (!ipCounts[e.clientIP]) {
      ipCounts[e.clientIP] = { count: 0, blocked: 0, event: e };
    }
    ipCounts[e.clientIP].count += 1;
    if (e.action === 'block') ipCounts[e.clientIP].blocked += 1;
  });

  const topDeniedIps = Object.entries(ipCounts)
    .sort((a, b) => b[1].blocked - a[1].blocked || b[1].count - a[1].count)
    .slice(0, 5)
    .map(([ip, data]) => ({
      ip,
      count: data.count * (data.event.sampleInterval || 5),
      blocked: data.blocked * (data.event.sampleInterval || 5),
      event: data.event,
    }));

  return (
    <div className="space-y-6">
      {/* Active Anomaly Alerts (Request Spikes & Repeated Challenge Failures) */}
      {anomalies.filter((a) => a.status === 'active').length > 0 && (
        <div className="space-y-2.5">
          {anomalies
            .filter((a) => a.status === 'active')
            .map((anom) => (
              <div
                key={anom.id}
                className="p-4 bg-red-950/20 border border-red-500/40 rounded-xl flex flex-wrap items-center justify-between gap-4 shadow-lg shadow-red-950/10"
              >
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400 shrink-0">
                    <AlertTriangle className="w-5 h-5 animate-pulse" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                        {anom.type.replace('_', ' ')}
                      </span>
                      <h4 className="font-semibold text-sm text-zinc-100">{anom.title}</h4>
                      <span className="text-xs font-mono text-zinc-400">({anom.zoneName})</span>
                    </div>
                    <p className="text-xs text-zinc-300 mt-1 leading-relaxed">
                      {anom.description}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {anom.suspectIp && (
                    <button
                      onClick={() => onInvestigateIp(anom.suspectIp!)}
                      className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 rounded-lg text-xs font-medium transition cursor-pointer flex items-center gap-1.5"
                    >
                      <Search className="w-3.5 h-3.5" /> Investigate IP
                    </button>
                  )}
                  <button
                    onClick={() => {
                      const sampleEvt = events.find((e) => e.clientIP === anom.suspectIp) || events[0];
                      onProposeRuleFromEvent(sampleEvt);
                    }}
                    className="px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-semibold transition cursor-pointer shadow-sm flex items-center gap-1.5"
                  >
                    <PlusCircle className="w-3.5 h-3.5" /> Mitigate Rule
                  </button>
                </div>
              </div>
            ))}
        </div>
      )}

      {/* KPI Stat Cards (Matching Vercel Firewall Overview) */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="bg-[#121215] border border-[#27272f] rounded-xl p-4">
          <span className="text-xs text-zinc-400 font-medium">Total Requests</span>
          <div className="text-2xl font-bold font-mono text-zinc-100 mt-1">
            {totalRequests.toLocaleString()}
          </div>
          <div className="flex items-center gap-1 text-[11px] text-emerald-400 font-mono mt-1">
            <TrendingUp className="w-3 h-3" /> Baseline Normal
          </div>
        </div>

        <div className="bg-[#121215] border border-[#27272f] rounded-xl p-4">
          <span className="text-xs text-red-400 font-medium">Denied (Blocked)</span>
          <div className="text-2xl font-bold font-mono text-red-400 mt-1">
            {totalDenied.toLocaleString()}
          </div>
          <div className="text-[11px] text-zinc-500 font-mono mt-1">
            {Math.round((totalDenied / Math.max(1, totalRequests)) * 100)}% of traffic
          </div>
        </div>

        <div className="bg-[#121215] border border-[#27272f] rounded-xl p-4">
          <span className="text-xs text-amber-400 font-medium">Challenged</span>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-1">
            {totalChallenged.toLocaleString()}
          </div>
          <div className="text-[11px] text-zinc-500 font-mono mt-1">
            Turnstile / JS Challenge
          </div>
        </div>

        <div className="bg-[#121215] border border-[#27272f] rounded-xl p-4">
          <span className="text-xs text-blue-400 font-medium">Logged</span>
          <div className="text-2xl font-bold font-mono text-blue-400 mt-1">
            {totalLogged.toLocaleString()}
          </div>
          <div className="text-[11px] text-zinc-500 font-mono mt-1">
            Passive observation
          </div>
        </div>

        <div className="bg-[#121215] border border-[#27272f] rounded-xl p-4">
          <span className="text-xs text-purple-400 font-medium">Rate Limited</span>
          <div className="text-2xl font-bold font-mono text-purple-400 mt-1">
            {totalRateLimited.toLocaleString()}
          </div>
          <div className="text-[11px] text-zinc-500 font-mono mt-1">
            Velocity throttled
          </div>
        </div>
      </div>

      {/* Traffic Time-Series Chart */}
      <TrafficChart
        data={trafficData}
        selectedRange={selectedRange}
        onRangeChange={onRangeChange}
        sampleRate={zones[0]?.plan === 'enterprise' ? 1 : 5}
      />

      {/* Interactive Threat-Origin World Map */}
      <ThreatWorldMap
        events={events}
        selectedCountry={selectedCountry}
        onSelectCountry={onSelectCountry}
      />

      {/* Two Column Grid: Top Denied IPs + Active WAF Rules Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Denied IPs Table */}
        <div className="bg-[#121215] border border-[#27272f] rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4 border-b border-zinc-800 pb-3">
              <div>
                <h3 className="font-semibold text-sm tracking-wide text-zinc-100 uppercase">
                  Top Denied IP Addresses
                </h3>
                <p className="text-xs text-zinc-400 mt-0.5">
                  Frequently mitigated malicious sources
                </p>
              </div>
              <span className="text-xs bg-red-500/10 text-red-400 border border-red-500/30 px-2 py-0.5 rounded font-mono">
                Threat Intelligence
              </span>
            </div>

            <div className="space-y-2">
              {topDeniedIps.map((item) => (
                <div
                  key={item.ip}
                  className="p-3 bg-[#18181c] border border-zinc-800/80 rounded-lg flex items-center justify-between hover:border-zinc-700 transition"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-xs text-zinc-200">{item.ip}</span>
                      <span className="text-[10px] bg-zinc-800 text-zinc-400 px-1.5 py-0.2 rounded font-medium">
                        {item.event.clientCountry}
                      </span>
                    </div>
                    <div className="text-[11px] text-zinc-400">
                      {item.event.clientAsnName} ({item.event.clientAsn})
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="text-right">
                      <div className="font-mono font-bold text-xs text-red-400">
                        {item.blocked.toLocaleString()} denied
                      </div>
                      <div className="text-[10px] text-zinc-500 font-mono">
                        Threat: {item.event.threatScore}/100
                      </div>
                    </div>
                    <button
                      data-testid="investigate-ip-btn"
                      onClick={() => onInvestigateIp(item.ip)}
                      className="px-2.5 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded text-xs border border-zinc-700 cursor-pointer transition"
                    >
                      Investigate IP
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* WAF Rules Breakdown */}
        <div className="bg-[#121215] border border-[#27272f] rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4 border-b border-zinc-800 pb-3">
              <div>
                <h3 className="font-semibold text-sm tracking-wide text-zinc-100 uppercase">
                  WAF Rules Engine Distribution
                </h3>
                <p className="text-xs text-zinc-400 mt-0.5">
                  Phase: <code className="text-zinc-300">http_request_firewall_custom</code>
                </p>
              </div>
              <button
                onClick={onProposeNewRule}
                className="flex items-center gap-1 text-xs bg-blue-600 hover:bg-blue-500 text-white px-2.5 py-1 rounded font-medium transition cursor-pointer"
              >
                <PlusCircle className="w-3.5 h-3.5" /> New Rule
              </button>
            </div>

            <div className="space-y-2.5">
              {rules.slice(0, 5).map((rule) => (
                <div
                  key={rule.id}
                  className="p-3 bg-[#18181c] border border-zinc-800/80 rounded-lg hover:border-zinc-700 transition"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium text-xs text-zinc-200">{rule.name}</span>
                    <span
                      className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded font-mono ${
                        rule.action === 'block'
                          ? 'bg-red-500/15 text-red-400'
                          : rule.action === 'challenge' || rule.action === 'managed_challenge'
                          ? 'bg-amber-500/15 text-amber-400'
                          : rule.action === 'rate_limit'
                          ? 'bg-purple-500/15 text-purple-400'
                          : 'bg-blue-500/15 text-blue-400'
                      }`}
                    >
                      {rule.action}
                    </span>
                  </div>
                  <div className="font-mono text-[11px] text-zinc-400 truncate bg-[#121215] p-1.5 rounded border border-zinc-800/60 mb-1">
                    {rule.expression}
                  </div>
                  <div className="flex justify-between items-center text-[10px] text-zinc-500 font-mono">
                    <span>24h matches: {rule.matchedCount24h.toLocaleString()}</span>
                    <span>Status: {rule.enabled ? 'Active' : 'Disabled'}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Recent WAF Events Table */}
      <div className="bg-[#121215] border border-[#27272f] rounded-xl p-5">
        <div className="flex items-center justify-between mb-4 border-b border-zinc-800 pb-3">
          <div>
            <h3 className="font-semibold text-sm tracking-wide text-zinc-100 uppercase">
              Recent WAF Events Telemetry
            </h3>
            <p className="text-xs text-zinc-400 mt-0.5">
              Inspected incoming requests and rule execution logs
            </p>
          </div>
          <span className="text-xs text-zinc-400 font-mono">
            Showing {displayEvents.length} events
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#18181c] text-zinc-400 border-b border-zinc-800 font-semibold uppercase tracking-wider text-[11px]">
              <tr>
                <th className="p-3">Action</th>
                <th className="p-3">Time</th>
                <th className="p-3">Client IP / Country</th>
                <th className="p-3">Method & Path</th>
                <th className="p-3">Zone</th>
                <th className="p-3">Triggered Rule</th>
                <th className="p-3">Sample</th>
                <th className="p-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60 text-zinc-300">
              {displayEvents.map((evt) => (
                <tr key={evt.id} className="hover:bg-zinc-800/40 transition group">
                  <td className="p-3">
                    <span
                      className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase ${
                        evt.action === 'block'
                          ? 'bg-red-500/15 text-red-400 border border-red-500/30'
                          : evt.action === 'challenge' || evt.action === 'managed_challenge'
                          ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                          : evt.action === 'rate_limit'
                          ? 'bg-purple-500/15 text-purple-400 border border-purple-500/30'
                          : evt.action === 'log'
                          ? 'bg-blue-500/15 text-blue-400 border border-blue-500/30'
                          : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                      }`}
                    >
                      {evt.action}
                    </span>
                  </td>
                  <td className="p-3 font-mono text-zinc-400">
                    {new Date(evt.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="p-3">
                    <div className="font-mono text-zinc-200">{evt.clientIP}</div>
                    <div className="text-[10px] text-zinc-400">{evt.clientCountryName}</div>
                  </td>
                  <td className="p-3">
                    <span className="font-bold text-zinc-300 mr-1.5">{evt.clientRequestHTTPMethod}</span>
                    <span className="font-mono text-zinc-400 truncate max-w-xs inline-block align-bottom">
                      {evt.clientRequestPath}
                    </span>
                  </td>
                  <td className="p-3 text-blue-400 font-medium">{evt.zoneName}</td>
                  <td className="p-3 text-zinc-300 truncate max-w-[200px]">
                    {evt.ruleName || 'Default Evaluation'}
                  </td>
                  <td className="p-3 font-mono text-zinc-400">
                    {evt.sampleInterval > 1 ? `1:${evt.sampleInterval}` : '1:1'}
                  </td>
                  <td className="p-3 text-right">
                    <button
                      data-testid="inspect-event-btn"
                      onClick={() => onInspectEvent(evt)}
                      className="px-2.5 py-1 bg-zinc-800 hover:bg-blue-600 text-zinc-200 hover:text-white rounded text-xs font-medium transition cursor-pointer border border-zinc-700"
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
