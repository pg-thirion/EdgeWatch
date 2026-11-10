import React, { useState } from 'react';
import {
  Globe,
  Filter,
  Search,
  Fingerprint,
  Server,
  Layers,
  ShieldAlert,
  ArrowUpRight,
  ExternalLink,
} from 'lucide-react';
import { WafEvent, CloudflareZone } from '../types/security';

interface TrafficTabProps {
  events: WafEvent[];
  zones: CloudflareZone[];
  onInvestigateIp: (ip: string) => void;
  onInspectEvent: (event: WafEvent) => void;
  onProposeRuleForPath: (path: string) => void;
}

export const TrafficTab: React.FC<TrafficTabProps> = ({
  events,
  zones,
  onInvestigateIp,
  onInspectEvent,
  onProposeRuleForPath,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterAction, setFilterAction] = useState<string>('all');
  const [filterZone, setFilterZone] = useState<string>('all');

  // Filter events based on selections
  const filteredEvents = events.filter((e) => {
    if (filterAction !== 'all' && e.action !== filterAction) return false;
    if (filterZone !== 'all' && e.zoneId !== filterZone && e.zoneName !== filterZone) return false;
    if (searchTerm.trim()) {
      const s = searchTerm.toLowerCase();
      return (
        e.clientIP.toLowerCase().includes(s) ||
        e.clientRequestPath.toLowerCase().includes(s) ||
        e.clientCountryName.toLowerCase().includes(s) ||
        e.clientAsnName.toLowerCase().includes(s) ||
        e.userAgent.toLowerCase().includes(s) ||
        (e.ja4Fingerprint && e.ja4Fingerprint.toLowerCase().includes(s))
      );
    }
    return true;
  });

  // Calculate dimensional aggregations
  // 1. Top IPs
  const ipMap: Record<string, { count: number; blocked: number; event: WafEvent }> = {};
  filteredEvents.forEach((e) => {
    if (!ipMap[e.clientIP]) ipMap[e.clientIP] = { count: 0, blocked: 0, event: e };
    ipMap[e.clientIP].count += 1;
    if (e.action === 'block') ipMap[e.clientIP].blocked += 1;
  });
  const topIps = Object.entries(ipMap)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 6);

  // 2. Top Paths
  const pathMap: Record<string, { count: number; blocked: number }> = {};
  filteredEvents.forEach((e) => {
    if (!pathMap[e.clientRequestPath]) pathMap[e.clientRequestPath] = { count: 0, blocked: 0 };
    pathMap[e.clientRequestPath].count += 1;
    if (e.action === 'block') pathMap[e.clientRequestPath].blocked += 1;
  });
  const topPaths = Object.entries(pathMap)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 6);

  // 3. Top Countries
  const countryMap: Record<string, { count: number; name: string }> = {};
  filteredEvents.forEach((e) => {
    if (!countryMap[e.clientCountry]) {
      countryMap[e.clientCountry] = { count: 0, name: e.clientCountryName };
    }
    countryMap[e.clientCountry].count += 1;
  });
  const topCountries = Object.entries(countryMap)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 6);

  // 4. Top ASNs
  const asnMap: Record<string, { count: number; name: string }> = {};
  filteredEvents.forEach((e) => {
    const key = `${e.clientAsn} - ${e.clientAsnName}`;
    if (!asnMap[key]) asnMap[key] = { count: 0, name: e.clientAsnName };
    asnMap[key].count += 1;
  });
  const topAsns = Object.entries(asnMap)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 6);

  // 5. Top JA4 Fingerprints
  const ja4Map: Record<string, number> = {};
  filteredEvents.forEach((e) => {
    const key = e.ja4Fingerprint || 't13d1516h2_clean_browser_tls_99';
    ja4Map[key] = (ja4Map[key] || 0) + 1;
  });
  const topJa4s = Object.entries(ja4Map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const totalFiltered = filteredEvents.length;

  return (
    <div className="space-y-6">
      {/* Top Filter Bar (Matching Vercel Traffic Tab) */}
      <div className="bg-[#121215] border border-[#27272f] rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2.5 flex-1 min-w-[280px]">
          {/* Search box */}
          <div className="relative flex-1 min-w-[200px]">
            <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter by IP, Path, Country, ASN, or JA4 fingerprint..."
              className="w-full bg-[#18181c] border border-zinc-700 text-zinc-200 rounded-lg pl-9 pr-3 py-2 text-xs focus:ring-1 focus:ring-blue-500 outline-none"
            />
          </div>

          {/* Action Filter */}
          <select
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            className="bg-[#18181c] border border-zinc-700 text-zinc-200 rounded-lg px-3 py-2 text-xs outline-none focus:ring-1 focus:ring-blue-500"
          >
            <option value="all">All Actions</option>
            <option value="block">Denied Only</option>
            <option value="challenge">Challenged Only</option>
            <option value="rate_limit">Rate Limited Only</option>
            <option value="log">Logged Only</option>
            <option value="allow">Allowed Only</option>
          </select>

          {/* Zone Filter */}
          <select
            value={filterZone}
            onChange={(e) => setFilterZone(e.target.value)}
            className="bg-[#18181c] border border-zinc-700 text-zinc-200 rounded-lg px-3 py-2 text-xs outline-none focus:ring-1 focus:ring-blue-500"
          >
            <option value="all">All Zones</option>
            {zones.map((z) => (
              <option key={z.id} value={z.id}>
                {z.name}
              </option>
            ))}
          </select>
        </div>

        <span className="text-xs text-zinc-400 font-mono">
          {totalFiltered} matching requests
        </span>
      </div>

      {/* Multi-Dimensional Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Dimension 1: Top Client IP Addresses */}
        <div className="bg-[#121215] border border-[#27272f] rounded-xl p-5">
          <div className="flex items-center justify-between mb-4 border-b border-zinc-800 pb-2.5">
            <h3 className="font-semibold text-xs tracking-wider uppercase text-zinc-200">
              Top Source IP Addresses
            </h3>
            <span className="text-[11px] text-zinc-500 font-mono">Top Traffic Sources</span>
          </div>

          <div className="space-y-2">
            {topIps.map(([ip, data]) => {
              const pct = Math.round((data.count / Math.max(1, totalFiltered)) * 100);
              return (
                <div
                  key={ip}
                  className="p-2.5 bg-[#18181c] rounded-lg border border-zinc-800/80 hover:border-zinc-700 transition flex items-center justify-between text-xs"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-medium text-zinc-100">{ip}</span>
                      <span className="text-[10px] bg-zinc-800 text-zinc-400 px-1.5 py-0.2 rounded font-mono">
                        {data.event.clientCountry}
                      </span>
                    </div>
                    <div className="text-[11px] text-zinc-500">
                      {data.event.clientAsnName}
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="text-right">
                      <span className="font-mono font-bold text-zinc-200">{data.count}</span>
                      <span className="text-zinc-500 text-[10px] block">({pct}%)</span>
                    </div>
                    <button
                      onClick={() => onInvestigateIp(ip)}
                      className="px-2 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded text-[11px] border border-zinc-700 cursor-pointer"
                    >
                      Inspect
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Dimension 2: Top Request Paths */}
        <div className="bg-[#121215] border border-[#27272f] rounded-xl p-5">
          <div className="flex items-center justify-between mb-4 border-b border-zinc-800 pb-2.5">
            <h3 className="font-semibold text-xs tracking-wider uppercase text-zinc-200">
              Top Request Paths / Endpoints
            </h3>
            <span className="text-[11px] text-zinc-500 font-mono">URI Breakdown</span>
          </div>

          <div className="space-y-2">
            {topPaths.map(([path, data]) => {
              const pct = Math.round((data.count / Math.max(1, totalFiltered)) * 100);
              return (
                <div
                  key={path}
                  className="p-2.5 bg-[#18181c] rounded-lg border border-zinc-800/80 hover:border-zinc-700 transition flex items-center justify-between text-xs"
                >
                  <span className="font-mono text-zinc-200 truncate max-w-xs">{path}</span>

                  <div className="flex items-center gap-3">
                    <div className="text-right">
                      <span className="font-mono font-bold text-zinc-200">{data.count}</span>
                      <span className="text-zinc-500 text-[10px] block">({pct}%)</span>
                    </div>
                    <button
                      onClick={() => onProposeRuleForPath(path)}
                      className="px-2 py-1 bg-zinc-800 hover:bg-blue-600 hover:text-white text-zinc-300 rounded text-[11px] border border-zinc-700 cursor-pointer transition"
                    >
                      Rule
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Dimension 3: Geographic Distribution (Countries) */}
        <div className="bg-[#121215] border border-[#27272f] rounded-xl p-5">
          <div className="flex items-center justify-between mb-4 border-b border-zinc-800 pb-2.5">
            <h3 className="font-semibold text-xs tracking-wider uppercase text-zinc-200">
              Traffic by Origin Country
            </h3>
            <span className="text-[11px] text-zinc-500 font-mono">Geographic Distribution</span>
          </div>

          <div className="space-y-2">
            {topCountries.map(([code, data]) => {
              const pct = Math.round((data.count / Math.max(1, totalFiltered)) * 100);
              return (
                <div
                  key={code}
                  className="p-2.5 bg-[#18181c] rounded-lg border border-zinc-800/80 flex items-center justify-between text-xs"
                >
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-blue-400">{code}</span>
                    <span className="text-zinc-200 font-medium">{data.name}</span>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="w-24 bg-zinc-800 h-2 rounded-full overflow-hidden">
                      <div style={{ width: `${pct}%` }} className="bg-blue-500 h-full" />
                    </div>
                    <span className="font-mono font-bold text-zinc-200 w-12 text-right">
                      {data.count} ({pct}%)
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Dimension 4: Autonomous Systems (ASNs) */}
        <div className="bg-[#121215] border border-[#27272f] rounded-xl p-5">
          <div className="flex items-center justify-between mb-4 border-b border-zinc-800 pb-2.5">
            <h3 className="font-semibold text-xs tracking-wider uppercase text-zinc-200">
              Autonomous Systems (ASNs)
            </h3>
            <span className="text-[11px] text-zinc-500 font-mono">Routing Providers</span>
          </div>

          <div className="space-y-2">
            {topAsns.map(([asnKey, data]) => {
              const pct = Math.round((data.count / Math.max(1, totalFiltered)) * 100);
              return (
                <div
                  key={asnKey}
                  className="p-2.5 bg-[#18181c] rounded-lg border border-zinc-800/80 flex items-center justify-between text-xs"
                >
                  <span className="font-mono text-zinc-300 truncate max-w-xs">{asnKey}</span>

                  <div className="flex items-center gap-3">
                    <span className="font-mono font-bold text-zinc-200">
                      {data.count} <span className="text-zinc-500 text-[10px]">({pct}%)</span>
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Dimension 5: JA4 TLS Fingerprints */}
      <div className="bg-[#121215] border border-[#27272f] rounded-xl p-5">
        <div className="flex items-center justify-between mb-4 border-b border-zinc-800 pb-2.5">
          <div className="flex items-center gap-2">
            <Fingerprint className="w-4 h-4 text-purple-400" />
            <h3 className="font-semibold text-xs tracking-wider uppercase text-zinc-200">
              JA4 TLS Client Fingerprints (Bot & Scraper Intelligence)
            </h3>
          </div>
          <span className="text-[11px] text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/20 font-mono">
            TLS Behavioral Analysis
          </span>
        </div>

        <div className="space-y-2">
          {topJa4s.map(([ja4, count]) => (
            <div
              key={ja4}
              className="p-3 bg-[#18181c] rounded-lg border border-zinc-800/80 flex items-center justify-between text-xs"
            >
              <div className="font-mono text-purple-300 font-medium select-all">{ja4}</div>
              <div className="font-mono font-bold text-zinc-200">{count} matches</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
