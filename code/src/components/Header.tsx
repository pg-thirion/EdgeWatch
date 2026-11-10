import React from 'react';
import {
  Shield,
  Layers,
  Zap,
  Download,
  Key,
  Activity,
  Play,
  Pause,
  ChevronDown,
} from 'lucide-react';
import { CloudflareAccount, CloudflareZone } from '../types/security';

interface HeaderProps {
  accounts: CloudflareAccount[];
  zones: CloudflareZone[];
  selectedZoneId: string;
  onSelectZoneId: (zoneId: string) => void;
  activeTab: 'overview' | 'traffic' | 'timeline';
  onSelectTab: (tab: 'overview' | 'traffic' | 'timeline') => void;
  isLiveStreaming: boolean;
  onToggleLiveStream: () => void;
  onOpenDemoAttacks: () => void;
  onOpenReports: () => void;
  onOpenAccountSettings: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  accounts,
  zones,
  selectedZoneId,
  onSelectZoneId,
  activeTab,
  onSelectTab,
  isLiveStreaming,
  onToggleLiveStream,
  onOpenDemoAttacks,
  onOpenReports,
  onOpenAccountSettings,
}) => {
  const selectedZone = zones.find((z) => z.id === selectedZoneId) || zones[0];
  const activeAccount = accounts.find((a) => a.id === selectedZone?.accountId) || accounts[0];

  return (
    <header className="border-b border-[#27272f] bg-[#0c0c0e]/95 sticky top-0 z-40 backdrop-blur-md">
      {/* Top Banner & Account Selector */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Zone Selector */}
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
                <Shield className="w-5 h-5" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="font-bold text-base tracking-tight text-white">EdgeWatch</span>
                <span className="text-[10px] text-zinc-500 uppercase font-mono tracking-wider">
                  Cloudflare Observability
                </span>
              </div>
            </div>

            <div className="h-5 w-[1px] bg-zinc-800 hidden sm:block" />

            {/* Cloudflare Zone Picker */}
            <div className="relative flex items-center gap-2">
              <span className="text-xs text-zinc-500 hidden md:inline">Zone:</span>
              <div className="relative">
                <select
                  id="zone-selector"
                  value={selectedZoneId}
                  onChange={(e) => onSelectZoneId(e.target.value)}
                  className="bg-[#18181c] border border-zinc-700/80 text-zinc-100 rounded-lg pl-3 pr-8 py-1.5 text-xs font-medium cursor-pointer focus:ring-1 focus:ring-blue-500 outline-none appearance-none"
                >
                  {zones.map((z) => (
                    <option key={z.id} value={z.id}>
                      {z.name} ({z.plan.toUpperCase()})
                    </option>
                  ))}
                </select>
                <ChevronDown className="w-3.5 h-3.5 text-zinc-400 absolute right-2.5 top-2.5 pointer-events-none" />
              </div>

              {/* Plan Badge */}
              <span
                className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold border ${
                  selectedZone.plan === 'free'
                    ? 'bg-zinc-800 text-zinc-300 border-zinc-700'
                    : selectedZone.plan === 'pro'
                    ? 'bg-blue-500/15 text-blue-400 border-blue-500/30'
                    : selectedZone.plan === 'business'
                    ? 'bg-purple-500/15 text-purple-400 border-purple-500/30'
                    : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                }`}
              >
                {selectedZone.plan}
              </span>
            </div>
          </div>

          {/* Header Action Tools */}
          <div className="flex items-center gap-2.5">
            {/* Live stream ticker toggle */}
            <button
              onClick={onToggleLiveStream}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer border ${
                isLiveStreaming
                  ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30 shadow-[0_0_10px_rgba(16,185,129,0.2)]'
                  : 'bg-zinc-800 text-zinc-400 border-zinc-700 hover:text-white'
              }`}
            >
              {isLiveStreaming ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                  <span>Streaming Live</span>
                </>
              ) : (
                <>
                  <Play className="w-3 h-3" />
                  <span>Resume Live</span>
                </>
              )}
            </button>

            {/* Demo Attack Trigger */}
            <button
              id="btn-demo-attacks-modal"
              onClick={onOpenDemoAttacks}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-red-600/20 hover:bg-red-600/30 text-red-300 border border-red-500/40 rounded-lg text-xs font-medium transition cursor-pointer shadow-sm"
            >
              <Zap className="w-3.5 h-3.5 text-red-400" />
              <span>Demo Attacks</span>
            </button>

            {/* Download Reports */}
            <button
              onClick={onOpenReports}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 rounded-lg text-xs font-medium transition cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-zinc-400" />
              <span className="hidden sm:inline">Reports</span>
            </button>

            {/* Account & Token settings */}
            <button
              onClick={onOpenAccountSettings}
              className="p-1.5 text-zinc-400 hover:text-white hover:bg-zinc-800 rounded-lg border border-zinc-800 transition cursor-pointer"
              title="Cloudflare Credentials & Accounts"
            >
              <Key className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab Navigation Row (Matching Vercel Firewall Observability) */}
        <div className="flex items-center gap-6 border-t border-[#1e1e24] -mb-[1px]">
          <button
            id="tab-btn-overview"
            onClick={() => onSelectTab('overview')}
            className={`py-3 text-xs font-medium border-b-2 transition flex items-center gap-1.5 cursor-pointer ${
              activeTab === 'overview'
                ? 'border-blue-500 text-white font-semibold'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <span>Overview</span>
          </button>
          <button
            id="tab-btn-traffic"
            onClick={() => onSelectTab('traffic')}
            className={`py-3 text-xs font-medium border-b-2 transition flex items-center gap-1.5 cursor-pointer ${
              activeTab === 'traffic'
                ? 'border-blue-500 text-white font-semibold'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <span>Traffic</span>
          </button>
          <button
            id="tab-btn-timeline"
            onClick={() => onSelectTab('timeline')}
            className={`py-3 text-xs font-medium border-b-2 transition flex items-center gap-1.5 cursor-pointer ${
              activeTab === 'timeline'
                ? 'border-blue-500 text-white font-semibold'
                : 'border-transparent text-zinc-400 hover:text-zinc-200'
            }`}
          >
            <span>Incident Timeline</span>
          </button>
        </div>
      </div>
    </header>
  );
};
