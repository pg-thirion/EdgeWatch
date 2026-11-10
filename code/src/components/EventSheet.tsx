import React from 'react';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Fingerprint,
  Globe,
  Terminal,
  FileCode,
  Search,
  PlusCircle,
  Download,
} from 'lucide-react';
import { WafEvent } from '../types/security';

interface EventSheetProps {
  event: WafEvent | null;
  onClose: () => void;
  onInvestigateIp: (ip: string) => void;
  onProposeRule: (event: WafEvent) => void;
}

export const EventSheet: React.FC<EventSheetProps> = ({
  event,
  onClose,
  onInvestigateIp,
  onProposeRule,
}) => {
  if (!event) return null;

  const downloadEventJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(event, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `edgewatch_event_${event.id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const getActionBadge = () => {
    switch (event.action) {
      case 'block':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30">
            <ShieldAlert className="w-3.5 h-3.5" /> Denied (Blocked)
          </span>
        );
      case 'challenge':
      case 'managed_challenge':
      case 'js_challenge':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3.5 h-3.5" /> Challenged
          </span>
        );
      case 'rate_limit':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-purple-500/15 text-purple-400 border border-purple-500/30">
            <Terminal className="w-3.5 h-3.5" /> Rate Limited
          </span>
        );
      case 'log':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-blue-500/15 text-blue-400 border border-blue-500/30">
            <FileCode className="w-3.5 h-3.5" /> Logged
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            <ShieldCheck className="w-3.5 h-3.5" /> Allowed
          </span>
        );
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-xs flex justify-end animate-fade-in">
      <div className="w-full max-w-xl bg-[#121215] border-l border-[#27272f] h-full shadow-2xl flex flex-col">
        {/* Header */}
        <div className="p-5 border-b border-[#27272f] flex items-center justify-between bg-[#15151a]">
          <div>
            <div className="flex items-center gap-2 mb-1">
              {getActionBadge()}
              <span className="text-xs text-zinc-400 font-mono">Ray ID: {event.id}</span>
            </div>
            <h2 className="text-base font-semibold text-zinc-100 flex items-center gap-2">
              <span>{event.clientRequestHTTPMethod}</span>
              <span className="font-mono text-zinc-300 text-sm">{event.clientRequestPath}</span>
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5 text-sm">
          {/* Quick Action Toolbar */}
          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={() => onProposeRule(event)}
              className="flex items-center justify-center gap-2 px-3 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium text-xs transition cursor-pointer shadow-sm"
            >
              <PlusCircle className="w-4 h-4" /> Propose WAF Rule
            </button>
            <button
              onClick={() => onInvestigateIp(event.clientIP)}
              className="flex items-center justify-center gap-2 px-3 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 rounded-lg font-medium text-xs transition cursor-pointer"
            >
              <Search className="w-4 h-4" /> Investigate IP
            </button>
          </div>

          {/* Client Telemetry Card */}
          <div className="bg-[#18181c] border border-zinc-800 rounded-lg p-4 space-y-3">
            <h4 className="text-xs uppercase tracking-wider font-semibold text-zinc-400 flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-blue-400" /> Client Intelligence
            </h4>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <span className="text-zinc-500 block">IP Address</span>
                <span className="font-mono text-zinc-200 font-medium">{event.clientIP}</span>
              </div>
              <div>
                <span className="text-zinc-500 block">Location</span>
                <span className="text-zinc-200 font-medium">
                  {event.clientCountryName} ({event.clientCountry})
                </span>
              </div>
              <div>
                <span className="text-zinc-500 block">Network (ASN)</span>
                <span className="font-mono text-zinc-200 font-medium">
                  {event.clientAsn} — {event.clientAsnName}
                </span>
              </div>
              <div>
                <span className="text-zinc-500 block">Cloudflare Threat Score</span>
                <span
                  className={`font-mono font-bold ${
                    event.threatScore > 50 ? 'text-red-400' : 'text-emerald-400'
                  }`}
                >
                  {event.threatScore} / 100
                </span>
              </div>
            </div>

            {/* JA4 Fingerprint */}
            <div className="pt-2 border-t border-zinc-800/80">
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="text-zinc-500 flex items-center gap-1">
                  <Fingerprint className="w-3 h-3 text-purple-400" /> JA4 TLS Fingerprint
                </span>
                <span className="text-[10px] bg-purple-500/10 text-purple-400 px-1.5 py-0.5 rounded border border-purple-500/20">
                  Bot Signature
                </span>
              </div>
              <div className="font-mono text-[11px] bg-[#121215] p-2 rounded border border-zinc-800 text-zinc-300 break-all">
                {event.ja4Fingerprint || 't13d1516h2_8daaf6152771_02711d053896'}
              </div>
            </div>

            {/* User Agent */}
            <div className="pt-2 border-t border-zinc-800/80">
              <span className="text-zinc-500 text-xs block mb-1">User Agent</span>
              <div className="font-mono text-[11px] bg-[#121215] p-2 rounded border border-zinc-800 text-zinc-300 break-all">
                {event.userAgent}
              </div>
            </div>
          </div>

          {/* Rule Match Details */}
          <div className="bg-[#18181c] border border-zinc-800 rounded-lg p-4 space-y-3">
            <h4 className="text-xs uppercase tracking-wider font-semibold text-zinc-400 flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" /> Rule Evaluation & Phase
            </h4>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-zinc-500">Execution Phase:</span>
                <span className="font-mono text-zinc-200">http_request_firewall_custom</span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-500">Triggered Rule:</span>
                <span className="font-medium text-zinc-200">{event.ruleName || 'Default WAF Evaluation'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-500">Rule ID:</span>
                <span className="font-mono text-zinc-400">{event.ruleId || 'cf_waf_adaptive_engine'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-500">Target Zone:</span>
                <span className="font-medium text-blue-400">{event.zoneName}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-zinc-500">Sample Interval:</span>
                <span className="font-mono text-zinc-300">
                  {event.sampleInterval > 1 ? `1 in ${event.sampleInterval} (Adaptive Sampling)` : 'Unsampled (1:1)'}
                </span>
              </div>
            </div>
          </div>

          {/* HTTP Request Headers */}
          <div className="bg-[#18181c] border border-zinc-800 rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-xs uppercase tracking-wider font-semibold text-zinc-400 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-emerald-400" /> HTTP Headers
              </h4>
              <span className="text-[10px] text-zinc-500 font-mono">
                {event.clientRequestHTTPProtocol}
              </span>
            </div>

            <div className="bg-[#121215] rounded border border-zinc-800 p-2 text-xs font-mono space-y-1 max-h-40 overflow-y-auto">
              {Object.entries(event.clientRequestHeaders || {}).map(([key, val]) => (
                <div key={key} className="flex gap-2">
                  <span className="text-zinc-400 select-all">{key}:</span>
                  <span className="text-zinc-200 select-all break-all">{val}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-[#27272f] bg-[#15151a] flex items-center justify-between">
          <button
            onClick={downloadEventJson}
            className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-white transition cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" /> Download Event JSON
          </button>
          <span className="text-xs text-zinc-500 font-mono">
            {new Date(event.timestamp).toLocaleString()}
          </span>
        </div>
      </div>
    </div>
  );
};
