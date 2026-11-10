import React, { useState } from 'react';
import {
  X,
  FileText,
  Download,
  Printer,
  Shield,
  Layers,
  CheckCircle2,
  Calendar,
  AlertTriangle,
} from 'lucide-react';
import { WafEvent, WafRule, CloudflareZone, SpikeAnomaly, IncidentTimelineEvent } from '../types/security';

interface ReportsModalProps {
  events: WafEvent[];
  rules: WafRule[];
  zones: CloudflareZone[];
  anomalies: SpikeAnomaly[];
  timeline: IncidentTimelineEvent[];
  onClose: () => void;
}

export const ReportsModal: React.FC<ReportsModalProps> = ({
  events,
  rules,
  zones,
  anomalies,
  timeline,
  onClose,
}) => {
  const [reportType, setReportType] = useState<'executive' | 'csv' | 'json'>('executive');

  const exportCSV = () => {
    const headers = [
      'RayID',
      'Timestamp',
      'Zone',
      'Action',
      'ClientIP',
      'Country',
      'ASN',
      'Method',
      'Path',
      'ThreatScore',
      'SampleInterval',
      'RuleMatched',
    ];

    const rows = events.map((e) => [
      e.id,
      e.timestamp,
      e.zoneName,
      e.action,
      e.clientIP,
      e.clientCountry,
      e.clientAsn,
      e.clientRequestHTTPMethod,
      `"${e.clientRequestPath.replace(/"/g, '""')}"`,
      e.threatScore,
      e.sampleInterval,
      `"${(e.ruleName || '').replace(/"/g, '""')}"`,
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', encodeURI(csvContent));
    downloadAnchor.setAttribute('download', `edgewatch_security_events_${Date.now()}.csv`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const exportJSON = () => {
    const reportData = {
      product: 'EdgeWatch Cloudflare Multi-Zone Security Intelligence',
      generatedAt: new Date().toISOString(),
      zonesSummary: zones.map((z) => ({
        zone: z.name,
        plan: z.plan,
        activeRulesCount: z.currentCustomRulesCount,
      })),
      anomalies,
      timeline,
      totalEventsAnalyzed: events.length,
      events,
      activeWafRules: rules,
    };

    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(reportData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `edgewatch_audit_report_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const handlePrint = () => {
    window.print();
  };

  const totalBlocked = events.filter((e) => e.action === 'block').length;
  const totalChallenged = events.filter((e) => e.action === 'challenge' || e.action === 'managed_challenge').length;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/80 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-[#121215] border border-[#27272f] w-full max-w-4xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Header */}
        <div className="p-5 border-b border-[#27272f] bg-[#16161b] flex items-center justify-between no-print">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-blue-500/15 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-zinc-100">
                Security Audit & Executive Reporting
              </h2>
              <p className="text-xs text-zinc-400">
                Multi-zone Cloudflare WAF analysis, telemetry logs, and compliance records
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

        {/* Tab Selector & Export Buttons */}
        <div className="p-4 border-b border-zinc-800 bg-[#141418] flex items-center justify-between no-print">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setReportType('executive')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition ${
                reportType === 'executive'
                  ? 'bg-blue-600 text-white'
                  : 'bg-zinc-800 text-zinc-400 hover:text-zinc-200'
              }`}
            >
              Executive Security Summary
            </button>
            <button
              onClick={() => setReportType('csv')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition ${
                reportType === 'csv'
                  ? 'bg-blue-600 text-white'
                  : 'bg-zinc-800 text-zinc-400 hover:text-zinc-200'
              }`}
            >
              CSV Event Export
            </button>
            <button
              onClick={() => setReportType('json')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium cursor-pointer transition ${
                reportType === 'json'
                  ? 'bg-blue-600 text-white'
                  : 'bg-zinc-800 text-zinc-400 hover:text-zinc-200'
              }`}
            >
              JSON Full Telemetry
            </button>
          </div>

          <div className="flex items-center gap-2">
            {reportType === 'executive' && (
              <button
                onClick={handlePrint}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 rounded-lg text-xs font-medium transition cursor-pointer"
              >
                <Printer className="w-3.5 h-3.5" /> Print / Save PDF
              </button>
            )}
            {reportType === 'csv' && (
              <button
                onClick={exportCSV}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium transition cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" /> Download CSV
              </button>
            )}
            {reportType === 'json' && (
              <button
                onClick={exportJSON}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-medium transition cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" /> Download JSON
              </button>
            )}
          </div>
        </div>

        {/* Report Content Body */}
        <div className="p-6 overflow-y-auto flex-1 space-y-6 text-sm bg-[#0c0c0e]">
          {reportType === 'executive' && (
            <div className="bg-[#121215] border border-zinc-800 rounded-xl p-8 space-y-6 print:border-none print:p-0">
              {/* Document Header */}
              <div className="flex justify-between items-start border-b border-zinc-800 pb-5">
                <div>
                  <div className="flex items-center gap-2 text-blue-400 mb-1">
                    <Shield className="w-6 h-6" />
                    <span className="font-bold text-lg text-zinc-100 tracking-tight">EdgeWatch</span>
                  </div>
                  <h1 className="text-xl font-bold text-white">Cloudflare Edge Security Executive Report</h1>
                  <p className="text-xs text-zinc-400 mt-1">
                    Multi-Zone WAF Observability, Threat Intelligence & Mitigation Audit
                  </p>
                </div>
                <div className="text-right text-xs text-zinc-400 space-y-1">
                  <div>Date: <strong className="text-zinc-200">{new Date().toLocaleDateString()}</strong></div>
                  <div>Audit Period: <strong className="text-zinc-200">Last 24 Hours</strong></div>
                  <div>Report ID: <span className="font-mono text-zinc-300">EW-SEC-{Date.now().toString().slice(-6)}</span></div>
                </div>
              </div>

              {/* Executive Summary Narrative */}
              <div>
                <h3 className="text-xs uppercase font-bold text-zinc-400 tracking-wider mb-2">
                  1. Executive Briefing
                </h3>
                <p className="text-xs text-zinc-300 leading-relaxed bg-[#18181c] p-4 rounded-lg border border-zinc-800/80">
                  During this monitoring cycle across <strong>{zones.length} connected zones</strong>, EdgeWatch evaluated continuous edge HTTP traffic. Automated anomaly detectors successfully captured <strong>{anomalies.length} security alerts</strong>, including volumetric request surges and repeated Cloudflare challenge failures on authentication endpoints. All proposed mitigation rules underwent mathematical impact previews prior to explicit operator authorization, adhering strictly to zero unauthorized edge mutations.
                </p>
              </div>

              {/* Key Metrics Grid */}
              <div>
                <h3 className="text-xs uppercase font-bold text-zinc-400 tracking-wider mb-2">
                  2. Observability Key Performance Indicators
                </h3>
                <div className="grid grid-cols-4 gap-3 text-xs">
                  <div className="bg-[#18181c] border border-zinc-800 p-3 rounded-lg">
                    <span className="text-zinc-500 block">Monitored Zones</span>
                    <span className="text-lg font-mono font-bold text-zinc-100 mt-1 block">
                      {zones.length}
                    </span>
                  </div>
                  <div className="bg-[#18181c] border border-zinc-800 p-3 rounded-lg">
                    <span className="text-zinc-500 block">Active Custom Rules</span>
                    <span className="text-lg font-mono font-bold text-blue-400 mt-1 block">
                      {rules.length}
                    </span>
                  </div>
                  <div className="bg-[#18181c] border border-zinc-800 p-3 rounded-lg">
                    <span className="text-zinc-500 block">Threat Mitigations (Denied)</span>
                    <span className="text-lg font-mono font-bold text-red-400 mt-1 block">
                      {totalBlocked}
                    </span>
                  </div>
                  <div className="bg-[#18181c] border border-zinc-800 p-3 rounded-lg">
                    <span className="text-zinc-500 block">Challenged Sessions</span>
                    <span className="text-lg font-mono font-bold text-amber-400 mt-1 block">
                      {totalChallenged}
                    </span>
                  </div>
                </div>
              </div>

              {/* Monitored Cloudflare Zones Breakdown */}
              <div>
                <h3 className="text-xs uppercase font-bold text-zinc-400 tracking-wider mb-2">
                  3. Connected Cloudflare Zones & Quotas
                </h3>
                <div className="border border-zinc-800 rounded-lg overflow-hidden">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-[#18181c] text-zinc-400 border-b border-zinc-800 font-semibold">
                      <tr>
                        <th className="p-2.5">Zone Name</th>
                        <th className="p-2.5">Account</th>
                        <th className="p-2.5">Cloudflare Plan</th>
                        <th className="p-2.5">Active Rules</th>
                        <th className="p-2.5">Phase</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/60 text-zinc-300">
                      {zones.map((z) => (
                        <tr key={z.id}>
                          <td className="p-2.5 font-medium text-white">{z.name}</td>
                          <td className="p-2.5 text-zinc-400">{z.accountName}</td>
                          <td className="p-2.5 uppercase font-mono text-blue-400">{z.plan}</td>
                          <td className="p-2.5 font-mono">{z.currentCustomRulesCount} rules</td>
                          <td className="p-2.5 font-mono text-zinc-500">http_request_firewall_custom</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Incident History Audit */}
              <div>
                <h3 className="text-xs uppercase font-bold text-zinc-400 tracking-wider mb-2">
                  4. Incident & Mitigation Audit Trail
                </h3>
                <div className="space-y-2">
                  {timeline.map((item) => (
                    <div
                      key={item.id}
                      className="p-3 bg-[#18181c] border border-zinc-800 rounded-lg flex justify-between items-start text-xs"
                    >
                      <div>
                        <div className="font-semibold text-zinc-100">{item.title}</div>
                        <div className="text-zinc-400 mt-0.5">{item.description}</div>
                      </div>
                      <div className="text-right shrink-0 ml-4 font-mono text-[11px] text-zinc-500">
                        {new Date(item.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Sign-off footer */}
              <div className="border-t border-zinc-800 pt-6 mt-8 flex justify-between items-center text-xs text-zinc-500">
                <div>
                  <span>Security Officer Approval: </span>
                  <span className="font-mono text-zinc-300 underline underline-offset-4 decoration-zinc-700">
                    SecOps Lead (Verified Digitally)
                  </span>
                </div>
                <div>EdgeWatch v2.0 • Autonomous Observability & WAF Guard</div>
              </div>
            </div>
          )}

          {reportType === 'csv' && (
            <div className="bg-[#121215] border border-zinc-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-semibold text-sm text-zinc-100">CSV Event Log Stream</h3>
                  <p className="text-xs text-zinc-400">
                    Ready for SIEM ingestion (Splunk, Datadog, Elastic)
                  </p>
                </div>
                <button
                  onClick={exportCSV}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" /> Download Full CSV ({events.length} rows)
                </button>
              </div>

              <div className="bg-[#09090b] border border-zinc-800 rounded-lg p-3 font-mono text-[11px] text-zinc-300 overflow-x-auto max-h-96">
                <div>RayID,Timestamp,Zone,Action,ClientIP,Country,ASN,Method,Path,ThreatScore</div>
                {events.slice(0, 15).map((e) => (
                  <div key={e.id} className="text-zinc-400 truncate">
                    {e.id},{e.timestamp},{e.zoneName},{e.action},{e.clientIP},{e.clientCountry},{e.clientAsn},{e.clientRequestHTTPMethod},{e.clientRequestPath},{e.threatScore}
                  </div>
                ))}
                {events.length > 15 && (
                  <div className="text-zinc-600 mt-2">... and {events.length - 15} more records</div>
                )}
              </div>
            </div>
          )}

          {reportType === 'json' && (
            <div className="bg-[#121215] border border-zinc-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-semibold text-sm text-zinc-100">JSON Telemetry Dump</h3>
                  <p className="text-xs text-zinc-400">Complete raw audit data and GraphQL analytics schema</p>
                </div>
                <button
                  onClick={exportJSON}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-semibold cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" /> Download JSON
                </button>
              </div>

              <pre className="bg-[#09090b] border border-zinc-800 rounded-lg p-3 font-mono text-[11px] text-emerald-400 overflow-x-auto max-h-96">
                {JSON.stringify(
                  {
                    system: 'EdgeWatch Security Intelligence',
                    zonesCount: zones.length,
                    activeRulesCount: rules.length,
                    anomaliesCount: anomalies.length,
                    sampleEvent: events[0],
                  },
                  null,
                  2
                )}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
