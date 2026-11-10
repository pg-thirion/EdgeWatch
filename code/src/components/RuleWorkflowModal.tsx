import React, { useState } from 'react';
import {
  X,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  Play,
  Layers,
  Lock,
  Info,
  Check,
} from 'lucide-react';
import {
  WafEvent,
  WafRule,
  CloudflareZone,
  WafAction,
  RulePreviewEstimate,
  PLAN_LIMITS,
} from '../types/security';
import { previewRuleImpact } from '../services/rulePreviewEngine';

interface RuleWorkflowModalProps {
  initialEvent?: WafEvent | null;
  zones: CloudflareZone[];
  historicalEvents: WafEvent[];
  onClose: () => void;
  onApplyRule: (rule: Omit<WafRule, 'id' | 'createdAt' | 'updatedAt' | 'matchedCount24h'>) => void;
}

export const RuleWorkflowModal: React.FC<RuleWorkflowModalProps> = ({
  initialEvent,
  zones,
  historicalEvents,
  onClose,
  onApplyRule,
}) => {
  const defaultZone = initialEvent
    ? zones.find((z) => z.id === initialEvent.zoneId) || zones[0]
    : zones[0];

  const [selectedZoneId, setSelectedZoneId] = useState<string>(defaultZone.id);
  const selectedZone = zones.find((z) => z.id === selectedZoneId) || zones[0];

  const defaultExpr = initialEvent
    ? `(http.request.uri.path contains "${initialEvent.clientRequestPath}" and ip.src in {${initialEvent.clientIP}})`
    : '(http.request.uri.path contains "/api/v1/auth" and cf.threat_score gt 40)';

  const [ruleName, setRuleName] = useState<string>(
    initialEvent
      ? `Mitigate Suspicious Traffic on ${initialEvent.clientRequestPath}`
      : 'Block Suspicious High Threat Request Patterns'
  );
  const [description] = useState<string>(
    initialEvent
      ? `Automated mitigation proposed from incident on IP ${initialEvent.clientIP}`
      : 'Block high threat requests hitting sensitive endpoints'
  );
  const [expression, setExpression] = useState<string>(defaultExpr);
  const [action, setAction] = useState<WafAction>('block');

  // Preview state
  const [previewResult, setPreviewResult] = useState<RulePreviewEstimate | null>(null);
  const [isPreviewing, setIsPreviewing] = useState<boolean>(false);

  // Approval gate state: Explicit two-factor gate
  const [hasUserApproved, setHasUserApproved] = useState<boolean>(false);
  const [appliedSuccess, setAppliedSuccess] = useState<boolean>(false);

  const handleRunPreview = () => {
    setIsPreviewing(true);
    // Reset approval on preview re-run to maintain strict safety contract
    setHasUserApproved(false);

    setTimeout(() => {
      const estimate = previewRuleImpact(
        expression,
        action,
        selectedZone,
        historicalEvents,
        24
      );
      setPreviewResult(estimate);
      setIsPreviewing(false);
    }, 250);
  };

  const handleApply = () => {
    if (!hasUserApproved || !previewResult || previewResult.planLimitExceeded) {
      return;
    }

    onApplyRule({
      zoneId: selectedZone.id,
      name: ruleName,
      description,
      expression,
      action,
      enabled: true,
      phase: 'http_request_firewall_custom',
    });

    setAppliedSuccess(true);
    setTimeout(() => {
      onClose();
    }, 1500);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-[#121215] border border-[#27272f] w-full max-w-3xl rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Modal Header */}
        <div className="p-5 border-b border-[#27272f] bg-[#16161b] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-blue-500/15 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-zinc-100">
                WAF Rule Proposal & Impact Preview Workflow
              </h2>
              <p className="text-xs text-zinc-400">
                Phase: <span className="font-mono text-zinc-300">http_request_firewall_custom</span> • Cloudflare Ruleset Engine
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

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-sm">
          {/* Step 1: Target Zone & Plan Limits */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-zinc-300 uppercase tracking-wider">
                1. Target Cloudflare Zone & Plan Quota
              </label>
              <span className="text-xs text-zinc-400">
                Plan: <strong className="uppercase text-blue-400">{selectedZone.plan}</strong>
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <select
                value={selectedZoneId}
                onChange={(e) => {
                  setSelectedZoneId(e.target.value);
                  setPreviewResult(null);
                  setHasUserApproved(false);
                }}
                className="bg-[#18181c] border border-zinc-700 text-zinc-100 rounded-lg p-2.5 text-xs focus:ring-1 focus:ring-blue-500 outline-none"
              >
                {zones.map((z) => (
                  <option key={z.id} value={z.id}>
                    {z.name} ({z.plan.toUpperCase()} Plan — {z.accountName})
                  </option>
                ))}
              </select>

              {/* Plan Limits Indicator Bar */}
              <div className="bg-[#18181c] border border-zinc-800 rounded-lg p-2.5 flex items-center justify-between text-xs">
                <span className="text-zinc-400">Custom WAF Rules Quota:</span>
                <span className="font-mono font-medium text-zinc-200">
                  {selectedZone.currentCustomRulesCount} /{' '}
                  {PLAN_LIMITS[selectedZone.plan].maxCustomRules} rules used
                </span>
              </div>
            </div>

            {selectedZone.currentCustomRulesCount >= PLAN_LIMITS[selectedZone.plan].maxCustomRules ? (
              <div className="flex items-center gap-2 p-2.5 bg-red-500/10 border border-red-500/30 rounded-lg text-red-300 text-xs">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>
                  <strong>Plan Quota Exceeded:</strong> {selectedZone.plan.toUpperCase()} plan allows maximum {PLAN_LIMITS[selectedZone.plan].maxCustomRules} custom rules.
                </span>
              </div>
            ) : selectedZone.currentCustomRulesCount >= PLAN_LIMITS[selectedZone.plan].maxCustomRules - 1 ? (
              <div className="flex items-center gap-2 p-2.5 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-300 text-xs">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>
                  <strong>Near Plan Quota:</strong> {selectedZone.plan.toUpperCase()} plan allows maximum {PLAN_LIMITS[selectedZone.plan].maxCustomRules} custom rules. Only 1 rule slot remains.
                </span>
              </div>
            ) : null}
          </div>

          {/* Step 2: Rule Metadata & Expression */}
          <div className="space-y-3">
            <label className="text-xs font-semibold text-zinc-300 uppercase tracking-wider block">
              2. Rule Definition & Wirefilter Expression
            </label>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <span className="text-[11px] text-zinc-400 block mb-1">Rule Name</span>
                <input
                  type="text"
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  className="w-full bg-[#18181c] border border-zinc-700 text-zinc-100 rounded-lg p-2 text-xs focus:ring-1 focus:ring-blue-500 outline-none"
                  placeholder="e.g. Block Credential Stuffing on Login"
                />
              </div>

              <div>
                <span className="text-[11px] text-zinc-400 block mb-1">Enforcement Action</span>
                <select
                  value={action}
                  onChange={(e) => {
                    setAction(e.target.value as WafAction);
                    setPreviewResult(null);
                    setHasUserApproved(false);
                  }}
                  className="w-full bg-[#18181c] border border-zinc-700 text-zinc-100 rounded-lg p-2 text-xs focus:ring-1 focus:ring-blue-500 outline-none font-medium"
                >
                  <option value="block">Block (Deny Request HTTP 403)</option>
                  <option value="managed_challenge">Managed Challenge (Interactive Cloudflare Turnstile)</option>
                  <option value="js_challenge">JavaScript Challenge (Non-interactive)</option>
                  <option value="log">Log (Simulate & Observe Traffic Only)</option>
                </select>
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <span className="text-[11px] text-zinc-400">Wirefilter Expression</span>
                <div className="flex gap-1.5">
                  <button
                    type="button"
                    onClick={() =>
                      setExpression('(http.request.uri.path contains "/api/v1/auth" and cf.threat_score gt 40)')
                    }
                    className="text-[10px] text-blue-400 hover:underline cursor-pointer"
                  >
                    + Auth Threat
                  </button>
                  <span className="text-zinc-600">|</span>
                  <button
                    type="button"
                    onClick={() =>
                      setExpression('(ip.geoip.country in {"RU" "CN"} and http.request.method eq "POST")')
                    }
                    className="text-[10px] text-blue-400 hover:underline cursor-pointer"
                  >
                    + Geo Filter
                  </button>
                </div>
              </div>
              <textarea
                rows={2}
                value={expression}
                onChange={(e) => {
                  setExpression(e.target.value);
                  setPreviewResult(null);
                  setHasUserApproved(false);
                }}
                className="w-full bg-[#0d0d10] font-mono border border-zinc-700 text-zinc-200 rounded-lg p-2.5 text-xs focus:ring-1 focus:ring-blue-500 outline-none"
              />
            </div>
          </div>

          {/* Step 3: Preview Button */}
          <div className="pt-2 border-t border-zinc-800">
            <button
              id="btn-preview-impact"
              type="button"
              onClick={handleRunPreview}
              disabled={isPreviewing}
              className="w-full py-2.5 px-4 bg-zinc-800 hover:bg-zinc-700 text-zinc-100 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 border border-zinc-600 transition cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 text-blue-400" />
              {isPreviewing ? 'Evaluating against historical traffic...' : 'Preview Estimated Effects (Dry Run)'}
            </button>
          </div>

          {/* Preview Results & Uncertainty Disclosure */}
          {previewResult && (
            <div className="bg-[#16161c] border border-blue-500/30 rounded-xl p-4 space-y-4 animate-fade-in">
              <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-blue-400" />
                  <h4 className="font-semibold text-xs text-zinc-100 uppercase tracking-wide">
                    Estimated 24-Hour Rule Impact Preview
                  </h4>
                </div>
                {previewResult.isSampled ? (
                  <span className="text-[11px] bg-amber-500/10 text-amber-400 border border-amber-500/30 px-2 py-0.5 rounded font-mono flex items-center gap-1">
                    <Layers className="w-3 h-3" /> Sampled Data (1:{previewResult.sampleInterval})
                  </span>
                ) : (
                  <span className="text-[11px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded font-mono">
                    Unsampled (Exact 1:1)
                  </span>
                )}
              </div>

              {/* Metric Cards */}
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-[#121215] border border-zinc-800 rounded-lg p-3">
                  <span className="text-zinc-400 text-xs block">Estimated Blocked Requests</span>
                  <div className="text-xl font-bold font-mono text-zinc-100 mt-1">
                    {previewResult.estimatedAffectedRequests.toLocaleString()}
                  </div>
                  {previewResult.isSampled && (
                    <div className="text-[10px] text-amber-400/90 font-mono mt-0.5">
                      95% CI: [{previewResult.confidenceIntervalMin.toLocaleString()} – {previewResult.confidenceIntervalMax.toLocaleString()}] (±{previewResult.uncertaintyPercentage}%)
                    </div>
                  )}
                </div>

                <div className="bg-[#121215] border border-zinc-800 rounded-lg p-3">
                  <span className="text-zinc-400 text-xs block">False Positive Risk</span>
                  <div
                    className={`text-xl font-bold font-mono mt-1 ${
                      previewResult.falsePositiveRisk === 'Low'
                        ? 'text-emerald-400'
                        : previewResult.falsePositiveRisk === 'Moderate'
                        ? 'text-amber-400'
                        : 'text-red-400'
                    }`}
                  >
                    {previewResult.falsePositiveRisk}
                  </div>
                  <div className="text-[10px] text-zinc-500 font-mono mt-0.5">
                    Est. clean users affected: {previewResult.estimatedBlockedLegitimateUsers}
                  </div>
                </div>

                <div className="bg-[#121215] border border-zinc-800 rounded-lg p-3">
                  <span className="text-zinc-400 text-xs block">Remaining Rule Quota</span>
                  <div className="text-xl font-bold font-mono text-zinc-100 mt-1">
                    {previewResult.remainingRuleSlots} / {previewResult.maxRulesAllowed}
                  </div>
                  <div className="text-[10px] text-zinc-500 font-mono mt-0.5">
                    Phase: custom WAF
                  </div>
                </div>
              </div>

              {/* Sampled Data Uncertainty Warning */}
              {previewResult.isSampled && (
                <div className="flex items-start gap-2 p-2.5 bg-zinc-900 border border-zinc-700/80 rounded-lg text-zinc-300 text-xs">
                  <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                  <p>
                    <strong>Sampling Disclosure:</strong> This zone operates on a {selectedZone.plan.toUpperCase()} plan with 1:{previewResult.sampleInterval} adaptive sampling. Projected request counts have statistical variance of ±{previewResult.uncertaintyPercentage}%.
                  </p>
                </div>
              )}

              {/* Breakdown of Affected Endpoints */}
              {previewResult.topAffectedPaths.length > 0 && (
                <div>
                  <span className="text-xs text-zinc-400 font-medium block mb-1.5">
                    Top Affected Endpoints:
                  </span>
                  <div className="bg-[#121215] border border-zinc-800 rounded-lg p-2 space-y-1 text-xs font-mono">
                    {previewResult.topAffectedPaths.map((item) => (
                      <div key={item.path} className="flex justify-between text-zinc-300">
                        <span>{item.path}</span>
                        <span className="text-blue-400 font-medium">~{item.count.toLocaleString()} reqs</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* CRITICAL SAFETY APPROVAL CHECKBOX */}
              <div className="pt-3 border-t border-zinc-800">
                <label className="flex items-start gap-2.5 cursor-pointer select-none">
                  <input
                    id="chk-explicit-approval"
                    type="checkbox"
                    checked={hasUserApproved}
                    onChange={(e) => setHasUserApproved(e.target.checked)}
                    className="mt-0.5 rounded border-zinc-700 text-blue-600 focus:ring-blue-500 w-4 h-4 bg-zinc-800 cursor-pointer"
                  />
                  <div className="text-xs text-zinc-200">
                    <strong className="text-white block">
                      Explicit Operator Approval Required
                    </strong>
                    <span>
                      I have reviewed the previewed impact (~{previewResult.estimatedAffectedRequests.toLocaleString()} requests, {previewResult.falsePositiveRisk} false positive risk) and explicitly authorize deployment to Cloudflare zone{' '}
                      <span className="text-blue-400 font-medium">{selectedZone.name}</span>.
                    </span>
                  </div>
                </label>
              </div>
            </div>
          )}

          {/* Success Notification */}
          {appliedSuccess && (
            <div className="p-3 bg-emerald-500/20 border border-emerald-500/50 rounded-lg text-emerald-300 text-xs flex items-center gap-2">
              <Check className="w-4 h-4" />
              <span>Rule successfully verified and deployed to Cloudflare zone {selectedZone.name}!</span>
            </div>
          )}
        </div>

        {/* Modal Footer with Strict Gate */}
        <div className="p-4 border-t border-[#27272f] bg-[#16161b] flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-xs text-zinc-400">
            <Lock className="w-3.5 h-3.5 text-zinc-500" />
            <span>Preview cannot apply rules without explicit approval</span>
          </div>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs text-zinc-400 hover:text-white transition cursor-pointer"
            >
              Cancel
            </button>

            {/* STRICTLY GATED APPLY BUTTON: Disabled until Preview is run AND checkbox is checked AND quota not exceeded! */}
            <button
              id="btn-apply-waf-rule"
              type="button"
              onClick={handleApply}
              disabled={!hasUserApproved || !previewResult || appliedSuccess || previewResult.planLimitExceeded}
              className={`px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition ${
                hasUserApproved && previewResult && !appliedSuccess && !previewResult.planLimitExceeded
                  ? 'bg-blue-600 hover:bg-blue-500 text-white cursor-pointer shadow-md'
                  : 'bg-zinc-800 text-zinc-500 border border-zinc-700 cursor-not-allowed'
              }`}
            >
              <CheckCircle2 className="w-4 h-4" />
              Apply Rule to Cloudflare WAF
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
