import React, { useState } from 'react';
import {
  X,
  Zap,
  ShieldAlert,
  Play,
  RotateCcw,
  CheckCircle2,
  Server,
  Crosshair,
} from 'lucide-react';
import { DemoAttackScenario, CloudflareZone } from '../types/security';
import { DEMO_SCENARIOS } from '../data/mockCloudflareData';

interface DemoAttacksModalProps {
  zones: CloudflareZone[];
  onTriggerAttack: (scenario: DemoAttackScenario, targetZone: CloudflareZone) => void;
  onResetSimulation: () => void;
  onClose: () => void;
}

export const DemoAttacksModal: React.FC<DemoAttacksModalProps> = ({
  zones,
  onTriggerAttack,
  onResetSimulation,
  onClose,
}) => {
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>(DEMO_SCENARIOS[0].id);
  const [selectedZoneId, setSelectedZoneId] = useState<string>(zones[0].id);
  const [activeMessage, setActiveMessage] = useState<string>('');

  const selectedScenario =
    DEMO_SCENARIOS.find((s) => s.id === selectedScenarioId) || DEMO_SCENARIOS[0];
  const selectedZone = zones.find((z) => z.id === selectedZoneId) || zones[0];

  const handleLaunch = () => {
    onTriggerAttack(selectedScenario, selectedZone);
    setActiveMessage(`Simulated ${selectedScenario.name} injected into ${selectedZone.name}!`);
    setTimeout(() => {
      setActiveMessage('');
      onClose();
    }, 1200);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-[#121215] border border-[#27272f] w-full max-w-2xl rounded-xl shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-5 border-b border-[#27272f] bg-[#16161b] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-red-500/15 border border-red-500/30 flex items-center justify-center text-red-400">
              <Zap className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-zinc-100">
                Realistic Demo Attack Simulation Suite
              </h2>
              <p className="text-xs text-zinc-400">
                Exercise detection, investigation, rule preview, and approval workflows
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

        {/* Content */}
        <div className="p-6 space-y-5 text-sm">
          {/* Target Zone Selection */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-zinc-300 uppercase tracking-wider block">
              1. Target Cloudflare Zone
            </label>
            <select
              value={selectedZoneId}
              onChange={(e) => setSelectedZoneId(e.target.value)}
              className="w-full bg-[#18181c] border border-zinc-700 text-zinc-100 rounded-lg p-2.5 text-xs outline-none focus:ring-1 focus:ring-blue-500"
            >
              {zones.map((z) => (
                <option key={z.id} value={z.id}>
                  {z.name} ({z.plan.toUpperCase()} Plan — {z.accountName})
                </option>
              ))}
            </select>
          </div>

          {/* Scenario Cards */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-zinc-300 uppercase tracking-wider block">
              2. Select Threat Vector Scenario
            </label>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {DEMO_SCENARIOS.map((scen) => {
                const isSelected = scen.id === selectedScenarioId;
                return (
                  <div
                    key={scen.id}
                    onClick={() => setSelectedScenarioId(scen.id)}
                    className={`p-3.5 rounded-xl border cursor-pointer transition flex flex-col justify-between ${
                      isSelected
                        ? 'bg-blue-950/20 border-blue-500 ring-1 ring-blue-500'
                        : 'bg-[#18181c] border-zinc-800 hover:border-zinc-700'
                    }`}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-xs font-semibold text-zinc-100">{scen.name}</span>
                        <span className="text-[10px] bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded font-mono">
                          {scen.category}
                        </span>
                      </div>
                      <p className="text-xs text-zinc-400 leading-relaxed mb-3">
                        {scen.description}
                      </p>
                    </div>

                    <div className="text-[11px] font-mono text-zinc-500 pt-2 border-t border-zinc-800/80 flex items-center justify-between">
                      <span>Rate: ~{scen.simulatedReqPerSec} req/s</span>
                      <span className="text-blue-400">Target: {scen.targetPath}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Scenario Details Preview */}
          <div className="bg-[#16161b] border border-zinc-800 rounded-lg p-3.5 space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-zinc-400 font-medium">Recommended Mitigation Rule:</span>
              <span className="font-mono text-amber-400 uppercase">
                Action: {selectedScenario.recommendedAction}
              </span>
            </div>
            <div className="font-mono text-[11px] bg-[#0f0f13] p-2 rounded border border-zinc-800 text-zinc-300 break-all select-all">
              {selectedScenario.recommendedExpression}
            </div>
          </div>

          {activeMessage && (
            <div className="p-3 bg-emerald-500/20 border border-emerald-500/40 rounded-lg text-emerald-300 text-xs flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4" />
              <span>{activeMessage}</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-[#27272f] bg-[#16161b] flex items-center justify-between">
          <button
            type="button"
            onClick={onResetSimulation}
            className="flex items-center gap-1.5 px-3 py-2 text-xs text-zinc-400 hover:text-white transition cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" /> Reset Telemetry Baseline
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-2 text-xs text-zinc-400 hover:text-white transition cursor-pointer"
            >
              Cancel
            </button>
            <button
              id="btn-launch-demo-attack"
              type="button"
              onClick={handleLaunch}
              className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-semibold flex items-center gap-2 transition cursor-pointer shadow-sm"
            >
              <Zap className="w-4 h-4" /> Inject Simulation Attack
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
