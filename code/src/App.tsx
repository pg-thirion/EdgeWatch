import React, { useState, useEffect, useMemo } from 'react';
import {
  CloudflareAccount,
  CloudflareZone,
  WafRule,
  WafEvent,
  SpikeAnomaly,
  TrafficDataPoint,
  DemoAttackScenario,
  IncidentTimelineEvent,
} from './types/security';
import {
  INITIAL_ACCOUNTS,
  INITIAL_ZONES,
  INITIAL_RULES,
  INITIAL_ANOMALIES,
  INITIAL_TIMELINE,
  generateInitialEvents,
} from './data/mockCloudflareData';
import { createAttackEvents, generateLiveTrafficTick } from './services/attackSimulator';
import { Header } from './components/Header';
import { OverviewTab } from './components/OverviewTab';
import { TrafficTab } from './components/TrafficTab';
import { IncidentTimeline } from './components/IncidentTimeline';
import { EventSheet } from './components/EventSheet';
import { RuleWorkflowModal } from './components/RuleWorkflowModal';
import { IpInvestigationModal } from './components/IpInvestigationModal';
import { DemoAttacksModal } from './components/DemoAttacksModal';
import { ReportsModal } from './components/ReportsModal';
import { AccountSettingsModal } from './components/AccountSettingsModal';

export const App: React.FC = () => {
  // Core state
  const [accounts, setAccounts] = useState<CloudflareAccount[]>(INITIAL_ACCOUNTS);
  const [zones, setZones] = useState<CloudflareZone[]>(INITIAL_ZONES);
  const [rules, setRules] = useState<WafRule[]>(INITIAL_RULES);
  const [events, setEvents] = useState<WafEvent[]>(generateInitialEvents);
  const [anomalies, setAnomalies] = useState<SpikeAnomaly[]>(INITIAL_ANOMALIES);
  const [timeline, setTimeline] = useState<IncidentTimelineEvent[]>(INITIAL_TIMELINE);

  // Active navigation & filters
  const [selectedZoneId, setSelectedZoneId] = useState<string>(INITIAL_ZONES[0].id);
  const [activeTab, setActiveTab] = useState<'overview' | 'traffic' | 'timeline'>('overview');
  const [selectedRange, setSelectedRange] = useState<string>('24h');
  const [selectedCountry, setSelectedCountry] = useState<string | null>(null);

  // Modals & Drawers state
  const [inspectedEvent, setInspectedEvent] = useState<WafEvent | null>(null);
  const [investigatingIp, setInvestigatingIp] = useState<string | null>(null);
  const [ruleWorkflowEvent, setRuleWorkflowEvent] = useState<WafEvent | null>(null);
  const [isRuleWorkflowOpen, setIsRuleWorkflowOpen] = useState<boolean>(false);
  const [isDemoAttacksOpen, setIsDemoAttacksOpen] = useState<boolean>(false);
  const [isReportsOpen, setIsReportsOpen] = useState<boolean>(false);
  const [isAccountSettingsOpen, setIsAccountSettingsOpen] = useState<boolean>(false);

  // Live streaming ticker
  const [isLiveStreaming, setIsLiveStreaming] = useState<boolean>(true);

  const selectedZone = zones.find((z) => z.id === selectedZoneId) || zones[0];

  // URL query parameter synchronization (allows direct deep-linking e.g. /?tab=traffic, /?inspect=evt_1)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const tabParam = params.get('tab');
    if (tabParam === 'traffic' || tabParam === 'overview' || tabParam === 'timeline') {
      setActiveTab(tabParam);
    }
    const inspectParam = params.get('inspect');
    if (inspectParam) {
      const match = events.find((e) => e.id === inspectParam) || events[0];
      setInspectedEvent(match);
    }
  }, []);

  // Periodic simulated live edge traffic
  useEffect(() => {
    if (!isLiveStreaming) return;
    const interval = setInterval(() => {
      const newEvt = generateLiveTrafficTick(selectedZone.name, selectedZone.id);
      setEvents((prev) => [newEvt, ...prev.slice(0, 150)]);
    }, 3000);
    return () => clearInterval(interval);
  }, [isLiveStreaming, selectedZone]);

  // Aggregate time-series chart data points from current events
  const trafficChartData: TrafficDataPoint[] = useMemo(() => {
    const points: TrafficDataPoint[] = [];
    const now = Date.now();
    const intervalsCount = 14;
    const stepMs = (24 * 3600 * 1000) / intervalsCount;

    for (let i = intervalsCount - 1; i >= 0; i--) {
      const time = new Date(now - i * stepMs);
      const hours = time.getHours().toString().padStart(2, '0');
      const mins = time.getMinutes().toString().padStart(2, '0');
      const label = `${hours}:${mins}`;

      // Calculate synthetic request distribution based on events
      const baseReq = 120 + Math.floor(Math.sin(i * 0.8) * 45) + (i === intervalsCount - 2 ? 380 : 0);
      const isSpike = i === intervalsCount - 2;

      points.push({
        timestamp: time.toISOString(),
        timeLabel: label,
        total: baseReq,
        allowed: Math.round(baseReq * 0.55),
        denied: isSpike ? Math.round(baseReq * 0.3) : Math.round(baseReq * 0.15),
        challenged: isSpike ? Math.round(baseReq * 0.25) : Math.round(baseReq * 0.15),
        logged: Math.round(baseReq * 0.08),
        rateLimited: isSpike ? Math.round(baseReq * 0.12) : Math.round(baseReq * 0.07),
        isSpike,
      });
    }
    return points;
  }, [events]);

  // Actions
  const handleOpenProposeRule = (event?: WafEvent) => {
    setRuleWorkflowEvent(event || null);
    setIsRuleWorkflowOpen(true);
  };

  const handleApplyRule = (
    ruleData: Omit<WafRule, 'id' | 'createdAt' | 'updatedAt' | 'matchedCount24h'>
  ) => {
    const newRule: WafRule = {
      ...ruleData,
      id: `rule_applied_${Date.now()}`,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      matchedCount24h: 0,
    };

    setRules((prev) => [newRule, ...prev]);

    // Update target zone count
    setZones((prev) =>
      prev.map((z) =>
        z.id === ruleData.zoneId
          ? { ...z, currentCustomRulesCount: z.currentCustomRulesCount + 1 }
          : z
      )
    );

    // Record in incident timeline
    const tlEvent: IncidentTimelineEvent = {
      id: `tl_approved_${Date.now()}`,
      timestamp: new Date().toISOString(),
      phase: 'rule_approved',
      title: `Rule Deployed: ${ruleData.name}`,
      description: `Operator explicitly authorized rule deployment to Cloudflare zone (${ruleData.expression}). Enforcement action: ${ruleData.action}.`,
      actor: 'SecOps Analyst (Explicit Approval)',
      metadata: {
        phase: 'http_request_firewall_custom',
        action: ruleData.action,
        zoneId: ruleData.zoneId,
      },
    };
    setTimeline((prev) => [tlEvent, ...prev]);

    // Mark corresponding anomaly mitigated
    setAnomalies((prev) =>
      prev.map((a) =>
        a.zoneId === ruleData.zoneId && a.status === 'active'
          ? { ...a, status: 'mitigated' }
          : a
      )
    );
  };

  const handleTriggerAttack = (scenario: DemoAttackScenario, targetZone: CloudflareZone) => {
    const { events: attackEvts, anomaly, timelineEvent } = createAttackEvents(
      scenario,
      targetZone.id,
      targetZone.name
    );

    setEvents((prev) => [...attackEvts, ...prev]);
    setAnomalies((prev) => [anomaly, ...prev]);
    setTimeline((prev) => [timelineEvent, ...prev]);
  };

  const handleResetSimulation = () => {
    setEvents(generateInitialEvents());
    setAnomalies(INITIAL_ANOMALIES);
    setTimeline(INITIAL_TIMELINE);
  };

  const handleAddAccount = (name: string, token: string) => {
    const newAcc: CloudflareAccount = {
      id: `cf_acc_${Date.now()}`,
      name,
      maskedToken: `cf_tok_••••••••••••${token.slice(-4)}`,
      encryptedTokenHash: `sha256:${Math.random().toString(16).substring(2, 18)}`,
      status: 'connected',
      permissions: ['Zone.WAF:Edit', 'Zone.Analytics:Read'],
      zonesCount: 1,
    };
    setAccounts((prev) => [...prev, newAcc]);
  };

  const handleDeleteAccount = (id: string) => {
    setAccounts((prev) => prev.filter((a) => a.id !== id));
  };

  return (
    <div className="min-h-screen bg-[#09090b] text-zinc-100 flex flex-col font-sans selection:bg-blue-600 selection:text-white">
      {/* Navigation Header */}
      <Header
        accounts={accounts}
        zones={zones}
        selectedZoneId={selectedZoneId}
        onSelectZoneId={setSelectedZoneId}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        isLiveStreaming={isLiveStreaming}
        onToggleLiveStream={() => setIsLiveStreaming((prev) => !prev)}
        onOpenDemoAttacks={() => setIsDemoAttacksOpen(true)}
        onOpenReports={() => setIsReportsOpen(true)}
        onOpenAccountSettings={() => setIsAccountSettingsOpen(true)}
      />

      {/* Main Tab Views */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'overview' && (
          <OverviewTab
            events={events}
            rules={rules}
            zones={zones}
            anomalies={anomalies}
            trafficData={trafficChartData}
            selectedRange={selectedRange}
            onRangeChange={setSelectedRange}
            selectedCountry={selectedCountry}
            onSelectCountry={setSelectedCountry}
            onInspectEvent={(evt) => setInspectedEvent(evt)}
            onInvestigateIp={(ip) => setInvestigatingIp(ip)}
            onProposeRuleFromEvent={(evt) => handleOpenProposeRule(evt)}
            onProposeNewRule={() => handleOpenProposeRule()}
          />
        )}

        {activeTab === 'traffic' && (
          <TrafficTab
            events={events}
            zones={zones}
            onInvestigateIp={(ip) => setInvestigatingIp(ip)}
            onInspectEvent={(evt) => setInspectedEvent(evt)}
            onProposeRuleForPath={(path) => {
              const matchingEvt = events.find((e) => e.clientRequestPath === path) || events[0];
              handleOpenProposeRule(matchingEvt);
            }}
          />
        )}

        {activeTab === 'timeline' && <IncidentTimeline events={timeline} />}
      </main>

      {/* Modals & Slide-over sheets */}
      <EventSheet
        event={inspectedEvent}
        onClose={() => setInspectedEvent(null)}
        onInvestigateIp={(ip) => {
          setInspectedEvent(null);
          setInvestigatingIp(ip);
        }}
        onProposeRule={(evt) => {
          setInspectedEvent(null);
          handleOpenProposeRule(evt);
        }}
      />

      {isRuleWorkflowOpen && (
        <RuleWorkflowModal
          initialEvent={ruleWorkflowEvent}
          zones={zones}
          historicalEvents={events}
          onClose={() => {
            setIsRuleWorkflowOpen(false);
            setRuleWorkflowEvent(null);
          }}
          onApplyRule={handleApplyRule}
        />
      )}

      {investigatingIp && (
        <IpInvestigationModal
          ip={investigatingIp}
          historicalEvents={events}
          onClose={() => setInvestigatingIp(null)}
          onProposeRuleForIp={(ip) => {
            const matchingEvt = events.find((e) => e.clientIP === ip) || events[0];
            handleOpenProposeRule(matchingEvt);
          }}
        />
      )}

      {isDemoAttacksOpen && (
        <DemoAttacksModal
          zones={zones}
          onTriggerAttack={handleTriggerAttack}
          onResetSimulation={handleResetSimulation}
          onClose={() => setIsDemoAttacksOpen(false)}
        />
      )}

      {isReportsOpen && (
        <ReportsModal
          events={events}
          rules={rules}
          zones={zones}
          anomalies={anomalies}
          timeline={timeline}
          onClose={() => setIsReportsOpen(false)}
        />
      )}

      {isAccountSettingsOpen && (
        <AccountSettingsModal
          accounts={accounts}
          zones={zones}
          onClose={() => setIsAccountSettingsOpen(false)}
          onAddAccount={handleAddAccount}
          onDeleteAccount={handleDeleteAccount}
        />
      )}
    </div>
  );
};

export default App;
