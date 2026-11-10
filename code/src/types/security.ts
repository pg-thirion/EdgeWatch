export type CloudflarePlan = 'free' | 'pro' | 'business' | 'enterprise';

export interface PlanLimitInfo {
  plan: CloudflarePlan;
  maxCustomRules: number;
  maxRateLimitingRules: number;
  analyticsRetentionDays: number;
  defaultSampleRate: number; // e.g. 10 means 1 in 10
  supportsManagedRules: boolean;
  supportsRawLogpush: boolean;
  supportsJA4Fingerprint: boolean;
}

export const PLAN_LIMITS: Record<CloudflarePlan, PlanLimitInfo> = {
  free: {
    plan: 'free',
    maxCustomRules: 5,
    maxRateLimitingRules: 1,
    analyticsRetentionDays: 1,
    defaultSampleRate: 10,
    supportsManagedRules: false,
    supportsRawLogpush: false,
    supportsJA4Fingerprint: false,
  },
  pro: {
    plan: 'pro',
    maxCustomRules: 20,
    maxRateLimitingRules: 2,
    analyticsRetentionDays: 3,
    defaultSampleRate: 5,
    supportsManagedRules: true,
    supportsRawLogpush: false,
    supportsJA4Fingerprint: true,
  },
  business: {
    plan: 'business',
    maxCustomRules: 50,
    maxRateLimitingRules: 5,
    analyticsRetentionDays: 30,
    defaultSampleRate: 2,
    supportsManagedRules: true,
    supportsRawLogpush: false,
    supportsJA4Fingerprint: true,
  },
  enterprise: {
    plan: 'enterprise',
    maxCustomRules: 1000,
    maxRateLimitingRules: 100,
    analyticsRetentionDays: 365,
    defaultSampleRate: 1, // Unsampled
    supportsManagedRules: true,
    supportsRawLogpush: true,
    supportsJA4Fingerprint: true,
  },
};

export interface CloudflareAccount {
  id: string;
  name: string;
  maskedToken: string;
  encryptedTokenHash: string;
  status: 'connected' | 'error' | 'syncing';
  permissions: string[];
  zonesCount: number;
}

export interface CloudflareZone {
  id: string;
  name: string;
  accountId: string;
  accountName: string;
  plan: CloudflarePlan;
  status: 'active' | 'paused' | 'pending';
  currentCustomRulesCount: number;
  rulesetId: string;
  rulesetPhase: 'http_request_firewall_custom';
}

export type WafAction = 'block' | 'challenge' | 'managed_challenge' | 'js_challenge' | 'log' | 'rate_limit' | 'allow';

export interface WafRule {
  id: string;
  zoneId: string;
  name: string;
  description: string;
  expression: string;
  action: WafAction;
  enabled: boolean;
  phase: 'http_request_firewall_custom';
  createdAt: string;
  updatedAt: string;
  matchedCount24h: number;
}

export interface WafEvent {
  id: string; // Cloudflare Ray ID
  timestamp: string; // ISO string
  zoneId: string;
  zoneName: string;
  action: WafAction;
  source: 'firewallCustom' | 'firewallManaged' | 'rateLimit' | 'ip' | 'wafRule' | 'unknown';
  ruleId?: string;
  ruleName?: string;
  clientIP: string;
  clientCountry: string; // ISO 2-letter
  clientCountryName: string;
  clientAsn: string;
  clientAsnName: string;
  clientRequestHTTPHost: string;
  clientRequestHTTPMethod: string;
  clientRequestHTTPProtocol: string;
  clientRequestPath: string;
  clientRequestQuery: string;
  clientRequestHeaders: Record<string, string>;
  userAgent: string;
  ja4Fingerprint?: string;
  threatScore: number; // 0 - 100
  sampleInterval: number; // 1 = unsampled, 10 = 1 in 10
}

export interface TrafficDataPoint {
  timestamp: string;
  timeLabel: string;
  total: number;
  allowed: number;
  denied: number;
  challenged: number;
  logged: number;
  rateLimited: number;
  isSpike?: boolean;
}

export interface SpikeAnomaly {
  id: string;
  type: 'request_spike' | 'repeated_challenge_failures' | 'bot_surge' | 'sqli_probe';
  zoneId: string;
  zoneName: string;
  detectedAt: string;
  severity: 'critical' | 'high' | 'medium';
  title: string;
  description: string;
  metricValue: string;
  targetPath?: string;
  suspectIp?: string;
  status: 'active' | 'mitigated' | 'dismissed';
}

export interface IpIntelligence {
  ip: string;
  country: string;
  countryName: string;
  asn: string;
  asnName: string;
  threatScore: number;
  totalRequests: number;
  blockedCount: number;
  challengeFailures: number;
  reputation: 'Malicious' | 'Suspicious' | 'Neutral' | 'Clean';
  firstSeen: string;
  lastSeen: string;
  matchedRules: { ruleId: string; ruleName: string; count: number }[];
  userAgents: string[];
  ja4Fingerprints: string[];
  recentEvents: WafEvent[];
}

export interface RulePreviewEstimate {
  proposedExpression: string;
  action: WafAction;
  targetZoneId: string;
  targetZonePlan: CloudflarePlan;
  sampleInterval: number;
  isSampled: boolean;
  evaluatedWindowHours: number;
  totalHistoricalRequests: number;
  rawSampledMatches: number;
  estimatedAffectedRequests: number;
  confidenceIntervalMin: number;
  confidenceIntervalMax: number;
  uncertaintyPercentage: number;
  estimatedBlockedLegitimateUsers: number;
  topAffectedPaths: { path: string; count: number }[];
  topAffectedIps: { ip: string; count: number; country: string }[];
  falsePositiveRisk: 'Low' | 'Moderate' | 'High';
  planLimitExceeded: boolean;
  currentRulesUsed: number;
  maxRulesAllowed: number;
  remainingRuleSlots: number;
}

export interface IncidentTimelineEvent {
  id: string;
  timestamp: string;
  phase: 'anomaly_detected' | 'investigation_started' | 'rule_previewed' | 'rule_approved' | 'traffic_stabilized';
  title: string;
  description: string;
  actor: string;
  metadata?: Record<string, any>;
}

export interface DemoAttackScenario {
  id: string;
  name: string;
  description: string;
  category: 'Credential Stuffing' | 'SQL Injection' | 'L7 DDoS Flood' | 'Scraper Botnet';
  targetZone: string;
  targetPath: string;
  simulatedReqPerSec: number;
  recommendedExpression: string;
  recommendedAction: WafAction;
}
