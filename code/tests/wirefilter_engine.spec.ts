import { test, expect } from '@playwright/test';
import { evaluateWirefilter, previewRuleImpact } from '../src/services/rulePreviewEngine';
import { WafEvent, CloudflareZone } from '../src/types/security';

const mockEvent: WafEvent = {
  id: 'evt_test_1',
  timestamp: new Date().toISOString(),
  zoneId: 'zone_api',
  zoneName: 'api.example.com',
  action: 'block',
  source: 'firewallCustom',
  clientIP: '198.51.100.44',
  clientCountry: 'RU',
  clientCountryName: 'Russian Federation',
  clientAsn: 'AS14061',
  clientAsnName: 'DigitalOcean',
  clientRequestHTTPHost: 'api.example.com',
  clientRequestHTTPMethod: 'POST',
  clientRequestHTTPProtocol: 'HTTP/2.0',
  clientRequestPath: '/api/v1/auth/login',
  clientRequestQuery: 'debug=true',
  clientRequestHeaders: { host: 'api.example.com' },
  userAgent: 'python-requests/2.31.0',
  threatScore: 85,
  sampleInterval: 5,
};

const mockCleanEvent: WafEvent = {
  id: 'evt_clean_1',
  timestamp: new Date().toISOString(),
  zoneId: 'zone_api',
  zoneName: 'api.example.com',
  action: 'allow',
  source: 'wafRule',
  clientIP: '93.184.216.34',
  clientCountry: 'US',
  clientCountryName: 'United States',
  clientAsn: 'AS15133',
  clientAsnName: 'Edgecast',
  clientRequestHTTPHost: 'api.example.com',
  clientRequestHTTPMethod: 'GET',
  clientRequestHTTPProtocol: 'HTTP/2.0',
  clientRequestPath: '/api/v1/users',
  clientRequestQuery: '',
  clientRequestHeaders: { host: 'api.example.com' },
  userAgent: 'Mozilla/5.0 Chrome/120.0.0.0',
  threatScore: 5,
  sampleInterval: 5,
};

const mockZone: CloudflareZone = {
  id: 'zone_api',
  name: 'api.example.com',
  accountId: 'acc_1',
  accountName: 'Acme',
  plan: 'pro',
  status: 'active',
  currentCustomRulesCount: 2,
  rulesetId: 'ruleset_1',
  rulesetPhase: 'http_request_firewall_custom',
};

test.describe('Wirefilter Engine & Preview Safety Unit Tests', () => {
  test('evaluates path contains and path eq accurately', () => {
    expect(evaluateWirefilter('http.request.uri.path contains "/auth"', mockEvent)).toBe(true);
    expect(evaluateWirefilter('http.request.uri.path contains "/unknown"', mockEvent)).toBe(false);
    expect(evaluateWirefilter('http.request.uri.path eq "/api/v1/auth/login"', mockEvent)).toBe(true);
    expect(evaluateWirefilter('http.request.uri.path eq "/api/v1/auth"', mockEvent)).toBe(false);
  });

  test('evaluates IP and geo country filter clauses', () => {
    expect(evaluateWirefilter('ip.src in {198.51.100.44}', mockEvent)).toBe(true);
    expect(evaluateWirefilter('ip.src in {192.0.2.1}', mockEvent)).toBe(false);
    expect(evaluateWirefilter('ip.src eq 198.51.100.44', mockEvent)).toBe(true);
    expect(evaluateWirefilter('ip.geoip.country in {"ru" "cn"}', mockEvent)).toBe(true);
    expect(evaluateWirefilter('ip.geoip.country eq "ru"', mockEvent)).toBe(true);
    expect(evaluateWirefilter('ip.geoip.country eq "us"', mockEvent)).toBe(false);
  });

  test('evaluates threat scores and compound boolean logic (AND / OR)', () => {
    expect(evaluateWirefilter('cf.threat_score gt 80', mockEvent)).toBe(true);
    expect(evaluateWirefilter('cf.threat_score gt 90', mockEvent)).toBe(false);
    expect(
      evaluateWirefilter(
        '(http.request.uri.path contains "/auth" and ip.src eq 198.51.100.44)',
        mockEvent
      )
    ).toBe(true);
    expect(
      evaluateWirefilter(
        '(http.request.uri.path contains "/auth" and ip.src eq 1.1.1.1)',
        mockEvent
      )
    ).toBe(false);
    expect(
      evaluateWirefilter(
        '(ip.src eq 1.1.1.1 or ip.geoip.country eq "ru")',
        mockEvent
      )
    ).toBe(true);
  });

  test('respects boolean operator precedence with nested parentheses', () => {
    // False AND (False OR True) should be FALSE
    expect(
      evaluateWirefilter(
        'http.request.uri.path contains "/other" and (ip.src eq 1.1.1.1 or ip.geoip.country eq "ru")',
        mockEvent
      )
    ).toBe(false);

    // True AND (False OR True) should be TRUE
    expect(
      evaluateWirefilter(
        'http.request.uri.path contains "/auth" and (ip.src eq 1.1.1.1 or ip.geoip.country eq "ru")',
        mockEvent
      )
    ).toBe(true);

    // Compound NOT logic
    expect(
      evaluateWirefilter(
        'http.request.uri.path contains "/auth" and not ip.geoip.country eq "us"',
        mockEvent
      )
    ).toBe(true);
  });

  test('handles string literals containing "or" or "and" without breaking clauses', () => {
    // Literal with "or" should not be split into multiple tokens
    expect(
      evaluateWirefilter(
        'http.user_agent contains "crawler or bot"',
        mockEvent
      )
    ).toBe(false);

    expect(
      evaluateWirefilter(
        'http.user_agent contains "requests or urllib" or http.user_agent contains "python-requests"',
        mockEvent
      )
    ).toBe(true);
  });

  test('unknown clauses return false instead of random substring matches', () => {
    expect(evaluateWirefilter('unknown.field eq "random_value"', mockEvent)).toBe(false);
    expect(evaluateWirefilter('', mockEvent)).toBe(false);
  });

  test('previewRuleImpact computes correct false positive risk and confidence bounds', () => {
    const events = [mockEvent, mockCleanEvent];

    // Targeted mitigation matching only attack
    const estMaliciousOnly = previewRuleImpact(
      'ip.src in {198.51.100.44}',
      'block',
      mockZone,
      events,
      24
    );
    expect(estMaliciousOnly.rawSampledMatches).toBe(1);
    expect(estMaliciousOnly.falsePositiveRisk).toBe('Low');
    expect(estMaliciousOnly.estimatedBlockedLegitimateUsers).toBe(0);

    // Overly broad rule matching clean traffic
    const estCleanOnly = previewRuleImpact(
      'http.request.uri.path contains "/users"',
      'block',
      mockZone,
      events,
      24
    );
    expect(estCleanOnly.rawSampledMatches).toBe(1);
    expect(estCleanOnly.falsePositiveRisk).toBe('High');
    expect(estCleanOnly.estimatedBlockedLegitimateUsers).toBeGreaterThan(0);
  });

  test('preview isolates zone events without polluting from other zones', () => {
    const otherZone: CloudflareZone = {
      ...mockZone,
      id: 'zone_empty',
      name: 'empty.example.com',
    };
    const estimate = previewRuleImpact(
      'ip.src in {198.51.100.44}',
      'block',
      otherZone,
      [mockEvent],
      24
    );
    expect(estimate.rawSampledMatches).toBe(0);
    expect(estimate.estimatedAffectedRequests).toBe(0);
  });

  test('enforces plan quota limits when zone rules reach capacity', () => {
    // Pro plan max is 20 custom rules
    const fullZone: CloudflareZone = {
      ...mockZone,
      currentCustomRulesCount: 20,
    };
    const estimate = previewRuleImpact(
      'ip.src in {198.51.100.44}',
      'block',
      fullZone,
      [mockEvent],
      24
    );
    expect(estimate.planLimitExceeded).toBe(true);
    expect(estimate.remainingRuleSlots).toBe(0);
    expect(estimate.currentRulesUsed).toBe(20);
    expect(estimate.maxRulesAllowed).toBe(20);
  });
});
