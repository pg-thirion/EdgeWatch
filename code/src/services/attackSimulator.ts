import {
  WafEvent,
  SpikeAnomaly,
  DemoAttackScenario,
  IncidentTimelineEvent,
  WafAction,
} from '../types/security';

export function createAttackEvents(
  scenario: DemoAttackScenario,
  zoneId: string,
  zoneName: string
): { events: WafEvent[]; anomaly: SpikeAnomaly; timelineEvent: IncidentTimelineEvent } {
  const timestamp = new Date().toISOString();
  const rayPrefix = Math.random().toString(16).substring(2, 10);
  const events: WafEvent[] = [];

  let anomalyTitle = '';
  let anomalyDesc = '';
  let anomalyType: SpikeAnomaly['type'] = 'request_spike';
  let suspectIp = '198.51.100.44';
  let metricVal = '320 req/s (+520%)';

  if (scenario.category === 'Credential Stuffing') {
    anomalyType = 'repeated_challenge_failures';
    suspectIp = '198.51.100.44';
    anomalyTitle = 'Credential Stuffing Botnet: High Challenge Failures';
    anomalyDesc = `Distributed botnet cycling auth attempts on ${scenario.targetPath}. 98% failed JS challenges.`;
    metricVal = '86 failed challenges / 2 min';

    for (let i = 0; i < 25; i++) {
      events.push({
        id: `${rayPrefix}${i.toString(16).padStart(4, '0')}`,
        timestamp: new Date(Date.now() - i * 1500).toISOString(),
        zoneId,
        zoneName,
        action: 'challenge',
        source: 'firewallCustom',
        ruleName: 'Challenge Suspicious Threat Scores on Auth Endpoints',
        clientIP: i % 3 === 0 ? '198.51.100.44' : `198.51.100.${50 + (i % 8)}`,
        clientCountry: 'RU',
        clientCountryName: 'Russian Federation',
        clientAsn: 'AS14061',
        clientAsnName: 'DigitalOcean, LLC',
        clientRequestHTTPHost: zoneName,
        clientRequestHTTPMethod: 'POST',
        clientRequestHTTPProtocol: 'HTTP/2.0',
        clientRequestPath: scenario.targetPath,
        clientRequestQuery: '',
        clientRequestHeaders: {
          'host': zoneName,
          'user-agent': 'python-requests/2.31.0',
          'content-type': 'application/json',
          'cf-ipcountry': 'RU',
        },
        userAgent: 'python-requests/2.31.0',
        ja4Fingerprint: 't13d1516h2_8daaf6152771_02711d053896',
        threatScore: 88 + (i % 10),
        sampleInterval: 5,
      });
    }
  } else if (scenario.category === 'SQL Injection') {
    anomalyType = 'sqli_probe';
    suspectIp = '203.0.113.195';
    anomalyTitle = 'SQL Injection Attack Campaign Detected';
    anomalyDesc = `Exploitation probes detected targeting query parameters on ${zoneName}. Matched OWASP SQLi ruleset.`;
    metricVal = '48 probes / min';

    const payloads = [
      "' UNION SELECT null, username, password FROM users--",
      "1' OR '1'='1",
      "admin' --",
      "../../../../etc/passwd",
      "'; EXEC xp_cmdshell('dir');--",
    ];

    for (let i = 0; i < 20; i++) {
      events.push({
        id: `${rayPrefix}${i.toString(16).padStart(4, '0')}`,
        timestamp: new Date(Date.now() - i * 2000).toISOString(),
        zoneId,
        zoneName,
        action: 'block',
        source: 'firewallCustom',
        ruleName: 'OWASP Managed SQLi Protection',
        clientIP: suspectIp,
        clientCountry: 'CN',
        clientCountryName: 'China',
        clientAsn: 'AS4134',
        clientAsnName: 'CHINANET-BACKBONE',
        clientRequestHTTPHost: zoneName,
        clientRequestHTTPMethod: 'GET',
        clientRequestHTTPProtocol: 'HTTP/1.1',
        clientRequestPath: '/search',
        clientRequestQuery: `query=${encodeURIComponent(payloads[i % payloads.length])}`,
        clientRequestHeaders: {
          'host': zoneName,
          'user-agent': 'sqlmap/1.7.4#stable',
          'cf-ipcountry': 'CN',
        },
        userAgent: 'sqlmap/1.7.4#stable',
        ja4Fingerprint: 't13d190800_4b4f5351_908fbb121300',
        threatScore: 96,
        sampleInterval: 2,
      });
    }
  } else if (scenario.category === 'L7 DDoS Flood') {
    anomalyType = 'request_spike';
    suspectIp = '45.154.255.89';
    anomalyTitle = `Volumetric L7 Surge on ${scenario.targetPath}`;
    anomalyDesc = `Request rate spiked to 1,850 req/s (+850% over baseline). Adaptive sampling active.`;
    metricVal = '1,850 req/s (+850%)';

    for (let i = 0; i < 30; i++) {
      events.push({
        id: `${rayPrefix}${i.toString(16).padStart(4, '0')}`,
        timestamp: new Date(Date.now() - i * 500).toISOString(),
        zoneId,
        zoneName,
        action: i % 2 === 0 ? 'managed_challenge' : 'rate_limit',
        source: 'rateLimit',
        ruleName: 'L7 Adaptive Rate Limiting',
        clientIP: `45.154.${100 + (i % 20)}.${i * 3 + 1}`,
        clientCountry: 'NL',
        clientCountryName: 'Netherlands',
        clientAsn: 'AS49981',
        clientAsnName: 'WorldStream B.V.',
        clientRequestHTTPHost: zoneName,
        clientRequestHTTPMethod: 'GET',
        clientRequestHTTPProtocol: 'HTTP/2.0',
        clientRequestPath: scenario.targetPath,
        clientRequestQuery: `rand=${Math.random()}`,
        clientRequestHeaders: {
          'host': zoneName,
          'user-agent': 'Mozilla/5.0 (compatible; FloodBot/2.0)',
          'cf-ipcountry': 'NL',
        },
        userAgent: 'Mozilla/5.0 (compatible; FloodBot/2.0)',
        ja4Fingerprint: 't13d1516h2_918273645123_891273918237',
        threatScore: 85,
        sampleInterval: 10,
      });
    }
  } else {
    // Scraper Botnet
    anomalyType = 'bot_surge';
    suspectIp = '185.220.101.5';
    anomalyTitle = 'Evasive Scraper Cluster JA4 Fingerprinted';
    anomalyDesc = 'Rotating proxies detected sharing TLS fingerprint t13d1516h2_8daaf6152771_02711d053896.';
    metricVal = '140 req/s bot activity';

    for (let i = 0; i < 20; i++) {
      events.push({
        id: `${rayPrefix}${i.toString(16).padStart(4, '0')}`,
        timestamp: new Date(Date.now() - i * 1800).toISOString(),
        zoneId,
        zoneName,
        action: 'log',
        source: 'firewallCustom',
        ruleName: 'Log Headless Curl Scripts',
        clientIP: `185.220.${100 + (i % 5)}.${i * 4 + 7}`,
        clientCountry: 'DE',
        clientCountryName: 'Germany',
        clientAsn: 'AS208294',
        clientAsnName: 'CariNet, Inc.',
        clientRequestHTTPHost: zoneName,
        clientRequestHTTPMethod: 'GET',
        clientRequestHTTPProtocol: 'HTTP/2.0',
        clientRequestPath: scenario.targetPath,
        clientRequestQuery: '',
        clientRequestHeaders: {
          'host': zoneName,
          'user-agent': 'HeadlessChrome/120.0.0.0',
          'cf-ipcountry': 'DE',
        },
        userAgent: 'HeadlessChrome/120.0.0.0',
        ja4Fingerprint: 't13d1516h2_8daaf6152771_02711d053896',
        threatScore: 68,
        sampleInterval: 5,
      });
    }
  }

  const anomaly: SpikeAnomaly = {
    id: `anom_sim_${Date.now()}`,
    type: anomalyType,
    zoneId,
    zoneName,
    detectedAt: 'Just now',
    severity: 'critical',
    title: anomalyTitle,
    description: anomalyDesc,
    metricValue: metricVal,
    targetPath: scenario.targetPath,
    suspectIp,
    status: 'active',
  };

  const timelineEvent: IncidentTimelineEvent = {
    id: `tl_sim_${Date.now()}`,
    timestamp,
    phase: 'anomaly_detected',
    title: `Simulated Attack Triggered: ${scenario.name}`,
    description: `EdgeWatch injected telemetry for ${scenario.category} targeting ${zoneName} (${scenario.targetPath}).`,
    actor: 'Demo Simulation Engine',
    metadata: {
      category: scenario.category,
      suspectIp,
      rate: metricVal,
    },
  };

  return { events, anomaly, timelineEvent };
}

export function generateLiveTrafficTick(zoneName: string, zoneId: string): WafEvent {
  const isMalicious = Math.random() < 0.25;
  const rayId = Math.random().toString(16).substring(2, 18);

  const cleanIps = [
    { ip: '142.250.190.46', country: 'US', name: 'United States', asn: 'AS15169', asnName: 'Google LLC' },
    { ip: '157.240.22.35', country: 'IE', name: 'Ireland', asn: 'AS32934', asnName: 'Meta Platforms' },
    { ip: '13.107.42.14', country: 'US', name: 'United States', asn: 'AS8075', asnName: 'Microsoft Corporation' },
    { ip: '185.199.108.153', country: 'GB', name: 'United Kingdom', asn: 'AS36459', asnName: 'GitHub Inc.' },
    { ip: '104.244.42.1', country: 'FR', name: 'France', asn: 'AS13414', asnName: 'Twitter Inc.' },
    { ip: '133.242.18.2', country: 'JP', name: 'Japan', asn: 'AS9370', asnName: 'SAKURA Internet Inc.' },
  ];

  const malIps = [
    { ip: '198.51.100.44', country: 'RU', name: 'Russian Federation', asn: 'AS14061', asnName: 'DigitalOcean' },
    { ip: '203.0.113.195', country: 'CN', name: 'China', asn: 'AS4134', asnName: 'CHINANET' },
    { ip: '45.154.255.89', country: 'NL', name: 'Netherlands', asn: 'AS49981', asnName: 'WorldStream' },
    { ip: '177.12.188.42', country: 'BR', name: 'Brazil', asn: 'AS28573', asnName: 'Claro Brasil' },
  ];

  const targetPool = isMalicious ? malIps : cleanIps;
  const chosen = targetPool[Math.floor(Math.random() * targetPool.length)];

  let action: WafAction = 'allow';
  let threatScore = Math.floor(Math.random() * 15);
  let path = '/products/item-' + Math.floor(Math.random() * 200);

  if (isMalicious) {
    threatScore = 70 + Math.floor(Math.random() * 28);
    const r = Math.random();
    if (r < 0.45) {
      action = 'block';
      path = '/api/v1/auth/login';
    } else if (r < 0.8) {
      action = 'challenge';
      path = '/v2/graphql';
    } else {
      action = 'rate_limit';
      path = '/search?q=exploit';
    }
  }

  return {
    id: rayId,
    timestamp: new Date().toISOString(),
    zoneId,
    zoneName,
    action,
    source: isMalicious ? 'firewallCustom' : 'wafRule',
    ruleName: isMalicious ? 'Threat Defense Engine' : undefined,
    clientIP: chosen.ip,
    clientCountry: chosen.country,
    clientCountryName: chosen.name,
    clientAsn: chosen.asn,
    clientAsnName: chosen.asnName,
    clientRequestHTTPHost: zoneName,
    clientRequestHTTPMethod: isMalicious && Math.random() > 0.5 ? 'POST' : 'GET',
    clientRequestHTTPProtocol: 'HTTP/2.0',
    clientRequestPath: path,
    clientRequestQuery: '',
    clientRequestHeaders: {
      'host': zoneName,
      'user-agent': isMalicious ? 'python-requests/2.31' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      'cf-ipcountry': chosen.country,
    },
    userAgent: isMalicious ? 'python-requests/2.31' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    ja4Fingerprint: isMalicious ? 't13d1516h2_8daaf6152771_02711d053896' : 't13d1516h2_clean_browser_tls_99',
    threatScore,
    sampleInterval: 5,
  };
}
