import {
  WafEvent,
  WafAction,
  CloudflareZone,
  PLAN_LIMITS,
  RulePreviewEstimate,
} from '../types/security';

/**
 * Parses and evaluates Cloudflare Wirefilter expressions against WAF events.
 * Read-only mathematical calculation with uncertainty bounds for sampled data.
 */
export function evaluateWirefilter(expression: string, event: WafEvent): boolean {
  if (!expression || !expression.trim()) return false;
  const cleanExpr = expression.toLowerCase().trim();

  // Tokenize by OR first, then AND
  const orClauses = cleanExpr.split(/\sor\s/);

  return orClauses.some((orClause) => {
    const andClauses = orClause.replace(/[()]/g, '').split(/\sand\s/);

    return andClauses.every((clause) => {
      const trimmed = clause.trim();
      if (!trimmed) return true;

      // Match path contains
      if (trimmed.includes('http.request.uri.path contains')) {
        const val = extractQuotedValue(trimmed);
        return event.clientRequestPath.toLowerCase().includes(val.toLowerCase());
      }

      // Match path eq
      if (trimmed.includes('http.request.uri.path eq')) {
        const val = extractQuotedValue(trimmed);
        return event.clientRequestPath.toLowerCase() === val.toLowerCase();
      }

      // Match IP in set: ip.src in {198.51.100.44}
      if (trimmed.includes('ip.src in')) {
        const ips = extractSetValues(trimmed);
        return ips.includes(event.clientIP.toLowerCase());
      }

      // Match IP eq: ip.src eq 198.51.100.44
      if (trimmed.includes('ip.src eq')) {
        const ip = extractBareOrQuoted(trimmed.split('eq')[1]);
        return event.clientIP.toLowerCase() === ip.toLowerCase();
      }

      // Match country in set: ip.geoip.country in {"ru" "cn"}
      if (trimmed.includes('ip.geoip.country in')) {
        const countries = extractSetValues(trimmed);
        return countries.includes(event.clientCountry.toLowerCase());
      }

      // Match threat score gt: cf.threat_score gt 40
      if (trimmed.includes('cf.threat_score gt')) {
        const score = parseInt(trimmed.split('gt')[1].trim(), 10);
        return !isNaN(score) && event.threatScore > score;
      }

      // Match query contains
      if (trimmed.includes('http.request.uri.query contains')) {
        const val = extractQuotedValue(trimmed);
        return event.clientRequestQuery.toLowerCase().includes(val.toLowerCase());
      }

      // Match user agent contains
      if (trimmed.includes('http.user_agent contains')) {
        const val = extractQuotedValue(trimmed);
        return event.userAgent.toLowerCase().includes(val.toLowerCase());
      }

      // Match method eq
      if (trimmed.includes('http.request.method eq')) {
        const method = extractBareOrQuoted(trimmed.split('eq')[1]);
        return event.clientRequestHTTPMethod.toLowerCase() === method.toLowerCase();
      }

      // Fallback substring search across key fields
      return (
        event.clientRequestPath.toLowerCase().includes(trimmed) ||
        event.clientIP.toLowerCase().includes(trimmed) ||
        event.userAgent.toLowerCase().includes(trimmed)
      );
    });
  });
}

function extractQuotedValue(clause: string): string {
  const match = clause.match(/"([^"]+)"/) || clause.match(/'([^']+)'/);
  return match ? match[1] : clause.split(' ').pop() || '';
}

function extractBareOrQuoted(raw: string): string {
  return raw.replace(/["'{}]/g, '').trim();
}

function extractSetValues(clause: string): string[] {
  const match = clause.match(/\{([^}]+)\}/);
  if (!match) return [];
  return match[1]
    .replace(/["']/g, '')
    .split(/\s+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

/**
 * Preview rule effects against historical traffic dataset.
 * STRICT SAFETY CONTRACT: This function is strictly pure and read-only.
 * It NEVER modifies rules or mutates state.
 */
export function previewRuleImpact(
  expression: string,
  action: WafAction,
  zone: CloudflareZone,
  historicalEvents: WafEvent[],
  windowHours: number = 24
): RulePreviewEstimate {
  const planInfo = PLAN_LIMITS[zone.plan];
  const sampleInterval = planInfo.defaultSampleRate;
  const isSampled = sampleInterval > 1;

  // Filter events belonging to this zone or universal simulation pool
  const zoneEvents = historicalEvents.filter(
    (e) => e.zoneId === zone.id || e.zoneName === zone.name
  );
  const samplePool = zoneEvents.length > 0 ? zoneEvents : historicalEvents;

  // Evaluate matches
  const matchedEvents = samplePool.filter((evt) =>
    evaluateWirefilter(expression, evt)
  );
  const rawSampledMatches = matchedEvents.length;

  // Synthetic 24h multiplier scaling from recent sample pool (assuming pool is ~30 min window)
  const windowMultiplier = Math.max(1, (windowHours * 60) / 30);
  const estimatedMatches = Math.round(
    rawSampledMatches * sampleInterval * windowMultiplier
  );

  // Compute 95% statistical confidence interval for sampled data
  let minEst = estimatedMatches;
  let maxEst = estimatedMatches;
  let uncertaintyPct = 0;

  if (isSampled && rawSampledMatches > 0) {
    // Standard error for Poisson/binomial sampled count
    const stdErr = Math.sqrt(rawSampledMatches * (1 - 1 / sampleInterval)) * sampleInterval * windowMultiplier;
    const marginOfError = Math.round(1.96 * stdErr);
    minEst = Math.max(0, estimatedMatches - marginOfError);
    maxEst = estimatedMatches + marginOfError;
    uncertaintyPct = Math.min(100, Math.round((marginOfError / Math.max(1, estimatedMatches)) * 100 * 10) / 10);
  }

  // Assess false positive risk
  // Clean traffic is events with threatScore < 20 or previously allowed
  const cleanMatches = matchedEvents.filter(
    (e) => e.threatScore < 20 || e.action === 'allow'
  );
  const estCleanBlocked = Math.round(
    cleanMatches.length * sampleInterval * windowMultiplier
  );
  const falsePositiveRatio =
    samplePool.length > 0 ? cleanMatches.length / samplePool.length : 0;

  let fpRisk: 'Low' | 'Moderate' | 'High' = 'Low';
  if (falsePositiveRatio > 0.05) fpRisk = 'High';
  else if (falsePositiveRatio > 0.01) fpRisk = 'Moderate';

  // Aggregate top affected paths
  const pathCounts: Record<string, number> = {};
  matchedEvents.forEach((e) => {
    pathCounts[e.clientRequestPath] = (pathCounts[e.clientRequestPath] || 0) + 1;
  });
  const topAffectedPaths = Object.entries(pathCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([path, count]) => ({
      path,
      count: Math.round(count * sampleInterval * windowMultiplier),
    }));

  // Aggregate top affected IPs
  const ipMap: Record<string, { count: number; country: string }> = {};
  matchedEvents.forEach((e) => {
    if (!ipMap[e.clientIP]) {
      ipMap[e.clientIP] = { count: 0, country: e.clientCountry };
    }
    ipMap[e.clientIP].count += 1;
  });
  const topAffectedIps = Object.entries(ipMap)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 5)
    .map(([ip, data]) => ({
      ip,
      count: Math.round(data.count * sampleInterval * windowMultiplier),
      country: data.country,
    }));

  const maxRules = planInfo.maxCustomRules;
  const currentRules = zone.currentCustomRulesCount;
  const planLimitExceeded = currentRules >= maxRules;
  const remainingSlots = Math.max(0, maxRules - currentRules);

  return {
    proposedExpression: expression,
    action,
    targetZoneId: zone.id,
    targetZonePlan: zone.plan,
    sampleInterval,
    isSampled,
    evaluatedWindowHours: windowHours,
    totalHistoricalRequests: Math.round(
      samplePool.length * sampleInterval * windowMultiplier
    ),
    rawSampledMatches,
    estimatedAffectedRequests: estimatedMatches,
    confidenceIntervalMin: minEst,
    confidenceIntervalMax: maxEst,
    uncertaintyPercentage: uncertaintyPct,
    estimatedBlockedLegitimateUsers: estCleanBlocked,
    topAffectedPaths,
    topAffectedIps,
    falsePositiveRisk: fpRisk,
    planLimitExceeded,
    currentRulesUsed: currentRules,
    maxRulesAllowed: maxRules,
    remainingRuleSlots: remainingSlots,
  };
}
