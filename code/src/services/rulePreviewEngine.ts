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
interface Token {
  type: 'LPAREN' | 'RPAREN' | 'OR' | 'AND' | 'NOT' | 'CLAUSE';
  value: string;
}

function tokenizeWirefilter(expr: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const len = expr.length;

  while (i < len) {
    while (i < len && /\s/.test(expr[i])) i++;
    if (i >= len) break;

    const char = expr[i];

    if (char === '(') {
      tokens.push({ type: 'LPAREN', value: '(' });
      i++;
      continue;
    }
    if (char === ')') {
      tokens.push({ type: 'RPAREN', value: ')' });
      i++;
      continue;
    }

    const rest = expr.slice(i);
    const orMatch = rest.match(/^(?:or|\|\|)(?=\s|\(|\)|$)/i);
    if (orMatch) {
      tokens.push({ type: 'OR', value: 'or' });
      i += orMatch[0].length;
      continue;
    }

    const andMatch = rest.match(/^(?:and|&&)(?=\s|\(|\)|$)/i);
    if (andMatch) {
      tokens.push({ type: 'AND', value: 'and' });
      i += andMatch[0].length;
      continue;
    }

    const notMatch = rest.match(/^(?:not|!)(?=\s|\(|\)|$)/i);
    if (notMatch) {
      tokens.push({ type: 'NOT', value: 'not' });
      i += notMatch[0].length;
      continue;
    }

    let clause = '';
    let inDoubleQuotes = false;
    let inSingleQuotes = false;
    let inBraces = false;

    while (i < len) {
      const c = expr[i];

      if (c === '"' && !inSingleQuotes) {
        inDoubleQuotes = !inDoubleQuotes;
        clause += c;
        i++;
        continue;
      }
      if (c === "'" && !inDoubleQuotes) {
        inSingleQuotes = !inSingleQuotes;
        clause += c;
        i++;
        continue;
      }
      if (c === '{' && !inDoubleQuotes && !inSingleQuotes) {
        inBraces = true;
        clause += c;
        i++;
        continue;
      }
      if (c === '}' && !inDoubleQuotes && !inSingleQuotes) {
        inBraces = false;
        clause += c;
        i++;
        continue;
      }

      if (!inDoubleQuotes && !inSingleQuotes && !inBraces) {
        if (c === '(' || c === ')') break;
        const sub = expr.slice(i);
        if (/^\s+(?:or|and|not|\|\||&&|!)(?=\s|\(|\)|$)/i.test(sub)) {
          break;
        }
      }

      clause += c;
      i++;
    }

    const trimmed = clause.trim();
    if (trimmed) {
      tokens.push({ type: 'CLAUSE', value: trimmed });
    }
  }

  return tokens;
}

function evaluateAtomicClause(clause: string, event: WafEvent): boolean {
  const trimmed = clause.trim();
  if (!trimmed) return true;

  // Match path contains
  if (trimmed.toLowerCase().includes('http.request.uri.path contains')) {
    const val = extractQuotedValue(trimmed);
    return event.clientRequestPath.toLowerCase().includes(val.toLowerCase());
  }

  // Match path eq / ==
  if (/\bhttp\.request\.uri\.path\s+(?:eq|==)\b/i.test(trimmed)) {
    const val = extractBareOrQuoted(trimmed.split(/\s+(?:eq|==)\s+/i)[1] || '');
    return event.clientRequestPath.toLowerCase() === val.toLowerCase();
  }

  // Match IP in set: ip.src in {198.51.100.44}
  if (trimmed.toLowerCase().includes('ip.src in')) {
    const ips = extractSetValues(trimmed);
    return ips.includes(event.clientIP.toLowerCase());
  }

  // Match IP eq / ==: ip.src eq 198.51.100.44
  if (/\bip\.src\s+(?:eq|==)\b/i.test(trimmed)) {
    const ip = extractBareOrQuoted(trimmed.split(/\s+(?:eq|==)\s+/i)[1] || '');
    return event.clientIP.toLowerCase() === ip.toLowerCase();
  }

  // Match country in set: ip.geoip.country in {"ru" "cn"}
  if (trimmed.toLowerCase().includes('ip.geoip.country in')) {
    const countries = extractSetValues(trimmed);
    return countries.includes(event.clientCountry.toLowerCase());
  }

  // Match country eq / ==: ip.geoip.country eq "ru"
  if (/\bip\.geoip\.country\s+(?:eq|==)\b/i.test(trimmed)) {
    const country = extractBareOrQuoted(trimmed.split(/\s+(?:eq|==)\s+/i)[1] || '');
    return event.clientCountry.toLowerCase() === country.toLowerCase();
  }

  // Match threat score gt / >: cf.threat_score gt 40
  if (/\bcf\.threat_score\s+(?:gt|>)\b/i.test(trimmed)) {
    const score = parseInt(trimmed.split(/\s+(?:gt|>)\s+/i)[1]?.trim() || '', 10);
    return !isNaN(score) && event.threatScore > score;
  }

  // Match threat score gte / >=: cf.threat_score gte 40
  if (/\bcf\.threat_score\s+(?:gte|>=)\b/i.test(trimmed)) {
    const score = parseInt(trimmed.split(/\s+(?:gte|>=)\s+/i)[1]?.trim() || '', 10);
    return !isNaN(score) && event.threatScore >= score;
  }

  // Match threat score lt / <: cf.threat_score lt 40
  if (/\bcf\.threat_score\s+(?:lt|<)\b/i.test(trimmed)) {
    const score = parseInt(trimmed.split(/\s+(?:lt|<)\s+/i)[1]?.trim() || '', 10);
    return !isNaN(score) && event.threatScore < score;
  }

  // Match threat score lte / <=: cf.threat_score lte 40
  if (/\bcf\.threat_score\s+(?:lte|<=)\b/i.test(trimmed)) {
    const score = parseInt(trimmed.split(/\s+(?:lte|<=)\s+/i)[1]?.trim() || '', 10);
    return !isNaN(score) && event.threatScore <= score;
  }

  // Match query contains
  if (trimmed.toLowerCase().includes('http.request.uri.query contains')) {
    const val = extractQuotedValue(trimmed);
    return event.clientRequestQuery.toLowerCase().includes(val.toLowerCase());
  }

  // Match user agent contains
  if (trimmed.toLowerCase().includes('http.user_agent contains')) {
    const val = extractQuotedValue(trimmed);
    return event.userAgent.toLowerCase().includes(val.toLowerCase());
  }

  // Match method eq / ==
  if (/\bhttp\.request\.method\s+(?:eq|==)\b/i.test(trimmed)) {
    const method = extractBareOrQuoted(trimmed.split(/\s+(?:eq|==)\s+/i)[1] || '');
    return event.clientRequestHTTPMethod.toLowerCase() === method.toLowerCase();
  }

  // Match host eq / ==
  if (/\bhttp\.host\s+(?:eq|==)\b/i.test(trimmed)) {
    const host = extractBareOrQuoted(trimmed.split(/\s+(?:eq|==)\s+/i)[1] || '');
    return event.clientRequestHTTPHost.toLowerCase() === host.toLowerCase();
  }

  return false;
}

export function evaluateWirefilter(expression: string, event: WafEvent): boolean {
  if (!expression || !expression.trim()) return false;
  const tokens = tokenizeWirefilter(expression.trim());
  if (tokens.length === 0) return false;

  let pos = 0;

  function parseOr(): boolean {
    let result = parseAnd();
    while (pos < tokens.length && tokens[pos].type === 'OR') {
      pos++;
      const nextAnd = parseAnd();
      result = result || nextAnd;
    }
    return result;
  }

  function parseAnd(): boolean {
    let result = parseNot();
    while (pos < tokens.length && tokens[pos].type === 'AND') {
      pos++;
      const nextNot = parseNot();
      result = result && nextNot;
    }
    return result;
  }

  function parseNot(): boolean {
    if (pos < tokens.length && tokens[pos].type === 'NOT') {
      pos++;
      return !parseNot();
    }
    return parsePrimary();
  }

  function parsePrimary(): boolean {
    if (pos >= tokens.length) return false;
    const token = tokens[pos];

    if (token.type === 'LPAREN') {
      pos++;
      const res = parseOr();
      if (pos < tokens.length && tokens[pos].type === 'RPAREN') {
        pos++;
      }
      return res;
    }

    if (token.type === 'CLAUSE') {
      pos++;
      return evaluateAtomicClause(token.value, event);
    }

    // Unexpected token fallback
    pos++;
    return false;
  }

  return parseOr();
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

  // Filter events belonging to this zone
  const zoneEvents = historicalEvents.filter(
    (e) => e.zoneId === zone.id || e.zoneName === zone.name
  );
  const samplePool = zoneEvents;

  // Evaluate matches
  const matchedEvents = samplePool.filter((evt) =>
    evaluateWirefilter(expression, evt)
  );
  const rawSampledMatches = matchedEvents.length;

  // Extrapolate to windowHours based on actual time span of events in pool (fallback: 30 min default)
  let windowMultiplier = Math.max(1, (windowHours * 60) / 30);
  if (samplePool.length >= 2) {
    const times = samplePool
      .map((e) => new Date(e.timestamp).getTime())
      .filter((t) => !isNaN(t));
    if (times.length >= 2) {
      const spanMinutes = (Math.max(...times) - Math.min(...times)) / 60000;
      if (spanMinutes >= 0.5) {
        windowMultiplier = Math.max(1, (windowHours * 60) / spanMinutes);
      }
    }
  }
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
    matchedEvents.length > 0 ? cleanMatches.length / matchedEvents.length : 0;

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
