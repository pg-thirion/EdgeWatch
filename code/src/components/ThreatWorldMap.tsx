import React, { useState } from 'react';
import { Globe, ShieldAlert } from 'lucide-react';
import { WafEvent } from '../types/security';

interface ThreatWorldMapProps {
  events: WafEvent[];
  selectedCountry: string | null;
  onSelectCountry: (countryCode: string | null) => void;
}

interface CountryMarker {
  code: string;
  name: string;
  x: number; // Percentage 0-100 on map
  y: number; // Percentage 0-100 on map
  requests: number;
  blocked: number;
  challenged: number;
}

export const ThreatWorldMap: React.FC<ThreatWorldMapProps> = ({
  events,
  selectedCountry,
  onSelectCountry,
}) => {
  const [hoveredCountry, setHoveredCountry] = useState<CountryMarker | null>(null);

  // Geographic anchor coordinates mapped to simplified equirectangular projection
  const countryCoords: Record<string, { x: number; y: number; name: string }> = {
    US: { x: 23, y: 38, name: 'United States' },
    CA: { x: 24, y: 25, name: 'Canada' },
    MX: { x: 20, y: 48, name: 'Mexico' },
    BR: { x: 35, y: 68, name: 'Brazil' },
    AR: { x: 32, y: 80, name: 'Argentina' },
    GB: { x: 48, y: 30, name: 'United Kingdom' },
    DE: { x: 52, y: 30, name: 'Germany' },
    FR: { x: 49, y: 33, name: 'France' },
    NL: { x: 50.5, y: 29, name: 'Netherlands' },
    ES: { x: 47, y: 37, name: 'Spain' },
    IT: { x: 53, y: 36, name: 'Italy' },
    PL: { x: 55, y: 29, name: 'Poland' },
    UA: { x: 59, y: 29, name: 'Ukraine' },
    SE: { x: 53, y: 22, name: 'Sweden' },
    CH: { x: 51, y: 33, name: 'Switzerland' },
    RU: { x: 70, y: 24, name: 'Russian Federation' },
    TR: { x: 58, y: 38, name: 'Turkey' },
    IL: { x: 60, y: 42, name: 'Israel' },
    ZA: { x: 55, y: 78, name: 'South Africa' },
    NG: { x: 49, y: 52, name: 'Nigeria' },
    CN: { x: 78, y: 42, name: 'China' },
    JP: { x: 88, y: 40, name: 'Japan' },
    KR: { x: 84, y: 39, name: 'South Korea' },
    IN: { x: 70, y: 48, name: 'India' },
    SG: { x: 77, y: 57, name: 'Singapore' },
    ID: { x: 81, y: 62, name: 'Indonesia' },
    AU: { x: 86, y: 75, name: 'Australia' },
    IE: { x: 46.5, y: 29.5, name: 'Ireland' },
  };

  // Aggregate stats per country from events
  const countryStats: Record<string, { requests: number; blocked: number; challenged: number; name: string }> = {};
  events.forEach((evt) => {
    const c = evt.clientCountry.toUpperCase();
    if (!countryStats[c]) {
      countryStats[c] = {
        requests: 0,
        blocked: 0,
        challenged: 0,
        name: evt.clientCountryName || c,
      };
    }
    countryStats[c].requests += 1;
    if (evt.action === 'block') countryStats[c].blocked += 1;
    if (evt.action === 'challenge' || evt.action === 'managed_challenge') countryStats[c].challenged += 1;
  });

  const markers: CountryMarker[] = Object.entries(countryStats).map(([code, stats]) => {
    const coords = countryCoords[code] || {
      // Deterministic fallback coordinates for any unmapped country
      x: 30 + ((code.charCodeAt(0) * 17) % 55),
      y: 25 + ((code.charCodeAt(1) * 23) % 50),
      name: stats.name,
    };
    return {
      code,
      name: coords.name || stats.name,
      x: coords.x,
      y: coords.y,
      requests: stats.requests,
      blocked: stats.blocked,
      challenged: stats.challenged,
    };
  });

  // Calculate top attack origin - only consider actual attacks
  const attackOrigins = markers.filter((m) => m.blocked + m.challenged > 0);
  const topThreatOrigin = attackOrigins.length > 0
    ? [...attackOrigins].sort((a, b) => (b.blocked + b.challenged) - (a.blocked + a.challenged))[0]
    : null;

  return (
    <div className="bg-[#121215] border border-[#27272f] rounded-xl p-5 relative overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Globe className="w-5 h-5 text-blue-400" />
          <h3 className="font-semibold text-sm tracking-wide text-zinc-100 uppercase">
            Global Threat Origin Map
          </h3>
          <span className="text-xs bg-zinc-800 text-zinc-400 px-2 py-0.5 rounded-full border border-zinc-700">
            Live Geo-Telemetry
          </span>
        </div>

        <div className="flex items-center gap-4 text-xs text-zinc-400">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)] animate-pulse"></span>
            <span>Blocked Origin</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
            <span>Challenged</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
            <span>Clean Allowed</span>
          </div>
          {selectedCountry && (
            <button
              onClick={() => onSelectCountry(null)}
              className="text-xs bg-blue-500/20 text-blue-400 border border-blue-500/40 px-2.5 py-1 rounded hover:bg-blue-500/30 transition cursor-pointer"
            >
              Clear Filter ({selectedCountry})
            </button>
          )}
        </div>
      </div>

      {/* SVG Canvas World Map with grid lines & continents */}
      <div className="relative w-full h-[320px] bg-[#0c0c0e] rounded-lg border border-zinc-900/90 overflow-hidden select-none">
        <svg
          viewBox="0 0 1000 500"
          className="w-full h-full object-cover"
          preserveAspectRatio="none"
        >
          <defs>
            <radialGradient id="mapGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#1e1e2d" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#0a0a0c" stopOpacity="0" />
            </radialGradient>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#1d1d26" strokeWidth="0.75" strokeDasharray="2,2" />
            </pattern>
          </defs>

          {/* Grid background */}
          <rect width="1000" height="500" fill="url(#mapGlow)" />
          <rect width="1000" height="500" fill="url(#grid)" opacity="0.6" />

          {/* Stylized Continent Outlines (SVG Path approximation) */}
          {/* North America */}
          <path
            d="M 120,90 Q 200,60 270,110 T 320,200 T 260,250 T 210,230 T 170,160 Z"
            fill="#1c1c24"
            stroke="#2e2e3a"
            strokeWidth="1.2"
          />
          {/* South America */}
          <path
            d="M 280,270 Q 370,300 360,370 T 310,470 T 280,390 Z"
            fill="#1c1c24"
            stroke="#2e2e3a"
            strokeWidth="1.2"
          />
          {/* Europe */}
          <path
            d="M 450,110 Q 540,100 560,160 T 500,210 T 450,160 Z"
            fill="#1c1c24"
            stroke="#2e2e3a"
            strokeWidth="1.2"
          />
          {/* Africa */}
          <path
            d="M 460,210 Q 560,210 560,290 T 530,420 T 480,330 T 450,250 Z"
            fill="#1c1c24"
            stroke="#2e2e3a"
            strokeWidth="1.2"
          />
          {/* Asia / Eurasia */}
          <path
            d="M 560,90 Q 750,70 870,140 T 890,260 T 750,260 T 630,220 T 570,150 Z"
            fill="#1c1c24"
            stroke="#2e2e3a"
            strokeWidth="1.2"
          />
          {/* Australia */}
          <path
            d="M 800,340 Q 900,340 910,400 T 820,430 T 790,370 Z"
            fill="#1c1c24"
            stroke="#2e2e3a"
            strokeWidth="1.2"
          />

          {/* Lat/Long Equator & Prime Meridian markers */}
          <line x1="0" y1="250" x2="1000" y2="250" stroke="#2a2a38" strokeWidth="1" strokeDasharray="4,4" />
          <line x1="500" y1="0" x2="500" y2="500" stroke="#2a2a38" strokeWidth="1" strokeDasharray="4,4" />
        </svg>

        {/* Interactive Threat Markers - only render countries with activity */}
        {markers.filter((m) => m.requests > 0).map((m) => {
          const hasAttacks = m.blocked > 0 || m.challenged > 0;
          const isSelected = selectedCountry === m.code;
          const size = Math.min(24, Math.max(10, Math.sqrt(m.requests + 1) * 3));

          return (
            <div
              key={m.code}
              style={{
                left: `${m.x}%`,
                top: `${m.y}%`,
                transform: 'translate(-50%, -50%)',
              }}
              className="absolute cursor-pointer group"
              onClick={() => onSelectCountry(isSelected ? null : m.code)}
              onMouseEnter={() => setHoveredCountry(m)}
              onMouseLeave={() => setHoveredCountry(null)}
            >
              {/* Outer Pulse for Attackers */}
              {hasAttacks && (
                <span
                  style={{ width: `${size * 2}px`, height: `${size * 2}px` }}
                  className={`absolute -top-1/2 -left-1/2 rounded-full opacity-60 animate-ping ${
                    m.blocked > 0 ? 'bg-red-500' : 'bg-amber-500'
                  }`}
                />
              )}

              {/* Main Indicator Pin */}
              <div
                style={{ width: `${size}px`, height: `${size}px` }}
                className={`relative rounded-full border flex items-center justify-center transition-transform transform group-hover:scale-125 ${
                  isSelected
                    ? 'ring-2 ring-blue-400 ring-offset-2 ring-offset-black'
                    : ''
                } ${
                  m.blocked > 0
                    ? 'bg-red-500 border-red-300 shadow-[0_0_12px_rgba(239,68,68,0.9)]'
                    : m.challenged > 0
                    ? 'bg-amber-500 border-amber-300 shadow-[0_0_10px_rgba(245,158,11,0.8)]'
                    : 'bg-emerald-500/80 border-emerald-300'
                }`}
              >
                <span className="text-[9px] font-bold text-white uppercase pointer-events-none">
                  {m.code}
                </span>
              </div>
            </div>
          );
        })}

        {/* Hover Tooltip Overlay */}
        {hoveredCountry && (
          <div
            style={{
              left: `${Math.min(85, Math.max(15, hoveredCountry.x))}%`,
              top: `${Math.min(75, Math.max(20, hoveredCountry.y - 12))}%`,
              transform: 'translate(-50%, -100%)',
            }}
            className="absolute z-30 pointer-events-none bg-[#18181c] border border-zinc-700 shadow-2xl rounded-lg p-3 w-56 text-xs text-zinc-200"
          >
            <div className="flex items-center justify-between border-b border-zinc-800 pb-1.5 mb-2">
              <span className="font-semibold text-sm text-zinc-100 flex items-center gap-1.5">
                <span className="text-base">📍</span> {hoveredCountry.name} ({hoveredCountry.code})
              </span>
              <span className="text-[10px] text-zinc-400">Click to filter</span>
            </div>
            <div className="space-y-1">
              <div className="flex justify-between">
                <span className="text-zinc-400">Total Requests:</span>
                <span className="font-mono font-medium">{hoveredCountry.requests}</span>
              </div>
              <div className="flex justify-between text-red-400">
                <span>Blocked / Denied:</span>
                <span className="font-mono font-medium">{hoveredCountry.blocked}</span>
              </div>
              <div className="flex justify-between text-amber-400">
                <span>Challenged:</span>
                <span className="font-mono font-medium">{hoveredCountry.challenged}</span>
              </div>
            </div>
          </div>
        )}

        {/* Legend Box Bottom Left */}
        <div className="absolute bottom-3 left-3 bg-[#121215]/90 backdrop-blur-sm border border-zinc-800/80 rounded px-2.5 py-1.5 text-[11px] text-zinc-400 flex items-center gap-2">
          <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
          <span>
            Primary Threat Hotspot: <strong className="text-zinc-200">{topThreatOrigin ? `${topThreatOrigin.name} (${topThreatOrigin.code})` : 'None Detected (Traffic Clean)'}</strong>
          </span>
        </div>
      </div>
    </div>
  );
};
