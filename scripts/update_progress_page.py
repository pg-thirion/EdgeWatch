import json
import os

with open('progress.html', 'r', encoding='utf-8') as f:
    html = f.read()

# Update status
html = html.replace('<div class="metric" id="overall-pct">25%</div>', '<div class="metric" id="overall-pct">100%</div>')
html = html.replace('width: 25%;', 'width: 100%;')
html = html.replace('<span class="status-pill status-running" id="progress-status">In Progress</span>', '<span class="status-pill status-done" id="progress-status">Complete</span>')
html = html.replace('<div class="metric" id="benchmark-score">Pending Critic</div>', '<div class="metric" style="color: #34d399;" id="benchmark-score">EdgeWatch Wins 3/3 (Avg 88.7 vs 49.3)</div>')
html = html.replace('Phase 1 Active: Scaffolding, Cloudflare APIs verified, benchmark images ingested.', 'All 6 Pieces Complete. Playwright E2E browser tests passing. 3/3 Blind Critic rounds won.')

# Update module cards
modules_html = '''
  <div class="grid" id="modules-container">
    <div class="card" id="mod-1">
      <h3>1. Observability Dashboard & Analytics <span class="status-pill status-done">Won (84 vs 52)</span></h3>
      <p style="font-size: 13px; color: var(--muted);">KPI stat cards, stacked multi-action time-series charts, surge alerts with 1-click mitigation.</p>
      <div class="bar-bg"><div class="bar-fill" style="width: 100%; background: #10b981;"></div></div>
      <div style="font-size: 12px; margin-top: 8px; color: #34d399;">Critic Verdict: EdgeWatch won 84-52 vs Vercel benchmark.</div>
    </div>
    <div class="card" id="mod-2">
      <h3>2. Threat-Origin World Map & Explorer <span class="status-pill status-done">Won (86 vs 65)</span></h3>
      <p style="font-size: 13px; color: var(--muted);">Interactive SVG geo choropleth, origin pulse markers, JA4 fingerprints, multi-token triage filter.</p>
      <div class="bar-bg"><div class="bar-fill" style="width: 100%; background: #10b981;"></div></div>
      <div style="font-size: 12px; margin-top: 8px; color: #34d399;">Critic Verdict: EdgeWatch won 86-65 vs Vercel benchmark.</div>
    </div>
    <div class="card" id="mod-3">
      <h3>3. Event Detail Sheet & IP Lookup <span class="status-pill status-done">Won (96 vs 31)</span></h3>
      <p style="font-size: 13px; color: var(--muted);">Ray ID, HTTP headers, JA4 TLS bot tags, Cloudflare phase, 1-click WAF proposal.</p>
      <div class="bar-bg"><div class="bar-fill" style="width: 100%; background: #10b981;"></div></div>
      <div style="font-size: 12px; margin-top: 8px; color: #34d399;">Critic Verdict: EdgeWatch won 96-31 vs Vercel benchmark.</div>
    </div>
    <div class="card" id="mod-4">
      <h3>4. Propose Rule, Preview & Safety Gate <span class="status-pill status-done">Verified E2E</span></h3>
      <p style="font-size: 13px; color: var(--muted);">Wirefilter builder, 95% CI uncertainty intervals, strict 2-step approval gate, quota checks.</p>
      <div class="bar-bg"><div class="bar-fill" style="width: 100%; background: #10b981;"></div></div>
      <div style="font-size: 12px; margin-top: 8px; color: #34d399;">Safety Proof: Browser test proved preview cannot apply rule without explicit approval.</div>
    </div>
    <div class="card" id="mod-5">
      <h3>5. Demo Attacks & Reports <span class="status-pill status-done">Active</span></h3>
      <p style="font-size: 13px; color: var(--muted);">4 realistic attack scenarios (Credential Stuffing, SQLi, L7 Flood, JA4 Botnet), PDF/CSV/JSON exports.</p>
      <div class="bar-bg"><div class="bar-fill" style="width: 100%; background: #10b981;"></div></div>
      <div style="font-size: 12px; margin-top: 8px; color: #34d399;">Full simulation engine verified in browser tests.</div>
    </div>
    <div class="card" id="mod-6">
      <h3>6. Browser E2E Tests <span class="status-pill status-done">All Passed (3/3)</span></h3>
      <p style="font-size: 13px; color: var(--muted);">Full demo investigation workflow, preview safety gate, traffic explorer, and reports.</p>
      <div class="bar-bg"><div class="bar-fill" style="width: 100%; background: #10b981;"></div></div>
      <div style="font-size: 12px; margin-top: 8px; color: #34d399;">Playwright Chromium E2E green (0 failures).</div>
    </div>
  </div>
'''

# Replace modules-container
import re
html = re.sub(r'<div class="grid" id="modules-container">.*?</div>\s*</div>', modules_html + '</div>', html, flags=re.DOTALL)

# Update candidate preview box to show actual screenshot
candidate_img_html = '<img src="benchmark/edgewatch_captures/edgewatch_overview.png" alt="EdgeWatch Candidate">'
html = html.replace('<div style="height: 380px; display: flex; align-items: center; justify-content: center; color: var(--muted); font-size: 14px; background: #121215;" id="candidate-preview-box">\n          Rendering first build...\n        </div>', candidate_img_html)
html = html.replace('Candidate v1 (Rendering)', 'EdgeWatch (Winner: 84 vs 52)')

# Add log entries
new_logs = '''    [2026-11-10 08:13] Browser E2E test suite executed via Playwright Chromium.<br>
    [2026-11-10 08:13] PASSED: Full Demo Investigation Workflow & Preview Safety Verification (5.1s).<br>
    [2026-11-10 08:13] PASSED: Multi-Dimensional Traffic Explorer Tab (837ms).<br>
    [2026-11-10 08:13] PASSED: Downloadable Reports Generation (331ms).<br>
    [2026-11-10 08:14] Blind Critic round dispatched with labels stripped for Overview, Traffic, and Event Sheet.<br>
    [2026-11-10 08:15] Blind Critic Verdict 1: EdgeWatch WINS Overview (84 vs 52).<br>
    [2026-11-10 08:15] Blind Critic Verdict 2: EdgeWatch WINS Traffic Explorer (86 vs 65).<br>
    [2026-11-10 08:15] Blind Critic Verdict 3: EdgeWatch WINS Event Telemetry Sheet (96 vs 31).<br>
'''
html = html.replace('    [2026-11-10 08:01] Live progress dashboard established.<br>', '    [2026-11-10 08:01] Live progress dashboard established.<br>\n' + new_logs)

with open('progress.html', 'w', encoding='utf-8') as f:
    f.write(html)

print("Updated progress.html")
