import { test, expect } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';

const SCREENSHOT_DIR = path.resolve('../benchmark/edgewatch_captures');

test.beforeAll(async () => {
  if (!fs.existsSync(SCREENSHOT_DIR)) {
    fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
  }
});

test.describe('EdgeWatch E2E Verification & Safety Suite', () => {
  test('1. Full Investigation Workflow & Preview Safety Verification', async ({ page }) => {
    // 1. Load EdgeWatch
    await page.goto('http://127.0.0.1:5173/');
    await expect(page.locator('text=EdgeWatch')).toBeVisible();

    // Verify initial zone and metrics
    await expect(page.locator('#zone-selector')).toBeVisible();
    await expect(page.locator('text=Incoming Web Traffic & WAF Actions')).toBeVisible();

    // Capture Candidate Overview Screenshot
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.waitForTimeout(500);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, 'edgewatch_overview.png'), fullPage: false });

    // 2. Trigger Demo Attack (Credential Stuffing)
    await page.click('#btn-demo-attacks-modal');
    await expect(page.locator('text=Realistic Demo Attack Simulation Suite')).toBeVisible();
    await page.click('#btn-launch-demo-attack');

    // Verify Anomaly Alert is displayed
    await expect(page.locator('text=Credential Stuffing Botnet: High Challenge Failures')).toBeVisible();

    // 3. Inspect Suspicious Event from Table
    const firstInspectBtn = page.locator('[data-testid="inspect-event-btn"]').first();
    await firstInspectBtn.click();

    // Verify Event Sheet is open
    await expect(page.locator('text=Client Intelligence')).toBeVisible();
    await expect(page.locator('text=JA4 TLS Fingerprint')).toBeVisible();

    // Capture Candidate Event Sheet Screenshot
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, 'edgewatch_eventsheet.png'), fullPage: false });

    // 4. Click Propose WAF Rule
    await page.click('button:has-text("Propose WAF Rule")');
    await expect(page.locator('text=WAF Rule Proposal & Impact Preview Workflow')).toBeVisible();

    // Check Apply button is initially disabled
    const applyBtn = page.locator('#btn-apply-waf-rule');
    await expect(applyBtn).toBeDisabled();

    // 5. Run Preview
    await page.click('#btn-preview-impact');
    await expect(page.locator('text=Estimated 24-Hour Rule Impact Preview')).toBeVisible();
    await expect(page.locator('text=Sampled Data')).toBeVisible();

    // CRITICAL SAFETY PROOF: Preview CANNOT apply the rule!
    // The Apply button MUST STILL BE DISABLED after preview!
    await expect(applyBtn).toBeDisabled();

    // 6. Explicit Operator Approval Checkbox
    const approvalCheckbox = page.locator('#chk-explicit-approval');
    await expect(approvalCheckbox).not.toBeChecked();
    await approvalCheckbox.check();

    // Now Apply button must become enabled
    await expect(applyBtn).toBeEnabled();

    // Capture Candidate Rule Workflow Screenshot
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, 'edgewatch_rule_preview.png'), fullPage: false });

    // 7. Apply Rule to Cloudflare Zone WAF
    await applyBtn.click();
    await expect(page.locator('text=Rule successfully verified and deployed')).toBeVisible();

    // Wait for modal to close and check timeline
    await page.waitForTimeout(1600);
    await page.click('#tab-btn-timeline');
    await expect(page.locator('text=Incident Response Timeline')).toBeVisible();
    await expect(page.locator('text=Rule Deployed')).toBeVisible();
  });

  test('2. Multi-Dimensional Traffic Explorer Tab', async ({ page }) => {
    await page.goto('http://127.0.0.1:5173/');
    await page.click('#tab-btn-traffic');
    await expect(page.locator('text=Top Source IP Addresses')).toBeVisible();
    await expect(page.locator('text=Top Request Paths / Endpoints')).toBeVisible();
    await expect(page.locator('text=JA4 TLS Client Fingerprints')).toBeVisible();

    // Capture Candidate Traffic Tab Screenshot
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.waitForTimeout(500);
    await page.screenshot({ path: path.join(SCREENSHOT_DIR, 'edgewatch_traffic.png'), fullPage: false });
  });

  test('3. Downloadable Reports Generation', async ({ page }) => {
    await page.goto('http://127.0.0.1:5173/');
    await page.click('button:has-text("Reports")');
    await expect(page.locator('text=Security Audit & Executive Reporting')).toBeVisible();
    await expect(page.locator('text=Cloudflare Edge Security Executive Report')).toBeVisible();
    await expect(page.locator('text=Observability Key Performance Indicators')).toBeVisible();
  });
});
