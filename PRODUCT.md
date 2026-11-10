# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Delegated: choose the stack during implementation after checking the product's requirements. No framework or hosting target is selected yet.

## Users

Small teams investigating suspicious traffic and managing security across multiple Cloudflare accounts and zones.

## Product Purpose

EdgeWatch brings Cloudflare security activity into one dashboard. It helps teams move from suspicious activity to evidence, a proposed WAF rule, an estimated impact preview, and an explicitly approved action.

Success means completing that investigation workflow while keeping credentials protected and making data limitations clear.

## Positioning

The intended focus is investigation and controlled response across accounts and zones in one workflow. A unique competitive advantage has not yet been established.

## Operating Context

- Users connect Cloudflare accounts and investigate activity across their zones.
- The central workflow is: select suspicious activity, inspect evidence, propose a WAF rule, preview its estimated effects, and apply it only after explicit approval.
- Historical IP activity, rule matches and incident timelines support investigation and reporting.
- Realistic demo attacks provide a way to exercise the investigation workflow without requiring live attack traffic.

## Capabilities and Constraints

The following is confirmed product scope, not a claim of implemented functionality. The project currently contains a brief and Impeccable configuration, with no app scaffold.

- Show recent WAF events and blocked requests.
- Provide an interactive world map of threat origins.
- Detect request spikes and repeated challenge failures.
- Investigate IP addresses using historical activity and rule matches.
- Provide incident timelines and downloadable reports.
- Include realistic demo attacks.
- Keep rule preview separate from application: preview must never apply a rule.
- Require explicit approval before applying a proposed WAF rule.
- Protect account credentials.
- Label sampled data and uncertainty in estimated rule effects.
- Verify Cloudflare APIs and plan limits against official documentation before relying on them.
- Verify the complete demo investigation workflow in browser tests, including proving that preview cannot apply rules.

Open decisions include hosting, authentication, credential storage, retention, report formats, supported Cloudflare plans and the precise detection and preview methods. API availability and plan limits have not yet been verified.

## Brand Commitments

- Preserve the product name EdgeWatch.
- The brief names Vercel Firewall's published observability dashboard screenshots as the quality reference. Future visual comparisons must use the actual images and equivalent views: https://vercel.com/docs/vercel-firewall/firewall-observability.

## Evidence on Hand

- `prompt.txt`: the original product brief, workflow requirements and evaluation expectations.
- No implemented interface, captured reference screenshots, customer evidence or measured detection results are present. Do not invent these.

## Product Principles

- Make evidence available throughout investigation and response.
- Keep changes to protection rules under explicit user control.
- Make sampling and preview uncertainty visible.
- Protect credentials when connecting accounts and performing actions.
- Prove the complete investigation workflow, including its approval boundary.

## Accessibility & Inclusion

No product-specific accessibility needs or required conformance level have been confirmed yet.
