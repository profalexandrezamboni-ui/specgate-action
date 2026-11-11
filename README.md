# SpecGate — Deterministic OpenAPI Breaking-Change Gate & SemVer Calculator

[![Live Playground & Cloud Gate](https://img.shields.io/badge/Live_Playground-SpecGate_Edge-blue)](https://specgate.profalexandrezamboni.workers.dev)
[![SpecGate Live Status Badge](https://specgate.profalexandrezamboni.workers.dev/api/v1/badge.svg?verdict=PASS&bump=MINOR)](https://specgate.profalexandrezamboni.workers.dev)

**SpecGate** is a 100% deterministic (zero-LLM) GitHub Action and CLI that catches breaking changes in OpenAPI 3.x and JSON Schema specifications before merge, computes exact Semantic Versioning bumps (`MAJOR`, `MINOR`, `PATCH`), blocks unverified AI coding agent regressions (Claude Code, Cursor, Copilot, OpenAI Codex), and exports cryptographic **SOC 2 CC8.1 Change Management** audit trails.

- **Live Web Playground & Interactive ROI Calculator:** https://specgate.profalexandrezamboni.workers.dev
- **AI Coding Agent Deterministic Harness Guide:** https://specgate.profalexandrezamboni.workers.dev/solutions/ai-coding-agent-ci-gate
- **OpenAPI Diff Comparison (vs. oasdiff, openapi-diff, Optic):** https://specgate.profalexandrezamboni.workers.dev/compare/openapi-diff-vs-oasdiff-vs-optic
- **SPF 10-Lookup Flattening Comparison (SPFGuard vs. EasyDMARC vs. dmarcian):** https://specgate.profalexandrezamboni.workers.dev/compare/spfguard-vs-easydmarc-vs-dmarcian-spf-flattening
- **Accessibility CI Gate Comparison (A11yRatchet vs. axe-linter vs. pa11y-ci):** https://specgate.profalexandrezamboni.workers.dev/compare/a11yratchet-vs-axe-linter-vs-pa11y-ci
- **Complete LLM & Staff Engineer Technical Reference (`llms-full.txt`):** https://specgate.profalexandrezamboni.workers.dev/llms-full.txt

## Direct Engineering Comparison

| Capability | `openapi-diff` | `oasdiff` | `Optic` | **SpecGate** |
| :--- | :--- | :--- | :--- | :--- |
| **CI Cold Start** | ~8–25s (JVM) | <1s (Go) | ~2–5s (Node) | **<0.5s CLI / <15ms Edge** |
| **Exact SemVer Output** | Manual | Diff flags | Changelog tags | **`MAJOR` / `MINOR` / `PATCH` + SVG Badge** |
| **Auditable PR Sign-Off** | No | Custom/Paid | Cloud workflow | **Built-in Reviewer Override + Reason** |
| **SOC 2 CC8.1 Export** | No | No native bundle | Enterprise | **SHA-256 Signed Bundle ($39/mo Team)** |

## Quick Start (GitHub Actions)

```yaml
name: API Contract Gate
on: [pull_request]

jobs:
  specgate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run SpecGate Contract Diff
        uses: profalexandrezamboni-ui/specgate-action@main
        with:
          base_spec: "openapi/base.json"
          head_spec: "openapi/head.json"
          fail_on_breaking: "true"
```

## Pricing & Plans (via Paddle Merchant of Record — 14-Day Unconditional Refund)
- **Free ($0.00/mo):** Up to 2 repositories, standalone CLI & GitHub Action.
- **Starter ($19.00/mo):** Up to 15 private/public repositories, automated PR comments & SemVer badges.
- **Team ($39.00/mo):** Unlimited repositories, Breaking-Change Sign-Off overrides & SOC 2 CC8.1 Audit Trail export.
