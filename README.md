# SpecGate — Deterministic OpenAPI Breaking-Change Gate & SemVer Calculator

[![Live Playground & Cloud Gate](https://img.shields.io/badge/Live_Playground-SpecGate_Edge-blue)](https://specgate.profalexandrezamboni.workers.dev)
[![SpecGate Live Status Badge](https://specgate.profalexandrezamboni.workers.dev/api/v1/badge.svg?verdict=PASS&bump=MINOR)](https://specgate.profalexandrezamboni.workers.dev)

**SpecGate** is a 100% deterministic (zero-LLM) GitHub Action and CLI that catches breaking changes in OpenAPI 3.x and JSON Schema specifications before merge, computes exact Semantic Versioning bumps (`MAJOR`, `MINOR`, `PATCH`), and exports cryptographic SOC 2 Change Management audit trails.

- **Live Web Playground & Interactive ROI Calculator:** https://specgate.profalexandrezamboni.workers.dev
- **OpenAPI Diff Comparison (vs. oasdiff, openapi-diff, Optic):** https://specgate.profalexandrezamboni.workers.dev/compare/openapi-diff-vs-oasdiff-vs-optic
- **Free SPF 10-Lookup Flattener & MTA-STS Generator:** https://specgate.profalexandrezamboni.workers.dev/tools/spf-10-lookup-flattener
- **WCAG 2.2 AA & EN 301 549 CI Regression Gate:** https://specgate.profalexandrezamboni.workers.dev/tools/wcag-2-2-en-301-549-ci-gate

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

## Pricing & Plans
- **Free ($0/mo):** Up to 2 repositories, standalone CLI & GitHub Action.
- **Starter ($19/mo):** Up to 15 private/public repositories, automated PR comments & SemVer badges.
- **Team ($39/mo):** Unlimited repositories, Breaking-Change Sign-Off overrides & SOC 2 Audit Trail export.
