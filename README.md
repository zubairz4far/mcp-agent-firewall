# MCP Agent Firewall

A deterministic security gateway for **Model Context Protocol (MCP) 2026-07-28** tool traffic.

It sits between an AI agent/MCP client and an upstream MCP server and decides whether a request is **allowed**, **denied**, or requires **explicit human approval** before a real tool executes.

**The LLM never owns the security decision.**

## Current milestone — v0.4.0

v0.4 adds **privacy-safe OpenTelemetry traces and low-cardinality security metrics** across the existing policy, trusted-schema, approval, and upstream execution path.

```text
agent / MCP client
        |
        v
W3C trace context
        |
        v
protocol integrity checks
        |
        v
deterministic policy
   |        |         |
 DENY    APPROVAL    ALLOW
             |          |
             +-----+----+
                   |
                   v
       pinned trusted tool catalog
       + exact tool membership
       + JSON Schema 2020-12
       + Mcp-Param-* consistency
                   |
          +--------+--------+
          |                 |
   signed approval        direct allow
   when required             |
          |                  |
   exact request hash        |
   expiry + policy version   |
   one-time consumption      |
          +--------+---------+
                   |
                   v
             upstream MCP
                   |
          +--------+--------+
          |                 |
     minimized audit   OpenTelemetry
                       traces + metrics
```

## Security controls

### Deterministic authorization

- default-deny tool policy
- exact `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` consistency checks
- explicit deny patterns for shell/command/credential-oriented tools
- explicit approval classes for consequential send/create/update/delete/purchase/transfer/deploy tools
- nested argument checks for secret-bearing keys, protected paths, oversized strings, and numeric limits
- prompt-injection-like content is only a **risk signal**, never the authorization primitive

### Pinned trusted tool contracts

Every `tools/call` must also exist in an operator-pinned tool catalog.

- canonical catalog SHA-256 pin
- JSON Schema **2020-12** argument validation
- policy wildcards cannot make an unpinned tool trusted
- duplicate catalog keys rejected
- external `$ref` / `$dynamicRef` targets rejected
- schema depth/node/tool counts bounded
- `x-mcp-header` annotations restricted to statically reachable primitive properties
- missing, duplicated, malformed, unexpected, or body-mismatched `Mcp-Param-*` headers fail closed
- Base64 sentinel values are decoded before comparison

### Signed human approvals

Consequential actions use HMAC-SHA256 approval receipts bound to:

- canonical SHA-256 of the exact MCP request
- tool and method
- MCP protocol version
- current firewall policy version
- approver identity
- issue/expiry time
- unique one-time `jti`

Receipts are atomically consumed before upstream dispatch. Modified, expired, replayed, forged, unregistered, or policy-stale receipts are rejected.

## v0.4 OpenTelemetry observability

Telemetry is optional and exports over **OTLP/HTTP** when enabled.

The firewall records:

- end-to-end MCP request spans
- deterministic policy decisions
- security rejection stage and bounded outcome
- upstream status and latency
- policy and trusted-catalog versions
- W3C `traceparent` parent context

Metrics:

- `mcp.firewall.requests`
- `mcp.firewall.request.duration`
- `mcp.firewall.policy.decisions`
- `mcp.firewall.security.rejects`
- `mcp.firewall.upstream.duration`

### Privacy and cardinality rules

Arbitrary attacker-controlled values are **not** metric labels.

Metric dimensions use bounded values such as:

- known MCP method or `unknown`
- tool class: `read`, `write`, `dangerous`, `other`, `none`
- bounded policy decision
- bounded rejection stage
- bounded request outcome
- HTTP status class

The telemetry layer does **not** put raw arguments, request bodies, request IDs, client names, filesystem paths, arbitrary error messages, secrets, or arbitrary tool names into metric labels.

A bounded tool name may appear on a trace for debugging, but raw tool arguments are never attached to spans.

Only standard W3C `traceparent` is extracted for parent context. Caller baggage is intentionally not accepted.

OpenTelemetry HTTP conventions recommend bounded attributes and explicitly warn that attacker-controlled values can create metric-cardinality problems; v0.4 applies that principle to the MCP-specific security metrics.

## Configuration

```env
POLICY_PATH=./config/policy.example.yaml
AUDIT_DB_PATH=./data/audit.db
UPSTREAM_MCP_URL=https://your-mcp-server.example/mcp

TRUSTED_TOOL_CATALOG_PATH=./config/trusted_tools.example.json
TRUSTED_TOOL_CATALOG_SHA256=<canonical-catalog-sha256>

APPROVAL_SIGNING_KEY=<random-secret-at-least-32-bytes>
APPROVAL_ISSUER_TOKEN=<operator-only-token>
APPROVAL_DEFAULT_TTL_SECONDS=300
APPROVAL_MAX_TTL_SECONDS=900

OTEL_ENABLED=true
OTEL_SERVICE_NAME=mcp-agent-firewall
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

If `OTEL_ENABLED=true`, an explicit OTLP endpoint is required. With telemetry disabled, the firewall runs without an exporter.

## Run

```bash
pip install -e ".[dev]"
pytest -q
python scripts/run_benchmark.py --fail-on-unsafe
python scripts/run_approval_benchmark.py
python scripts/run_schema_benchmark.py
python scripts/run_telemetry_benchmark.py
uvicorn app.main:app --reload
```

Docker:

```bash
docker build -t mcp-agent-firewall .
docker run --rm -p 8000:8000 --env-file .env mcp-agent-firewall
```

## Verified v0.4 regression evidence

Verified on GitHub Actions for the v0.4 implementation:

- **66 pytest tests passed**
- policy safety benchmark: **32/32 exact decisions**
- policy benchmark: **0 unsafe false accepts, 0 false blocks**
- signed approval benchmark: **11/11 passed**
- approval benchmark: **0 unsafe false accepts**
- trusted schema / MCP-header benchmark: **12/12 passed**
- schema/header benchmark: **0 unsafe false accepts, 0 false blocks**
- telemetry privacy/cardinality benchmark: **10/10 passed**
- telemetry benchmark: **0 unsafe false accepts**
- Ruff: **passed**
- Docker build: **passed**

These are synthetic regression results, not a claim of universal production security or production-scale observability.

## Portfolio story

This project demonstrates that production AI-agent engineering is not only about model quality. An agent connected to real tools also needs deterministic authorization, protocol integrity, contract validation, human approval for consequential actions, replay resistance, privacy-aware auditability, and observable failure boundaries.

## Residual risks / next milestones

- approval signing-key rotation with key IDs and bounded overlap
- response-side DLP and explicit untrusted-output labeling
- distributed replay/rate-limit state for multi-replica deployments
- optional OPA/Rego policy backend with deterministic local fallback
- live upstream `tools/list` drift reconciliation against the pinned catalog
- adversarial corpus derived from real MCP traces

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the security model.
