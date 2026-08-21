# MCP Agent Firewall

A deterministic policy gateway for **Model Context Protocol (MCP) 2026-07-28** tool traffic.

It sits between an agent/MCP client and a remote MCP server and decides whether a request is allowed, denied, or requires explicit human approval **before** the upstream tool executes.

The LLM never owns the policy decision.

## Current milestone — v0.4.0

v0.4 adds **privacy-minimized OpenTelemetry tracing and metrics** to the security boundary built in v0.1–v0.3.

The firewall can now trace an MCP request through policy evaluation, pinned-schema validation, human-approval verification/consumption, and upstream dispatch while deliberately excluding raw tool arguments, request bodies, approval identities, and authentication tokens from telemetry attributes.

Telemetry export is disabled by default. When an OTLP HTTP endpoint is configured, traces and metrics can be exported to an OpenTelemetry-compatible collector/backend.

## Safety + observability model

```text
agent / MCP client
        |
        | W3C traceparent (optional)
        v
mcp.firewall.request                    [SERVER span]
        |
        +--> mcp.policy.evaluate
        |        |
        |      DENY ----------------------> stop
        |
        +--> mcp.schema.validate
        |        |
        |      invalid -------------------> stop
        |
        +--> mcp.approval.verify          [when required]
        |        |
        |      invalid/missing -----------> stop
        |
        +--> mcp.approval.consume         [one-time receipt]
        |
        v
mcp.upstream.dispatch                    [CLIENT span]
        |
        | generated W3C trace context
        v
upstream MCP server

Parallel signals:
- privacy-minimized SQLite audit
- low-cardinality OpenTelemetry metrics
- optional OTLP HTTP export
```

Prompt-injection detection remains intentionally **outside** the authorization decision. Injection-like content is recorded as a risk signal; permissions are determined by protocol integrity, deterministic policy, trusted tool contracts, argument constraints, and human approval where required.

## v0.4 OpenTelemetry observability

### Trace stages

The manual instrumentation emits security-focused spans rather than generic request dumps:

- `mcp.firewall.request` — server span for the accepted MCP envelope
- `mcp.policy.evaluate` — deterministic policy decision
- `mcp.schema.validate` — pinned JSON Schema / `Mcp-Param-*` validation
- `mcp.approval.issue` — operator-approved receipt issuance
- `mcp.approval.verify` — signed receipt verification
- `mcp.approval.consume` — atomic one-time receipt consumption
- `mcp.upstream.dispatch` — client span for the upstream MCP call

Incoming W3C `traceparent` context is parsed by the OpenTelemetry propagator. For an allowed upstream call, the firewall injects **new trace context derived from the current client span** rather than blindly forwarding the caller's raw trace header.

### Telemetry privacy boundary

The observability API intentionally does **not** accept raw MCP arguments or request bodies.

Trace attributes are limited to control-plane metadata such as:

- MCP method and bounded method family
- protocol version
- tool name
- SHA-256 request fingerprint
- policy version
- trusted catalog version
- policy decision / risk
- schema/approval stage outcomes
- upstream HTTP status family/outcome

The following are deliberately excluded from telemetry attributes:

- raw tool arguments
- raw request/response bodies
- approval receipts
- approval identities
- caller/upstream authorization tokens
- secret argument values

Tool names and request SHA-256 fingerprints are **trace-only** and are not metric dimensions.

### Low-cardinality metrics

| Metric | Dimensions |
| --- | --- |
| `mcp.firewall.policy.decisions` | `decision`, `risk`, `method_family` |
| `mcp.firewall.schema.validations` | `check`, `outcome`, `phase` |
| `mcp.firewall.approval.events` | `phase`, `outcome` |
| `mcp.firewall.upstream.duration` | `outcome` |

The method family is normalized to `server`, `tools`, `resources`, `prompts`, or `other`; upstream status is normalized to `2xx`, `3xx`, `4xx`, `5xx`, or `other`.

### Configure OTLP HTTP export

```env
OTEL_ENABLED=true
OTEL_SERVICE_NAME=mcp-agent-firewall
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
```

If `OTEL_ENABLED=true` is set without an endpoint, `/health` reports telemetry as `disabled_no_endpoint`. If an endpoint is configured, the firewall creates OpenTelemetry SDK trace/metric providers with OTLP HTTP exporters.

`/health` exposes only observability configuration state:

```json
{
  "telemetry_mode": "otlp_http",
  "telemetry_exporting": true
}
```

## Pinned trusted tool contracts

The example catalog lives at [`config/trusted_tools.example.json`](config/trusted_tools.example.json). The deployment pins the canonical catalog SHA-256 so a changed catalog cannot silently become trusted.

```env
TRUSTED_TOOL_CATALOG_PATH=./config/trusted_tools.example.json
TRUSTED_TOOL_CATALOG_SHA256=d6c3586e2d14d581089bf470df99ef6948abbef81de36c97b5c1637ff93098ac
```

A policy allow/approval decision is necessary but **not sufficient** to execute `tools/call`. The tool must exist under its exact name in the pinned catalog, its arguments must satisfy the pinned JSON Schema 2020-12 contract, and schema-declared `Mcp-Param-*` mirrors must agree with the JSON-RPC body.

Schema controls include:

- JSON Schema 2020-12 validation before approval issuance and again before dispatch
- exact trusted catalog membership for every `tools/call`
- duplicate JSON-key rejection while loading the catalog
- external `$ref` / `$dynamicRef` rejection; only local `#...` references accepted
- bounded schema depth, node count, and catalog tool count
- object-only root input schemas
- policy wildcards cannot make an unpinned tool trusted
- validation errors expose path/validator metadata without echoing raw argument values

## Signed human approvals

Consequential tools can require HMAC-SHA256, expiring, one-time approval receipts.

Each receipt is bound to:

- canonical SHA-256 of protocol version + MCP method + MCP name + JSON-RPC body
- tool name
- MCP method and protocol version
- current firewall policy version
- human approver identity
- issue and expiry timestamps
- a unique receipt ID (`jti`)

Changing the request or policy version invalidates the receipt. A valid receipt is atomically consumed immediately before upstream dispatch and cannot be replayed.

## Core controls

- `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` integrity checks
- default-deny deterministic tool policy
- explicit deny patterns for shell/command/credential-style tools
- human approval for consequential send/create/update/delete/purchase/transfer/deploy tools
- nested secret-key, protected-path, string-size, and numeric constraints
- prompt-injection signals without giving regex security authority
- SHA-256 pinned trusted tool catalog
- JSON Schema 2020-12 argument validation
- trusted `x-mcp-header` / `Mcp-Param-*` body-header verification
- HMAC-SHA256 short-lived one-time approval receipts
- privacy-minimized SQLite audit logging
- caller authorization never forwarded upstream
- per-process rate limiting and bounded request bodies
- W3C TraceContext extraction + generated upstream propagation
- privacy-minimized OpenTelemetry spans and low-cardinality metrics
- optional OTLP HTTP trace/metric export
- four independent regression/security gates in CI
- Docker + GitHub Actions

## Run

```bash
pip install -e ".[dev]"
pytest -q
python scripts/run_benchmark.py --fail-on-unsafe
python scripts/run_approval_benchmark.py
python scripts/run_schema_benchmark.py
python scripts/run_observability_benchmark.py
uvicorn app.main:app --reload
```

## Verified v0.4 regression evidence

Verified on GitHub Actions for the v0.4 implementation:

- **52 pytest tests passed**
- policy safety benchmark: **32/32 exact decisions**
- policy safety benchmark: **0 unsafe false accepts, 0 false blocks**
- signed approval security benchmark: **11/11 passed**
- signed approval security benchmark: **0 unsafe false accepts**
- trusted schema / MCP header benchmark: **12/12 passed**
- trusted schema / MCP header benchmark: **0 unsafe false accepts, 0 false blocks**
- observability privacy/propagation benchmark: **11/11 passed**
- observability benchmark: **0 detected telemetry leaks of the injected secret sentinel**
- Ruff: **passed**
- Docker build: **passed**

The observability benchmark exercises real FastAPI/MCP requests and checks W3C parent context, policy/schema/approval spans, bounded metric dimensions, upstream client-span creation, generated upstream trace propagation, latency metric emission, and absence of an injected secret sentinel from captured span attributes/events and metric measurements.

These are **synthetic regression tests**. The sentinel test is evidence for the implemented telemetry boundary, not a claim that arbitrary sensitive data can never reach an observability backend under every future code/configuration change.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for trust boundaries and residual risk.

## Next milestones

1. response-side DLP / explicit untrusted-content labeling
2. approval signing-key rotation with key IDs and bounded overlap
3. shared replay/rate-limit state for multi-replica deployment
4. live upstream `tools/list` drift detection against the pinned catalog
5. optional OPA/Rego backend with deterministic local fallback
6. adversarial corpus derived from real MCP traces
7. broader protocol metadata consistency checks beyond `tools/call`
