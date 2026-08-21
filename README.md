# MCP Agent Firewall

A deterministic security gateway for **Model Context Protocol (MCP) 2026-07-28** traffic.

It sits between an agent/MCP client and a remote MCP server and enforces both sides of the trust boundary:

- **before execution:** protocol integrity, deterministic policy, pinned tool schemas, and signed human approval
- **after execution:** response-side credential DLP, bounded inspection, explicit untrusted-content labeling, and privacy-minimized output audit

The LLM never owns the security decision.

## Current milestone — v0.5.0

v0.5 adds **response-side output containment**.

An authorized tool call is no longer assumed to produce trustworthy output. Every upstream response is inspected before it is returned to the caller. Secret/credential-like output is blocked, prompt-injection-like text is flagged, and all passed-through upstream content is explicitly labeled untrusted.

```text
agent / MCP client
        |
        v
MCP header/body integrity
        |
        v
deterministic policy
        |
        +--> DENY ------------------------------> stop
        |
        v
pinned tool catalog + JSON Schema
        |
        v
signed human approval when required
        |
        v
mcp.upstream.dispatch                   [CLIENT span]
        |
        v
upstream MCP server
        |
        |  UNTRUSTED OUTPUT
        v
mcp.output.inspect
        |
        +--> credential / secret -------------> BLOCK 502 / -32046
        |
        +--> malformed / binary / oversized --> BLOCK 502 / -32046
        |
        +--> prompt-injection signal ----------> FLAG + pass through
        |
        +--> clean ----------------------------> pass through
        |
        v
explicit untrusted-content headers
        |
        v
agent / MCP client

Parallel controls:
- privacy-minimized request + output SQLite audit
- low-cardinality OpenTelemetry metrics
- optional OTLP HTTP export
```

## Response-side containment

### Credential/secret DLP

The deterministic output scanner blocks recognized credential material including:

- structured secret-bearing keys such as `access_token`, `refresh_token`, `api_key`, `private_key`, `authorization`, `password`, `secret`, and related variants
- PEM private-key material
- bearer credentials
- AWS access-key IDs
- GitHub-style tokens
- OpenAI-style `sk-` credentials
- JWT-shaped credential strings

A blocked upstream response is replaced with a firewall-generated JSON-RPC error:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32046,
    "message": "Upstream MCP response blocked by output containment",
    "data": {
      "action": "block",
      "signals": ["sensitive_key"],
      "untrusted": true
    }
  }
}
```

The blocked response body is **not echoed** in the error.

### Prompt-injection handling

Output prompt-injection regexes are signals, not a security authority.

For example, content such as “ignore previous instructions” is allowed to pass through if it contains no blocking secret signal, but the caller receives:

```text
Mcp-Firewall-Untrusted-Content: true
Mcp-Firewall-Output-Inspection: flagged
Mcp-Firewall-Output-Signals: prompt_injection_signal
```

Even clean output receives:

```text
Mcp-Firewall-Untrusted-Content: true
Mcp-Firewall-Output-Inspection: clean
```

This preserves the distinction between **data returned by a tool** and trusted instructions.

### Fail-closed response bounds

Output inspection blocks:

- declared JSON that cannot be parsed
- non-UTF-8 binary output
- responses larger than `MAX_RESPONSE_BYTES` (default **262,144 bytes**)
- JSON deeper than 32 levels
- JSON traversals above 10,000 nodes

UTF-8 output beginning with `{` or `[` is JSON-parsed even when the upstream server declares a misleading non-JSON media type, preventing simple content-type evasion of structured-key DLP.

Current limitation: `httpx` buffers the upstream response before the size check. The limit therefore bounds inspection/return behavior but is not yet a streaming network-memory limit.

## Privacy-minimized output audit

`GET /v1/audit/output` is protected by the same `X-Operator-Token` control as request audit access.

Output audit records contain only:

- timestamp
- method/tool name
- `clean`, `flagged`, or `blocked` outcome
- fixed-vocabulary signal names
- response SHA-256
- response byte length

Raw upstream response bodies are never persisted in the output audit.

## OpenTelemetry observability

Security-focused spans include:

- `mcp.firewall.request`
- `mcp.policy.evaluate`
- `mcp.schema.validate`
- `mcp.approval.issue`
- `mcp.approval.verify`
- `mcp.approval.consume`
- `mcp.upstream.dispatch`
- `mcp.output.inspect`

Low-cardinality metrics:

| Metric | Dimensions |
| --- | --- |
| `mcp.firewall.policy.decisions` | `decision`, `risk`, `method_family` |
| `mcp.firewall.schema.validations` | `check`, `outcome`, `phase` |
| `mcp.firewall.approval.events` | `phase`, `outcome` |
| `mcp.firewall.output.inspections` | `outcome`, `signal_class` |
| `mcp.firewall.upstream.duration` | `outcome` |

Tool names and request hashes are trace-only, not metric dimensions. Trace strings are sanitized and length-bounded. Raw request arguments, response bodies, approval receipts, identities, and auth tokens are excluded from telemetry.

## Request-side controls retained from v0.1–v0.4

- `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` integrity checks
- default-deny deterministic tool policy
- explicit deny patterns for shell/command/credential-style tools
- human approval for consequential send/create/update/delete/purchase/transfer/deploy tools
- nested secret-key, protected-path, string-size, and numeric request constraints
- prompt-injection signals without giving regex security authority
- SHA-256-pinned trusted tool catalog
- JSON Schema 2020-12 argument validation
- trusted `x-mcp-header` / `Mcp-Param-*` body-header verification
- HMAC-SHA256 short-lived one-time approval receipts
- caller authorization never forwarded upstream
- per-process rate limiting and bounded request bodies
- W3C TraceContext extraction + generated upstream propagation
- optional OTLP HTTP trace/metric export

## Configure

```env
UPSTREAM_MCP_URL=https://your-mcp-server.example/mcp
MAX_BODY_BYTES=65536
MAX_RESPONSE_BYTES=262144

APPROVAL_SIGNING_KEY=<random-secret-at-least-32-bytes>
APPROVAL_ISSUER_TOKEN=<operator-only-token>
APPROVAL_DEFAULT_TTL_SECONDS=300
APPROVAL_MAX_TTL_SECONDS=900

TRUSTED_TOOL_CATALOG_PATH=./config/trusted_tools.example.json
TRUSTED_TOOL_CATALOG_SHA256=<canonical-catalog-sha256>

AUDIT_READ_TOKEN=<operator-only-token>

OTEL_ENABLED=false
OTEL_SERVICE_NAME=mcp-agent-firewall
OTEL_EXPORTER_OTLP_ENDPOINT=
```

## Run all gates

```bash
pip install -e ".[dev]"
ruff check app tests scripts
pytest -q
python scripts/run_benchmark.py --fail-on-unsafe
python scripts/run_approval_benchmark.py
python scripts/run_schema_benchmark.py
python scripts/run_observability_benchmark.py
python scripts/run_output_benchmark.py
docker build -t mcp-agent-firewall:test .
```

## Verified v0.5 regression evidence

Verified on GitHub Actions for the v0.5 implementation:

- **74 pytest tests passed**
- policy safety benchmark: **32/32 exact decisions**
- policy safety benchmark: **0 unsafe false accepts, 0 false blocks**
- signed approval security benchmark: **11/11 passed**
- signed approval security benchmark: **0 unsafe false accepts**
- trusted schema / MCP header benchmark: **12/12 passed**
- trusted schema / MCP header benchmark: **0 unsafe false accepts, 0 false blocks**
- observability privacy/propagation benchmark: **14/14 passed**
- observability benchmark: **0 detected telemetry leaks**
- output-containment benchmark: **11/11 passed**
- output-containment benchmark: **0 unsafe false accepts**
- Ruff: **passed**
- Docker build: **passed**

The output-containment benchmark covers clean pass-through, structured secret keys, PEM private keys, bearer credentials, GitHub-style credentials, prompt-injection signaling, malformed JSON, binary output, response-size limits, misleading content types, and non-echoing public inspection metadata.

The observability benchmark exercises real FastAPI/MCP requests and checks W3C parent context, policy/schema/approval/output spans, bounded metric dimensions, generated upstream trace propagation, output untrusted labeling, and absence of an injected secret sentinel from captured telemetry.

These are **synthetic regression tests**, not a claim of universal production security or complete credential/prompt-injection detection.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for trust boundaries, controls, and residual risks.

## Next milestones

1. approval signing-key rotation with key IDs and bounded overlap
2. streaming response-size enforcement and optional safe content-type allowlists
3. shared replay/rate-limit state for multi-replica deployment
4. live upstream `tools/list` drift detection against the pinned catalog
5. optional OPA/Rego backend with deterministic local fallback
6. adversarial corpus derived from real MCP traces
