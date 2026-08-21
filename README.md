# MCP Agent Firewall

A deterministic policy gateway for **Model Context Protocol (MCP) 2026-07-28** tool traffic.

It sits between an agent/MCP client and a remote MCP server and decides whether a request is allowed, denied, or requires explicit human approval **before** the upstream tool executes.

The LLM never owns the policy decision.

## Current milestone — v0.2.0

v0.2 replaces the static approval secret from the first scaffold with **HMAC-signed, expiring, one-time approval receipts** bound to the canonical fingerprint of the exact MCP request.

A receipt is bound to:

- canonical SHA-256 of protocol version + MCP method + MCP name + JSON-RPC body
- tool name
- MCP method and protocol version
- current firewall policy version
- human approver identity
- issue and expiry timestamps
- a unique receipt ID (`jti`)

Changing an argument, JSON-RPC ID, tool/method header, protocol version, or policy version invalidates the receipt. Receipts are atomically marked consumed immediately before upstream dispatch and cannot be replayed.

## Safety model

```text
agent / MCP client
        |
        v
MCP header + body integrity checks
        |
        v
deterministic tool policy
   |        |         |
 DENY    APPROVAL    ALLOW
             |          |
             v          |
    signed receipt      |
    exact request hash  |
    expiry + policy ver |
    one-time consume    |
             |          |
             +----------+
                 |
                 v
             upstream MCP
                 |
                 v
          privacy-minimized audit
```

Prompt-injection detection is intentionally **not** the authorization primitive. Injection-like text is recorded as a risk signal; permissions remain determined by tool identity, protocol integrity, argument policy, and human approval requirements.

## Core controls

- validates `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` against the JSON-RPC body
- default-deny tool allowlist
- explicit deny patterns for shell/command/credential-style tools
- explicit human-approval class for send/create/update/delete/purchase/transfer/deploy tools
- nested argument scanning for secret-bearing keys, protected paths, oversized strings, and numeric limits
- prompt-injection **signals** on untrusted text fields without treating regex as a complete defense
- HMAC-SHA256 approval receipts with a minimum 32-byte signing key
- configurable short receipt TTL with a hard one-hour maximum
- receipt invalidation on policy-version drift
- durable SQLite receipt registry and atomic one-time consumption
- privacy-minimized audit log that stores request fingerprints instead of raw tool arguments
- operator-protected approval issuance and audit reads
- caller authorization is never forwarded upstream
- single-process per-client rate limiting
- optional upstream MCP reverse proxy after policy passes
- policy and approval security benchmarks in CI
- Docker + GitHub Actions

## Run

```bash
pip install -e ".[dev]"
pytest -q
python scripts/run_benchmark.py --fail-on-unsafe
python scripts/run_approval_benchmark.py
uvicorn app.main:app --reload
```

## Configure signed approvals

```env
UPSTREAM_MCP_URL=https://your-mcp-server.example/mcp
APPROVAL_SIGNING_KEY=<random-secret-at-least-32-bytes>
APPROVAL_ISSUER_TOKEN=<operator-only-token>
APPROVAL_DEFAULT_TTL_SECONDS=300
APPROVAL_MAX_TTL_SECONDS=900
```

The signing key stays inside the firewall. Operators authenticate to the receipt-issuance endpoint with `X-Operator-Token`; callers never receive the signing key.

### 1. Evaluate a consequential request

```bash
curl -X POST http://localhost:8000/v1/evaluate \
  -H 'content-type: application/json' \
  -d '{
    "protocol_version":"2026-07-28",
    "mcp_method":"tools/call",
    "mcp_name":"delete_file",
    "body":{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/tmp/example.txt"}}}
  }'
```

Expected decision: `approval_required`.

### 2. Issue a short-lived receipt after human review

```bash
curl -X POST http://localhost:8000/v1/approvals/issue \
  -H 'content-type: application/json' \
  -H 'X-Operator-Token: <operator-token>' \
  -d '{
    "request": {
      "protocol_version":"2026-07-28",
      "mcp_method":"tools/call",
      "mcp_name":"delete_file",
      "body":{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/tmp/example.txt"}}}
    },
    "approver":"human@example.com",
    "ttl_seconds":300
  }'
```

The endpoint refuses to sign requests that the deterministic policy classifies as either `allow` or `deny`.

### 3. Dispatch the exact approved request

Send the returned receipt in `X-Human-Approval` with the exact request that was reviewed.

```bash
curl -X POST http://localhost:8000/mcp \
  -H 'content-type: application/json' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/call' \
  -H 'Mcp-Name: delete_file' \
  -H 'X-Human-Approval: <signed-receipt>' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/tmp/example.txt"}}}'
```

The receipt is atomically consumed immediately before the upstream request. If the process cannot prove the upstream outcome after dispatch begins, the receipt remains spent and a new human approval is required. This favors duplicate-side-effect prevention over automatic retry.

## Regression evidence

The original policy benchmark contains **32 synthetic cases** spanning protocol mismatches, denied tools, approval-required tools, protected paths, secret-bearing fields, argument limits, injection-risk signals, and known-safe reads.

The v0.1 baseline was:

- **32/32 exact policy decisions**
- **0 unsafe false accepts**
- **0 false blocks**
- **15 unit/API tests passed**

v0.2 adds a dedicated approval-security benchmark covering signature tampering, request mutation, expiry, policy drift, wrong signing keys, malformed receipts, unregistered receipts, and replay attempts. CI gates both suites before merge.

These are synthetic regression results, not a claim of universal production security.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for trust boundaries and residual risk.

## Next milestones

1. schema-aware validation from a pinned trusted MCP tool catalog
2. `Mcp-Param-*` verification against trusted tool schemas
3. OpenTelemetry traces and low-cardinality policy-decision metrics
4. response-side DLP / untrusted-content labeling
5. shared replay/rate-limit state for multi-replica deployment
6. optional OPA/Rego backend with deterministic local fallback
7. adversarial corpus derived from real MCP traces
