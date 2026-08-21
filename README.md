# MCP Agent Firewall

A deterministic policy gateway for **Model Context Protocol (MCP) 2026-07-28** tool traffic.

It sits between an agent/MCP client and a remote MCP server and decides whether a request is allowed, denied, or requires explicit human approval **before** the upstream tool executes.

## Why this build

The 2026-07-28 MCP revision makes every request self-contained and requires `Mcp-Method` / `Mcp-Name` headers, which means gateways can route, meter, and authorize tool traffic without deep JSON inspection just to identify the operation. This project uses that transport boundary as a deterministic control plane.

The LLM never owns the policy decision.

## v0.1 features

- validates `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` against the JSON-RPC body
- default-deny tool allowlist
- explicit deny patterns for shell/command/credential-style tools
- explicit human-approval class for send/create/update/delete/purchase/transfer/deploy tools
- nested argument scanning for secret-bearing keys, protected paths, oversized strings, and numeric limits
- prompt-injection **signals** on untrusted text fields without pretending regex is a complete prompt-injection defense
- single-process per-client rate limiting
- privacy-minimized SQLite audit log that stores SHA-256 request fingerprints instead of raw tool arguments
- audit reads require a separate operator token; caller authorization is never forwarded upstream
- optional upstream MCP reverse proxy after policy passes
- benchmark suite with an unsafe-false-accept CI gate
- Docker + GitHub Actions scaffold

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
             v          v
      human token    upstream MCP
             |          |
             +----------+
                 audit
```

Prompt-injection detection is intentionally **not** the authorization primitive. Injection-like text is recorded as a risk signal; permissions remain determined by tool identity, protocol integrity, argument policy, and human approval requirements.

## Run

```bash
pip install -e ".[dev]"
pytest -q
python scripts/run_benchmark.py --fail-on-unsafe
uvicorn app.main:app --reload
```

Dry-run a policy decision:

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

## Proxy mode

Set:

```env
UPSTREAM_MCP_URL=https://your-mcp-server.example/mcp
APPROVAL_TOKEN=<human-controlled-secret>
```

Requests that evaluate to `allow` may proxy upstream. Requests classified as `approval_required` require the approval token before forwarding.

## Measured v0.1 regression baseline

The included synthetic safety benchmark contains **32 cases** spanning protocol mismatches, denied tools, approval-required tools, protected paths, secret-bearing fields, argument limits, injection-risk signals, and known-safe reads.

Current local baseline before repository publication:

- **32/32 exact policy decisions**
- **0 unsafe false accepts**
- **0 false blocks**
- **15 unit/API tests passed**

These are synthetic regression results, not a claim of universal production security.

## Next milestones

1. signed approval receipts bound to the exact MCP request hash
2. schema-aware validation from trusted tool manifests
3. OpenTelemetry traces and policy-decision metrics
4. replay protection and short-lived approval expiry
5. adversarial benchmark expansion with indirect prompt-injection payloads
