# MCP Agent Firewall

A deterministic policy gateway for **Model Context Protocol (MCP) 2026-07-28** tool traffic.

It sits between an agent/MCP client and a remote MCP server and decides whether a request is allowed, denied, or requires explicit human approval **before** the upstream tool executes.

The LLM never owns the policy decision.

## Current milestone — v0.3.0

v0.3 adds a **SHA-256 pinned trusted tool catalog** and schema-aware validation to the signed-approval boundary introduced in v0.2.

A policy allow/approval decision is now necessary but **not sufficient** to execute `tools/call`. The requested tool must also exist as an exact entry in the operator-pinned catalog, its arguments must satisfy the pinned JSON Schema 2020-12 contract, and any schema-declared `Mcp-Param-*` mirrors must agree with the JSON-RPC body.

This blocks a broad policy pattern such as `read_*` from automatically authorizing a newly exposed or renamed upstream tool.

## Safety model

```text
agent / MCP client
        |
        v
MCP method/name integrity checks
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
       + exact tool-name membership
       + JSON Schema argument check
       + Mcp-Param-* body/header check
                   |
          +--------+--------+
          |                 |
    signed approval       direct allow
    when required            |
          |                  |
    exact request hash       |
    expiry + policy ver      |
    one-time consume         |
          +--------+---------+
                   |
                   v
               upstream MCP
                   |
                   v
          privacy-minimized audit
```

Prompt-injection detection remains intentionally **outside** the authorization decision. Injection-like content is recorded as a risk signal; permissions are determined by protocol integrity, deterministic policy, trusted tool contracts, argument constraints, and human approval where required.

## v0.3 trusted tool contracts

The example catalog lives at [`config/trusted_tools.example.json`](config/trusted_tools.example.json). The deployment pins the canonical catalog SHA-256 so a changed catalog cannot silently become trusted.

```env
TRUSTED_TOOL_CATALOG_PATH=./config/trusted_tools.example.json
TRUSTED_TOOL_CATALOG_SHA256=d6c3586e2d14d581089bf470df99ef6948abbef81de36c97b5c1637ff93098ac
```

The committed example catalog has a matching pin in [`config/trusted_tools.example.sha256`](config/trusted_tools.example.sha256). When a custom catalog path is configured, an explicit `TRUSTED_TOOL_CATALOG_SHA256` is required; startup fails closed without a valid pin.

### Schema controls

- JSON Schema **2020-12** validation before approval issuance and again before dispatch
- exact trusted catalog membership for every `tools/call`
- duplicate JSON keys rejected while loading the catalog
- external `$ref` / `$dynamicRef` targets rejected; only local `#...` references are accepted
- schema depth, node count, and catalog tool count bounded
- root input schema must be an object
- policy wildcards cannot make an unpinned tool trusted
- schema validation errors expose the failing path/validator, not the raw argument value

### `Mcp-Param-*` integrity

The firewall implements the MCP 2026-07-28 `x-mcp-header` contract for primitive mirrored parameters:

- `x-mcp-header` is accepted only for statically reachable `properties`
- supported mirrored types are `string`, `integer`, and `boolean`
- header names must be valid HTTP tokens and unique case-insensitively
- required body values must have exactly one matching `Mcp-Param-{Name}` header
- missing, duplicate, malformed, unexpected, or body-mismatched mirrors fail closed
- Base64 sentinel values (`=?base64?...?=`) are decoded as UTF-8 before comparison
- integer mirrors are compared numerically
- validated `Mcp-Param-*` headers, including unrecognized ones, are preserved when proxying upstream

Example trusted schema fragment:

```json
{
  "name": "read_metrics",
  "inputSchema": {
    "type": "object",
    "properties": {
      "region": {"type": "string", "x-mcp-header": "Region"},
      "window_minutes": {"type": "integer", "minimum": 1, "maximum": 1440}
    },
    "required": ["region"],
    "additionalProperties": false
  }
}
```

A valid call therefore carries the same value in both places:

```text
Mcp-Name: read_metrics
Mcp-Param-Region: us-west1
```

```json
{"name":"read_metrics","arguments":{"region":"us-west1","window_minutes":15}}
```

If the header says `eu-west1` while the body says `us-west1`, the firewall rejects the request before upstream execution.

## Signed human approvals

v0.2 introduced HMAC-SHA256, expiring, one-time approval receipts. v0.3 retains that design and requires the request to pass the pinned tool schema before a receipt can be issued.

Each receipt remains bound to:

- canonical SHA-256 of protocol version + MCP method + MCP name + JSON-RPC body
- tool name
- MCP method and protocol version
- current firewall policy version
- human approver identity
- issue and expiry timestamps
- a unique receipt ID (`jti`)

Changing the request or policy version invalidates the receipt. A valid receipt is atomically consumed immediately before upstream dispatch and cannot be replayed.

## Core controls

- validates `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` against the gateway request model/body
- default-deny deterministic tool policy
- explicit deny patterns for shell/command/credential-style tools
- human-approval class for consequential send/create/update/delete/purchase/transfer/deploy tools
- nested argument scanning for secret-bearing keys, protected paths, oversized strings, and numeric limits
- prompt-injection signals without treating regex as a security authority
- pinned trusted tool catalog + JSON Schema argument validation
- `Mcp-Param-*` validation from trusted `x-mcp-header` annotations
- HMAC-SHA256 approval receipts with minimum 32-byte signing key
- short approval TTL with a hard one-hour maximum
- policy-version-bound approvals and atomic one-time consumption
- privacy-minimized SQLite audit log storing request fingerprints instead of raw tool arguments
- operator-protected approval issuance and audit reads
- caller authorization is never forwarded upstream
- single-process per-client rate limiting
- optional upstream MCP reverse proxy only after all applicable checks pass
- three independent security regression gates in CI
- Docker + GitHub Actions

## Run

```bash
pip install -e ".[dev]"
pytest -q
python scripts/run_benchmark.py --fail-on-unsafe
python scripts/run_approval_benchmark.py
python scripts/run_schema_benchmark.py
uvicorn app.main:app --reload
```

## Configure

```env
UPSTREAM_MCP_URL=https://your-mcp-server.example/mcp
APPROVAL_SIGNING_KEY=<random-secret-at-least-32-bytes>
APPROVAL_ISSUER_TOKEN=<operator-only-token>
APPROVAL_DEFAULT_TTL_SECONDS=300
APPROVAL_MAX_TTL_SECONDS=900
TRUSTED_TOOL_CATALOG_PATH=./config/trusted_tools.example.json
TRUSTED_TOOL_CATALOG_SHA256=<canonical-catalog-sha256>
```

The signing key stays inside the firewall. Operators authenticate to the receipt-issuance endpoint using `X-Operator-Token`; callers never receive the signing key.

## Verified v0.3 regression evidence

Verified on GitHub Actions for the v0.3 implementation:

- **47 pytest tests passed**
- policy safety benchmark: **32/32 exact decisions**
- policy safety benchmark: **0 unsafe false accepts, 0 false blocks**
- signed approval security benchmark: **11/11 passed**
- signed approval security benchmark: **0 unsafe false accepts**
- trusted schema / MCP header benchmark: **12/12 passed**
- trusted schema / MCP header benchmark: **0 unsafe false accepts, 0 false blocks**
- Ruff: **passed**
- Docker build: **passed**

The schema/header benchmark covers valid mirrors, missing mirrors, header/body mismatches, extra arguments, unpinned tools, nested bindings, Base64 Unicode values, malformed Base64, catalog-pin tampering, external schema references, unsupported mirrored numeric types, and non-static header annotations.

These are synthetic regression results, not a claim of universal production security.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for trust boundaries and residual risk.

## Next milestones

1. OpenTelemetry traces and low-cardinality policy-decision metrics
2. approval signing-key rotation with key IDs and bounded overlap
3. response-side DLP / untrusted-content labeling
4. shared replay and rate-limit state for multi-replica deployment
5. optional OPA/Rego backend with deterministic local fallback
6. adversarial corpus derived from real MCP traces
7. broader protocol metadata consistency checks beyond the v0.3 `tools/call` contract
