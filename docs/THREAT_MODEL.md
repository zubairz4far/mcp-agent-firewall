# Threat model — MCP Agent Firewall v0.5

## Assets to protect

- downstream MCP tools and the external side effects they can cause
- the trusted definition of authorized tool contracts
- upstream MCP credentials and credentials accidentally returned by tools
- user data present in tool arguments and responses
- human approval authority and signing-key material
- audit integrity and traceability
- telemetry confidentiality, integrity, and bounded cardinality
- the agent's instruction boundary when consuming untrusted tool output

## Trust boundaries

1. **Agent/MCP client → firewall**: untrusted. The client may be compromised or influenced by prompt injection.
2. **Firewall policy configuration**: trusted administrative input for coarse allow/deny/approval classes.
3. **Pinned trusted tool catalog**: trusted exact tool names, JSON Schema contracts, and `x-mcp-header` mappings, pinned by canonical SHA-256.
4. **Approval issuer operator**: trusted human/operator interface authenticated separately from the MCP caller.
5. **Approval signing key**: trusted deployment secret held only by the firewall.
6. **Firewall SQLite state**: trusted single-instance state for request/output audit and one-time receipt consumption.
7. **Firewall → upstream MCP server**: configured transport destination. Live upstream discovery is not authorization authority.
8. **Upstream MCP response → firewall**: untrusted data, even when the request itself was authorized.
9. **Firewall → agent**: only output that passes deterministic response containment is returned; all passed-through upstream output is explicitly labeled untrusted.
10. **Firewall → OpenTelemetry collector/backend**: optional security-sensitive operational boundary.

## Primary threats and controls

### Header/body smuggling or mismatch

An attacker may present benign MCP headers while asking the JSON-RPC body to execute a different operation.

**Control:** deterministic `Mcp-Name` / `Mcp-Method` consistency checks fail closed. Trusted `x-mcp-header` mappings require `Mcp-Param-*` values to agree with the exact body arguments.

### Broad policy pattern captures an unreviewed tool

A wildcard such as `read_*` may match a newly exposed upstream tool.

**Control:** a policy allow/approval result is not sufficient for `tools/call`; the exact tool name must also exist in the SHA-256-pinned trusted catalog.

### Tool-schema drift or upstream redefinition

An upstream server may change a tool's argument schema or semantics after firewall review.

**Control:** requests are validated against the operator-pinned local JSON Schema 2020-12 contract rather than live discovery metadata.

**Residual risk:** a pinned input schema constrains request shape, not implementation semantics behind the same tool name. Live `tools/list` drift reconciliation is not implemented yet.

### Argument or routing-header smuggling

An agent may send missing, unexpected, mistyped, out-of-range, or header/body-divergent parameters.

**Control:** arguments are schema-validated before approval issuance and again before dispatch. Required mirrored primitive parameters must have exactly one valid `Mcp-Param-*` header whose decoded value matches the body.

### Excessive agent authority

A model may attempt consequential actions without human review.

**Control:** configured send/create/update/delete/purchase/transfer/deploy classes require signed human approval after policy and schema checks.

### Approval substitution, replay, staleness, or policy drift

An attacker may alter an approved request, replay it, use it after expiry, or use it after policy changes.

**Control:** HMAC-SHA256 receipts bind the exact canonical request hash, tool, method, protocol version, policy version, approver metadata, timestamps, and unique `jti`. Receipts expire and are atomically consumed once before dispatch.

### Credential or secret leakage in upstream output

An authorized tool may return credentials accidentally or maliciously. A compromised upstream server could also try to make the agent ingest secrets.

**v0.5 control:** every upstream response is inspected before it is returned. Deterministic DLP blocks:

- structured secret-bearing keys such as `access_token`, `refresh_token`, `api_key`, `private_key`, `authorization`, `password`, and related variants
- PEM private-key material
- bearer credentials
- AWS access-key IDs
- GitHub-style tokens
- OpenAI-style `sk-` credentials
- JWT-shaped credential strings

Blocked content is replaced with firewall JSON-RPC error `-32046`; the original response body is never echoed in the error.

**Residual risk:** pattern matching is intentionally conservative and cannot recognize every proprietary credential format. False positives are possible for content that intentionally discusses credential-shaped strings.

### Prompt injection in tool output

An upstream result may contain instructions such as “ignore previous instructions” intended to manipulate the agent.

**v0.5 control:** output prompt-injection patterns are deterministic **signals**, not authorization authority. A response containing only an injection signal is passed through but receives:

- `Mcp-Firewall-Untrusted-Content: true`
- `Mcp-Firewall-Output-Inspection: flagged`
- `Mcp-Firewall-Output-Signals: prompt_injection_signal`

All clean upstream responses are also labeled `Mcp-Firewall-Untrusted-Content: true` so callers do not confuse tool output with trusted instructions.

**Residual risk:** labels require the consuming agent/client to preserve the trust distinction. Regex signals are incomplete and are not claimed to solve prompt injection.

### Content-type evasion

An upstream server may return JSON containing structured secrets while declaring a misleading non-JSON media type.

**v0.5 control:** UTF-8 responses beginning with `{` or `[` are JSON-parsed and recursively scanned even when the declared content type is not JSON.

### Malformed, binary, oversized, or pathological responses

An attacker may use invalid JSON, opaque binary bytes, excessive response size, extreme nesting, or huge JSON structures to bypass inspection or exhaust resources.

**v0.5 control:** response inspection fails closed on:

- declared JSON that cannot be parsed
- non-UTF-8 binary content
- responses larger than `MAX_RESPONSE_BYTES` (default 262,144 bytes)
- JSON deeper than 32 levels
- JSON traversals above 10,000 nodes

**Residual risk:** upstream responses are currently buffered by `httpx` before the size check, so `MAX_RESPONSE_BYTES` bounds inspection/return behavior but is not yet a streaming network-memory limit.

### Sensitive request/audit leakage

Raw tool arguments or responses may contain private data or secrets.

**Control:** request audit stores request fingerprints and bounded metadata rather than raw request bodies. Output audit stores only response SHA-256, byte length, outcome, and fixed-vocabulary signals; raw output is not persisted.

### Telemetry exfiltration of request/output data

Observability can accidentally become a second data-exfiltration channel.

**Control:** telemetry receives control-plane metadata, bounded outcome labels, and signal classes—not raw arguments, request bodies, response bodies, approval receipts, approver identities, or authorization values. Output metrics use only `outcome` and a bounded `signal_class`.

### High-cardinality telemetry denial of service / cost explosion

Attacker-controlled strings in metric labels can create unbounded series cardinality.

**Control:** metric values are collapsed into fixed sets. Tool names and request fingerprints are trace-only, with trace strings sanitized and length-bounded.

### Trace-context spoofing

An untrusted caller may send attacker-chosen trace context.

**Control:** only W3C TraceContext is extracted. Upstream receives newly injected context from the firewall's current client span, not a blind copy of the incoming header. No security decision depends on tracing.

### Credential confused-deputy behavior

A caller may try to smuggle caller authorization to the upstream server.

**Control:** caller authorization is not forwarded. Upstream bearer auth is separately deployment-configured.

### Resource exhaustion

A client may flood the gateway or provide pathological input.

**Control:** bounded request bodies, per-process sliding-window rate limiting, bounded tool catalogs/schemas, and bounded response inspection.

## Output containment privacy contract

Returned upstream data is always labeled untrusted. Output inspection metadata may include only:

- `clean`, `flagged`, or `blocked` outcome
- fixed-vocabulary output signals
- fixed-vocabulary telemetry signal class
- response byte length in the output audit
- response SHA-256 in the output audit

Raw upstream response bodies must not be added to SQLite audit or telemetry without an explicit threat-model/privacy review.

## Explicit non-goals / residual risk

- v0.5 is not a complete prompt-injection detector.
- response DLP focuses on credentials/secrets, not general PII classification.
- opaque binary MCP payload support is intentionally fail-closed in this milestone.
- response-size enforcement is post-buffer rather than streaming.
- live upstream `tools/list` drift detection is not implemented.
- a trusted input schema cannot prove benign upstream implementation semantics.
- SQLite replay/audit state and the in-memory rate limiter are single-instance controls.
- approval signing has no key IDs or overlapping rotation window yet.
- OTLP collector/backend security and retention remain deployment responsibilities.
- there is no OPA/Rego backend yet.

## Next hardening milestones

1. approval signing-key rotation with key IDs and bounded verification overlap
2. streaming response-size enforcement and optional safe content-type allowlists
3. shared receipt/rate-limit state for multi-replica deployment
4. live upstream `tools/list` drift detection against the pinned catalog
5. optional OPA/Rego backend with deterministic local fallback
6. adversarial corpus derived from real MCP traces
7. broader protocol metadata consistency checks beyond `tools/call`
