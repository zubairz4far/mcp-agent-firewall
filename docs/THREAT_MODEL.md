# Threat model — MCP Agent Firewall v0.4

## Assets to protect

- downstream MCP tools and the external side effects they can cause
- the trusted definition of which tool contracts are authorized
- credentials used by the upstream MCP server
- user data present in tool arguments and responses
- human approval authority and approval-signing key material
- audit integrity and traceability
- telemetry confidentiality, integrity, and bounded cardinality

## Trust boundaries

1. **Agent/MCP client → firewall**: untrusted. The client may be confused, compromised, or influenced by prompt injection.
2. **Firewall policy configuration**: trusted administrative input controlling coarse allow/deny/approval classes.
3. **Pinned trusted tool catalog**: trusted administrative input defining exact executable tool names, JSON Schema contracts, and permitted `x-mcp-header` mappings. Its canonical SHA-256 is pinned separately from its path.
4. **Approval issuer operator**: trusted human/operator interface authenticated separately from the MCP caller.
5. **Approval signing key**: trusted deployment secret held only by the firewall.
6. **Firewall SQLite state**: trusted single-instance state for audit and one-time receipt consumption.
7. **Firewall → upstream MCP server**: configured transport destination. Live upstream discovery is not treated as authorization authority.
8. **Firewall → OpenTelemetry collector/backend**: optional configured observability boundary. The collector/backend must be treated as security-sensitive operational infrastructure.
9. **Tool output → agent**: untrusted content. v0.4 still passes upstream responses through without output DLP or sanitization.

## Primary threats and controls

### Header/body smuggling or mismatch

An attacker may present benign MCP headers while asking the JSON-RPC body to execute a different operation.

**Control:** deterministic `Mcp-Name` / `Mcp-Method` consistency checks fail closed. Trusted `x-mcp-header` mappings additionally require `Mcp-Param-*` values to agree with the exact body arguments.

### Broad policy pattern captures an unreviewed tool

A wildcard such as `read_*` may match a newly exposed upstream tool.

**Control:** a policy allow/approval result is not sufficient for `tools/call`; the exact tool name must also exist in the SHA-256-pinned trusted catalog.

### Tool-schema drift or upstream redefinition

An upstream server may change a tool's argument schema, semantics, or metadata after firewall policy/catalog review.

**Control:** requests are validated against the operator-pinned local JSON Schema 2020-12 contract rather than trusting live discovery metadata.

**Residual risk:** a pinned schema constrains request shape, not implementation semantics behind the same tool name. v0.4 does not yet reconcile live `tools/list` output against the pinned catalog.

### Malicious or ambiguous trusted schema

A catalog may contain invalid, external, excessively deep, or structurally ambiguous schemas.

**Control:** duplicate JSON keys, invalid schemas, external `$ref` / `$dynamicRef`, excessive depth/node/tool counts, non-object roots, duplicate tool names, and unsupported/ambiguous `x-mcp-header` annotations fail catalog loading.

### Trusted catalog replacement

An attacker with filesystem access may replace the catalog while preserving its path.

**Control:** startup verifies the canonical parsed catalog SHA-256 against a separately configured digest. A custom path without an explicit valid pin fails closed.

### Argument or routing-header smuggling

An agent may send missing, unexpected, mistyped, out-of-range, or header/body-divergent parameters.

**Control:** arguments are schema-validated before approval issuance and again before dispatch. Required mirrored primitive parameters must have exactly one valid `Mcp-Param-*` header whose decoded value matches the body.

### Excessive agent authority

A model may attempt consequential actions without human review.

**Control:** configured send/create/update/delete/purchase/transfer/deploy classes require signed human approval after policy and schema checks.

### Approval substitution, replay, staleness, or policy drift

An attacker may alter an approved request, replay it, use it after expiry, or use it after policy changes.

**Control:** HMAC-SHA256 receipts bind the exact canonical request hash, tool, method, protocol version, policy version, approver metadata, timestamps, and unique `jti`. Receipts expire and are atomically consumed once before dispatch.

### Approval signing-key compromise

If the symmetric signing key is exposed, an attacker can forge receipts.

**Control:** keys must be at least 32 bytes and are never returned by the API. Secret management and rotation remain deployment responsibilities.

### Uncertain upstream outcome

The firewall may consume an approval and lose the connection after the upstream action has potentially executed.

**Control:** the receipt remains spent after dispatch begins; consequential requests are not automatically retried with the same approval.

### Sensitive argument/audit leakage

Raw tool arguments may contain private data or secrets.

**Control:** deterministic sensitive-key/path checks run before forwarding. Audit records store request fingerprints and bounded metadata rather than raw request bodies/arguments.

### Telemetry exfiltration of request data

Observability instrumentation can accidentally become a second data-exfiltration channel by recording tool arguments, bodies, tokens, approvals, or PII.

**v0.4 control:** the `FirewallObservability` API accepts control-plane outcomes/metadata, not raw argument/body objects. Current telemetry attributes deliberately exclude raw tool arguments, raw bodies, approval receipts, approver identities, and authorization tokens. Request identity is represented by SHA-256 fingerprint rather than raw content.

**Regression evidence:** the observability CI benchmark injects a secret sentinel into a real MCP request and asserts that the sentinel is absent from captured span attributes/events and metric measurements. This is a targeted regression test, not universal proof that future instrumentation/configuration cannot leak sensitive data.

### High-cardinality telemetry denial of service / cost explosion

Attacker-controlled values in metric labels can create unbounded series cardinality and excessive backend cost/resource use.

**v0.4 control:** metric dimensions are restricted to bounded sets: decision, risk, normalized method family, schema check/outcome/phase, approval phase/outcome, and normalized upstream status family. Tool names and request fingerprints are trace-only and are never metric dimensions.

**Residual risk:** trace attributes such as exact tool name and request SHA-256 still create operational metadata volume and may reveal tool usage patterns to a telemetry backend. Collector access and retention should therefore be restricted.

### Trace-context spoofing or malformed propagation

An untrusted caller may send a malformed or attacker-chosen trace context, or the firewall may forward a caller header verbatim downstream.

**v0.4 control:** incoming HTTP W3C TraceContext is parsed by the OpenTelemetry propagator. The upstream hop receives a newly injected context derived from the firewall's current client span rather than a blind copy of the incoming raw `traceparent` value.

**Residual risk:** trace IDs are correlation metadata, not authentication or authorization. An attacker controlling a valid incoming trace context can influence correlation identity, so no security decision depends on trace context.

### Telemetry collector compromise or misconfiguration

A configured OTLP collector/backend may be compromised, overly permissive, or retained longer than intended.

**v0.4 control:** telemetry export is off by default. OTLP HTTP export is created only when configured. The firewall's security decisions do not depend on collector availability.

**Residual risk:** when export is enabled, control-plane trace metadata leaves the firewall process and inherits the collector/backend's confidentiality, access-control, retention, and transport posture.

### Prompt injection

Untrusted content may try to override the agent's instructions and trigger unintended calls.

**Control:** prompt-injection-like text is only a signal. Protocol integrity, deterministic policy, pinned schemas, argument constraints, and human approval remain authoritative.

### Credential confused-deputy behavior

A caller may try to smuggle caller authorization to the upstream server.

**Control:** caller authorization is not forwarded. Upstream bearer auth is separately deployment-configured and is excluded from telemetry attributes.

### Resource exhaustion

A client may flood the gateway, send oversized requests, or provide pathological trusted schemas.

**Control:** bounded request bodies, per-process sliding-window rate limiting, and bounded catalog/schema size/depth.

## Observability-specific privacy contract

Current trace attributes may include:

- MCP method / normalized method family
- protocol version
- exact tool name
- request SHA-256 fingerprint
- firewall policy version
- trusted catalog version
- policy decision / risk
- schema and approval outcomes
- upstream status/outcome

Current metric dimensions are limited to:

- policy: `decision`, `risk`, `method_family`
- schema: `check`, `outcome`, `phase`
- approval: `phase`, `outcome`
- upstream latency: `outcome`

Current instrumentation must not add raw request arguments, bodies, responses, approval receipts, approver identities, or authorization values as telemetry attributes/dimensions without an explicit threat-model and privacy review.

## Explicit non-goals / residual risk

- v0.4 is not a complete prompt-injection detector.
- the pinned catalog is static local administrative state; secure remote distribution/signing/rotation is not implemented.
- live upstream `tools/list` drift detection/reconciliation is not implemented.
- a trusted input schema cannot prove benign upstream implementation semantics.
- SQLite replay state and the in-memory rate limiter are single-instance controls, not distributed coordination primitives.
- approval issuer auth remains a shared-secret baseline rather than phishing-resistant operator identity.
- HMAC approval signing has no key IDs or overlapping rotation window yet.
- upstream tool responses are not yet passed through DLP, sanitization, or explicit untrusted-content labeling.
- OTLP collector/backend confidentiality, retention, and access controls are outside the application boundary.
- the sentinel regression benchmark is targeted evidence, not a comprehensive information-flow proof.
- no OpenTelemetry `baggage` propagation is intentionally implemented; v0.4 focuses on W3C trace context.
- there is no OPA/Rego backend yet.

## Next hardening milestones

1. response-side DLP / explicit untrusted-content labeling
2. approval signing-key rotation with key IDs and bounded verification overlap
3. shared receipt/rate-limit state for multi-replica deployments
4. live upstream `tools/list` drift detection against the pinned catalog
5. optional OPA/Rego backend with deterministic local fallback
6. adversarial corpus derived from real MCP traces rather than only synthetic fixtures
7. broader protocol metadata consistency checks beyond the `tools/call` boundary
