# Threat model — MCP Agent Firewall v0.3

## Assets to protect

- downstream MCP tools and the external side effects they can cause
- the trusted definition of which tool contracts are authorized
- credentials used by the upstream MCP server
- user data present in tool arguments
- human approval authority
- approval-signing key material
- audit integrity and traceability

## Trust boundaries

1. **Agent/MCP client → firewall**: untrusted. The client may be confused, compromised, or influenced by prompt injection.
2. **Firewall policy configuration**: trusted administrative input controlling coarse allow/deny/approval classes.
3. **Pinned trusted tool catalog**: trusted administrative input defining exact executable tool names, JSON Schema input contracts, and permitted `x-mcp-header` mappings. Its canonical SHA-256 is configured separately from its path.
4. **Approval issuer operator**: trusted human/operator interface authenticated separately from the MCP caller.
5. **Approval signing key**: trusted deployment secret held only by the firewall.
6. **Firewall SQLite state**: trusted single-instance state for audit and one-time receipt consumption.
7. **Firewall → upstream MCP server**: configured transport destination. The upstream server may change its exposed tool metadata; v0.3 does not treat live upstream discovery as authorization authority.
8. **Tool output → agent**: untrusted content. v0.3 does not yet sanitize upstream responses beyond transport pass-through.

## Primary threats

### Header/body smuggling or mismatch

An attacker may present benign `Mcp-Name` / `Mcp-Method` headers while asking the JSON-RPC body to execute a different operation.

**Control:** deterministic header/body consistency checks fail closed before forwarding. For schema-declared mirrored parameters, v0.3 additionally checks `Mcp-Param-*` values against the exact body arguments.

### Broad allowlist pattern captures a new tool

A wildcard policy such as `read_*` may match a newly added upstream tool that an operator never reviewed.

**v0.3 control:** policy authorization is not sufficient for `tools/call`. The tool must also exist under its exact name in the pinned trusted catalog. A policy-matched but unpinned tool is denied before upstream execution.

### Tool-schema drift or upstream tool redefinition

An upstream MCP server may change a tool's argument schema, semantics, or metadata after the firewall policy was written.

**v0.3 control:** the firewall validates against the operator-pinned local catalog rather than treating live upstream `tools/list` metadata as security authority. Changing the trusted catalog requires updating its separately configured SHA-256 pin.

**Residual risk:** a pinned schema constrains request shape, not the implementation semantics behind the same upstream tool name. A compromised upstream server can still behave maliciously after receiving an authorized call.

### Argument shape smuggling

An agent may call an authorized tool with missing, unexpected, mistyped, or out-of-range arguments that were not part of the reviewed tool contract.

**v0.3 control:** `tools/call` arguments are validated with JSON Schema 2020-12 against the pinned input schema. Validation happens before approval issuance and again before dispatch. Catalog tools can use `additionalProperties: false` to reject unexpected fields.

### Malicious or ambiguous trusted schema

A catalog may contain an invalid, unexpectedly remote, excessively deep, or structurally ambiguous schema.

**v0.3 control:** catalog loading rejects duplicate JSON object keys, invalid JSON Schema, external `$ref` / `$dynamicRef` targets, non-object root schemas, excessive schema depth/node count, excessive tool counts, duplicate tool names, and invalid `x-mcp-header` annotations. Only local `#...` references are accepted.

### Trusted catalog file replacement

An attacker with filesystem access may replace the configured catalog while retaining its path.

**v0.3 control:** startup canonicalizes the parsed catalog and verifies its SHA-256 against a separately configured expected digest. A custom catalog path without an explicit pin fails closed.

**Residual risk:** if an attacker can modify both the catalog and its deployment pin/configuration, this control is bypassed. Protecting deployment configuration remains an infrastructure responsibility.

### `Mcp-Param-*` routing/header smuggling

A client may provide a routing-optimized `Mcp-Param-*` value that differs from the JSON-RPC body, causing an intermediary or upstream system to route/authorize based on one value while the tool receives another.

**v0.3 control:** trusted `x-mcp-header` annotations are permitted only on statically reachable object properties with primitive `string`, `integer`, or `boolean` types. Required mirrors must appear exactly once; missing, duplicate, malformed, unexpected, or body-mismatched mirrors fail closed. Base64 sentinel values are decoded before comparison, and integer values are compared numerically.

### Unsafe `x-mcp-header` annotations

A catalog author may place an `x-mcp-header` on a number, array, composed schema, reference, or ambiguous dynamic location where exact extraction is not deterministic.

**v0.3 control:** annotations must be directly and statically reachable through `properties`, use a valid HTTP token name, be unique case-insensitively, and have primitive `string`, `integer`, or `boolean` type. Unsupported or ambiguous annotations make the catalog fail to load.

### Excessive agent authority

A model may attempt to send, delete, update, transfer, purchase, or deploy without a human reviewing the consequential action.

**Control:** consequential tool classes return `approval_required`. They are not forwarded without a valid signed receipt issued after operator authentication. The request must also satisfy its pinned trusted tool schema before an approval receipt can be issued.

### Approval substitution

An attacker may obtain approval for one request and change the tool, arguments, JSON-RPC ID, method, protocol version, or other request data before execution.

**Control:** the receipt contains an HMAC-SHA256 signature over claims that include the canonical SHA-256 fingerprint of the full `EvaluationInput`: protocol version, MCP method, MCP name, and JSON-RPC body. Any change invalidates verification.

### Approval replay

A valid receipt may be captured and submitted more than once to repeat a side effect.

**Control:** every issued receipt has a unique `jti` recorded in SQLite. Immediately before upstream dispatch the firewall atomically marks that receipt consumed. A second dispatch attempt fails closed.

### Approval after policy drift

A human may approve a request and an operator may then change policy before the request is dispatched.

**Control:** the receipt is bound to the current policy version. A policy-version mismatch invalidates the receipt and requires new review.

### Stale approval

A once-valid human decision may be used much later when context has changed.

**Control:** receipts have short expirations, a configurable maximum TTL, and a hard one-hour upper bound enforced by the verifier.

### Approval signing-key weakness or exposure

If an attacker learns the signing key, they can forge approval receipts.

**Control:** configured keys must be at least 32 bytes and are never returned by the API. Deployment must provide the key through a secret-management boundary. Key compromise remains a critical incident requiring rotation.

### Uncertain upstream outcome

The firewall may consume a receipt and then lose the network connection while the upstream tool may or may not have executed.

**Control:** the receipt is consumed before dispatch and remains spent after an uncertain outcome. The firewall does not automatically retry consequential actions with the same authorization. A fresh human approval is required.

### Dangerous tool classes

A server may expose shell, command execution, credential-export, or secret-oriented tools.

**Control:** explicit deny patterns override all other tool policy and cannot be bypassed by a catalog entry or approval receipt.

### Sensitive argument exfiltration

A tool call may contain secrets or protected filesystem targets.

**Control:** deterministic nested argument inspection rejects configured sensitive keys and protected path patterns before trusted-schema forwarding. Raw arguments are not written to the audit database.

### Prompt injection

Untrusted content may contain instructions intended to override the agent's task or cause unintended actions.

**Control:** prompt-injection-like text is recorded as a signal, never as the authorization primitive. Tool identity, argument policy, pinned schemas, protocol/header integrity, and human approval remain authoritative.

### Credential confused-deputy behavior

A caller may try to smuggle its authorization header to the upstream MCP server.

**Control:** caller authorization is not forwarded. Upstream bearer authentication is configured separately by the operator.

### Audit data leakage

Raw tool arguments can contain private or secret data.

**Control:** audit events store a SHA-256 fingerprint rather than the raw body. Approval state stores hashes and bounded metadata, not raw tool arguments. Schema failures report validator/path metadata without echoing raw argument values. Audit reads require a separate operator token.

### Resource exhaustion

A client may flood the gateway, send oversized bodies, or supply pathological trusted schemas.

**Control:** bounded request body size and a single-process sliding-window request limiter protect runtime requests; catalog size, schema node count, and schema depth are bounded at startup.

## Explicit non-goals / residual risk

- v0.3 is not a complete prompt-injection detector.
- the pinned trusted catalog is static local administrative state; secure remote distribution, signatures, and catalog rotation workflows are not implemented.
- the firewall does not dynamically trust or reconcile live upstream `tools/list` responses; schema drift detection against a live server is not yet implemented.
- a trusted schema constrains input shape but cannot prove benign upstream implementation semantics.
- v0.3 focuses on the `tools/call` trusted contract and `Mcp-Param-*` integrity; broader modern MCP metadata consistency surfaces remain future hardening.
- SQLite receipt consumption and the in-memory rate limiter are single-instance controls, not distributed coordination primitives.
- the approval issuer token is a shared-secret administrative baseline, not workload identity or phishing-resistant operator authentication.
- HMAC receipt signing uses one symmetric deployment key; key rotation / multi-key verification is not implemented yet.
- upstream tool outputs are not yet passed through an output-DLP or sanitization layer.
- there is no policy signature or remote policy distribution yet.
- there is no OPA/Rego engine yet.

## Next hardening milestones

1. OpenTelemetry trace export and low-cardinality policy-decision metrics
2. approval signing-key rotation with key IDs and bounded verification overlap
3. response-side DLP / untrusted-content labeling
4. shared receipt/rate-limit state for multi-replica deployments
5. optional OPA/Rego backend with deterministic local fallback
6. adversarial corpus derived from real MCP traces rather than only synthetic fixtures
7. broader protocol metadata consistency checks beyond the v0.3 `tools/call` boundary
