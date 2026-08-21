# Threat model — MCP Agent Firewall v0.2

## Assets to protect

- downstream MCP tools and the external side effects they can cause
- credentials used by the upstream MCP server
- user data present in tool arguments
- human approval authority
- approval-signing key material
- audit integrity and traceability

## Trust boundaries

1. **Agent/MCP client → firewall**: untrusted. The client may be confused, compromised, or influenced by prompt injection.
2. **Firewall policy configuration**: trusted administrative input.
3. **Approval issuer operator**: trusted human/operator interface authenticated separately from the MCP caller.
4. **Approval signing key**: trusted deployment secret held only by the firewall.
5. **Firewall SQLite state**: trusted single-instance state for audit and one-time receipt consumption.
6. **Firewall → upstream MCP server**: trusted transport target configured by deployment, never by the incoming request.
7. **Tool output → agent**: untrusted content. v0.2 does not yet sanitize upstream responses beyond transport pass-through.

## Primary threats

### Header/body smuggling or mismatch

An attacker may present benign `Mcp-Name` / `Mcp-Method` headers while asking the JSON-RPC body to execute a different operation.

**Control:** exact header/body consistency checks fail closed before forwarding.

### Excessive agent authority

A model may attempt to send, delete, update, transfer, purchase, or deploy without a human reviewing the consequential action.

**Control:** consequential tool classes return `approval_required`. They are not forwarded without a valid signed receipt issued after operator authentication.

### Approval substitution

An attacker may obtain approval for one request and change the tool, arguments, JSON-RPC ID, method, protocol version, or other request data before execution.

**v0.2 control:** the receipt contains an HMAC-SHA256 signature over claims that include the canonical SHA-256 fingerprint of the full `EvaluationInput`: protocol version, MCP method, MCP name, and JSON-RPC body. Any change invalidates verification.

### Approval replay

A valid receipt may be captured and submitted more than once to repeat a side effect.

**v0.2 control:** every issued receipt has a unique `jti` recorded in SQLite. Immediately before upstream dispatch the firewall atomically marks that receipt consumed. A second dispatch attempt fails closed.

### Approval after policy drift

A human may approve a request and an operator may then tighten or otherwise change policy before the request is dispatched.

**v0.2 control:** the receipt is bound to the current policy version. A policy-version mismatch invalidates the receipt and requires new review.

### Stale approval

A once-valid human decision may be used much later when context has changed.

**v0.2 control:** receipts have short expirations, a configurable maximum TTL, and a hard one-hour upper bound enforced by the verifier.

### Approval signing-key weakness or exposure

If an attacker learns the signing key, they can forge approval receipts.

**v0.2 control:** configured keys must be at least 32 bytes and are never returned by the API. Deployment must provide the key through a secret-management boundary. Key compromise remains a critical incident requiring rotation.

### Uncertain upstream outcome

The firewall may consume a receipt and then lose the network connection while the upstream tool may or may not have executed.

**v0.2 control:** the receipt is consumed before dispatch and remains spent after an uncertain outcome. The firewall does not automatically retry consequential actions with the same authorization. A fresh human approval is required.

### Dangerous tool classes

A server may expose shell, command execution, credential-export, or secret-oriented tools.

**Control:** explicit deny patterns override all other tool policy and cannot be bypassed by an approval receipt.

### Sensitive argument exfiltration

A tool call may contain secrets or protected filesystem targets.

**Control:** nested argument inspection rejects configured sensitive keys and protected path patterns. Raw arguments are not written to the audit database.

### Prompt injection

Untrusted content may contain instructions intended to override the agent's task or cause unintended actions.

**Control:** prompt-injection-like text is recorded as a signal, never as the authorization primitive. Tool identity, argument policy, protocol integrity, and human approval remain authoritative.

### Credential confused-deputy behavior

A caller may try to smuggle its authorization header to the upstream MCP server.

**Control:** caller authorization is not forwarded. Upstream bearer authentication is configured separately by the operator.

### Audit data leakage

Raw tool arguments can contain private or secret data.

**Control:** audit events store a SHA-256 fingerprint rather than the raw body. Approval state stores hashes and bounded metadata, not raw tool arguments. Audit reads require a separate operator token.

### Resource exhaustion

A client may flood the gateway or send oversized bodies.

**Control:** bounded body size and a single-process sliding-window request limiter.

## Explicit non-goals / residual risk

- v0.2 is not a complete prompt-injection detector.
- SQLite receipt consumption and the in-memory rate limiter are single-instance controls, not distributed coordination primitives.
- the approval issuer token is a shared-secret administrative baseline, not workload identity or phishing-resistant operator authentication.
- HMAC receipt signing uses one symmetric deployment key; key rotation / multi-key verification is not implemented yet.
- dynamic `Mcp-Param-*` validation is not implemented because it requires trusted tool-schema knowledge.
- upstream tool outputs are not yet passed through an output-DLP or sanitization layer.
- there is no policy signature or remote policy distribution yet.
- there is no OPA/Rego engine yet.

## Next hardening milestones

1. schema-aware `Mcp-Param-*` validation from a pinned trusted tool catalog
2. signing-key rotation with key IDs and bounded overlap
3. response-side DLP / untrusted-content labeling
4. OpenTelemetry trace export and policy-decision spans
5. shared receipt/rate-limit state for multi-replica deployments
6. optional OPA/Rego backend with deterministic local fallback
7. adversarial corpus derived from real MCP traces rather than only synthetic fixtures
