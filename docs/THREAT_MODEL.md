# Threat model — MCP Agent Firewall v0.1

## Assets to protect

- downstream MCP tools and the external side effects they can cause
- credentials used by the upstream MCP server
- user data present in tool arguments
- human approval authority
- audit integrity and traceability

## Trust boundaries

1. **Agent/MCP client → firewall**: untrusted. The client may be confused, compromised, or influenced by prompt injection.
2. **Firewall policy configuration**: trusted administrative input.
3. **Human approval token**: trusted only when supplied out-of-band by an operator-controlled interface.
4. **Firewall → upstream MCP server**: trusted transport target configured by deployment, not by the incoming request.
5. **Tool output → agent**: untrusted content. v0.1 does not yet sanitize upstream responses beyond transport pass-through.

## Primary threats

### Header/body smuggling or mismatch

An attacker may try to present a benign `Mcp-Name`/`Mcp-Method` to the gateway while asking the body to execute a different operation.

**v0.1 control:** exact header/body consistency checks fail closed before forwarding.

### Excessive agent authority

A model may attempt to send, delete, update, transfer, purchase, or deploy without a human reviewing the consequential action.

**v0.1 control:** consequential tool-name classes return `approval_required`; they are not forwarded unless a separate operator-controlled approval token is present.

### Dangerous tool classes

A server may expose shell, command execution, credential-export, or secret-oriented tools.

**v0.1 control:** explicit deny patterns override all other tool policy.

### Sensitive argument exfiltration

A tool call may contain secrets or protected filesystem targets.

**v0.1 control:** nested argument inspection rejects configured sensitive keys and protected path patterns. Raw arguments are not written to the audit database.

### Prompt injection

Untrusted content may contain instructions intended to override the agent's task or cause unintended actions.

**v0.1 control:** prompt-injection-like text is recorded as a signal, but never becomes the authorization decision. Tool identity, argument policy, protocol integrity, and human approval remain authoritative. This avoids treating regex detection as a complete injection defense.

### Credential confused-deputy behavior

A caller may try to smuggle its authorization header to the upstream MCP server.

**v0.1 control:** caller authorization is not forwarded. Upstream bearer authentication, when needed, is configured separately by the operator.

### Audit data leakage

Raw tool arguments can contain private or secret data.

**v0.1 control:** audit events store a SHA-256 fingerprint of the canonical request instead of the raw body. Audit reads require a separate operator token.

### Resource exhaustion

A client may flood the gateway or send oversized bodies.

**v0.1 control:** bounded body size and a single-process sliding-window request limiter.

## Explicit non-goals / residual risk

- v0.1 is not a complete prompt-injection detector.
- the in-memory rate limiter is not globally consistent across replicas.
- the approval token is a baseline, not workload identity or signed approval.
- dynamic `Mcp-Param-*` validation is not implemented because it requires trusted tool-schema knowledge.
- upstream tool outputs are not yet passed through an output-DLP/sanitization layer.
- there is no policy signature or remote policy distribution yet.
- there is no OPA/Rego engine yet.

## Next hardening milestones

1. signed, expiring approval receipts bound to request hash + tool + arguments
2. schema-aware `Mcp-Param-*` validation from a pinned trusted tool catalog
3. response-side DLP / untrusted-content labeling
4. OpenTelemetry trace export and policy decision spans
5. shared rate limiting for multi-replica deployments
6. optional OPA/Rego backend with deterministic local fallback
7. adversarial corpus derived from real MCP traces rather than only synthetic fixtures
