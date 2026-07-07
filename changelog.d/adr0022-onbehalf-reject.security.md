- **On-behalf-of assertions are now rejected on every ingress surface
  (ADR-0022 Interim rules).** Five header/metadata names are reserved —
  `On-Behalf-Of`, `X-On-Behalf-Of`, `X-Yuzu-On-Behalf-Of`,
  `X-Yuzu-Delegated-Operator`, `X-Yuzu-Delegation-Artifact` (case-insensitive)
  — and any HTTP request carrying one (REST, MCP, dashboard, static, health)
  receives `403` with the A4 error envelope before authentication; a gRPC call
  carrying one as a metadata key is cancelled at a server interceptor. Nothing
  previously consumed these headers, so no legitimate integration breaks — but
  an integration *testing* a delegation header will now see the rejection.
  Server-verifiable delegation arrives with the ADR-0022 auth follow-up;
  client-asserted delegation stays rejected permanently. Rejections are
  counted in the new `yuzu_onbehalf_rejected_total{surface,event="security"}`
  metric (log lines are throttled; the counter records every event).
