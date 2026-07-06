# ADR-0022: Yuzu Server is a Headless Platform; Use-Cases Live in External Engines

- **Status:** Proposed (draft — under discussion)
- **Date:** 2026-07-06
- **Deciders:** Dave Rae
- **Related:** ADR-0021 (Spark/Reflex architecture), `docs/agentic-first-principle.md` (A1–A4), `docs/auth-architecture.md`

## Context

Yuzu's goal is use-case-agnostic scaffolding for an IT estate: highly performant primitives for query, command, detection, enforcement, and inventory across a fleet. The Spark/Reflex rebuild (ADR-0021) is already re-founding the detection/action kernel on use-case-agnostic terms.

Customers, however, expect a GUI and pre-packaged use-cases (vulnerability management, compliance reporting, software asset management, …). Building those into the server would pull domain semantics — NVD feeds, CVE matching, scoring, dashboards — into the C++ core, coupling its release cadence to interpretation logic that churns on a different clock, and privileging our own UI over the agentic workers the platform is designed for.

The agentic-first principle (A1: dashboard parity) already requires every dashboard capability to have an API twin. This ADR takes the next step: the server is *headless by design*, and every consumer — including our own UI — is an external client of the same versioned surface.

## Decision

### 1. Agentic first is a core principle

The server is designed to be driven by agentic AI as a first-class operator — MCP and REST are the primary control surfaces, not an integration afterthought. Every capability must be **discoverable, invocable, and observable** by an agentic worker without human mediation, with honest machine-readable error envelopes. This elevates the existing agentic-first invariants (A1–A4, `docs/agentic-first-principle.md`) from a per-surface checklist to a founding principle of the platform: humans with a GUI and agentic workers are peer classes of operator, and no capability may favour one over the other.

### 2. The Yuzu server is a headless, use-case-agnostic platform

The server owns **mechanism, not interpretation**: device registry and transport, instruction/Spark/Reflex engines, scope, RBAC, audit, response and inventory stores, content plane, and the REST/MCP/event surfaces that expose them. It contains no use-case domain logic (no CVE analysis, no compliance framework semantics, no domain-specific scoring).

**Boundary test** for any proposed feature: *does it collect/enforce/transport facts about the estate (mechanism → core), or does it interpret those facts for a purpose (interpretation → use-case engine)?* Agent-side capability is always mechanism. Analysis joining fleet data with external data (e.g. NVD) is always interpretation.

### 3. All consumers are external principals on the versioned API

Use-case engines, agentic AI workers, automation scripts, and Yuzu's own first-party console all consume the server through the same versioned REST/MCP surface, as authenticated principals subject to RBAC, audit, and (future) rate limits. No consumer — first-party included — gets a private seam: no shared database access, no co-deployment assumption, no linked-in shortcut.

A customer may point their own use-case engine, or their own agentic AI, at the server. Our first-party console must therefore prove the API surface is complete: **if our UI needs a capability, it becomes an API first.**

### 4. No UI-only capabilities

Effective immediately and permanently: no capability may exist that is reachable only through a UI. This strengthens A1 from "dashboard capabilities must have API twins" to "UIs may only compose public APIs."

### 5. Consumer trust tier: engine principals with on-behalf-of delegation

The principal model gains a third class alongside human operators and agent daemons: **engines** — long-lived service principals representing a use-case engine or agentic worker.

- Engines authenticate with their own credentials and carry their own RBAC grants.
- When an engine performs an action initiated by a human (e.g. an operator clicks "remediate" in a vuln console), it acts **on behalf of** that operator. The audit record captures both identities: *engine X acting for operator Y*. Actions the engine initiates autonomously audit as the engine alone.
- The server's RBAC remains the **single authority** over fleet actions. Engines may implement their own internal UI-level authorization, but nothing an engine does can exceed what the server grants its principal (and, for delegated actions, the intersection with the operator's grants).

The concrete token/delegation mechanism (token exchange, scoped sub-tokens, …) is deferred to an auth-architecture follow-up; this ADR fixes the requirement and the audit shape.

### 6. First-party use-case engine: one host, many modules

Yuzu's own GUI/use-case product is a single **use-case engine host** (auth delegation, server-sync plumbing, UI shell) hosting use-cases as modules — vulnerability management first (NVD ingest + join against Yuzu software inventory). Separate apps per use-case would reinvent that plumbing each time. The host's technology stack, internals, and delivery are out of scope here and will be decided when the first module is scoped.

### 7. Thin built-in admin console remains on the server

Headless does not mean zero UI. The server keeps a **minimal admin console** for platform operations — the things you need before/without any engine: enrollment and device liveness, health/readiness, RBAC and principal management, settings, audit view. It is a bootstrap/break-glass surface, not a product UI, and it obeys rule 4: it composes the same public APIs.

The existing full dashboard remains in place and maintained until a migration/implementation plan for the first-party engine is established (strangler expected, not big-bang). This ADR schedules no migration, but the direction is decided: the product UI's long-term home is the use-case engine, and the in-server dashboard shrinks toward the thin admin console above.

## Out of scope (deliberately deferred)

- **Egress primitives** (durable/replayable event subscription, changed-since bulk sync for engines). Anticipated, but not committed here; design waits for concrete demand from the first engine module. ADR-0021 work should avoid *precluding* external subscription in event-spine shapes, without building for it.
- Use-case engine host stack, packaging, and repo layout.
- Dashboard migration sequencing.
- Delegation token mechanics (auth follow-up).
- Consumer rate limiting / quota design.

## Consequences

- **API surface becomes a product contract.** New REST/MCP surface added from now on (including during the ADR-0021 rebuild) is designed as externally consumable: versioned, discoverable, honest error envelopes (A2–A4).
- **Governance gains a standing review question** for every new server surface: *"could an external engine consume this exactly as our UI does?"* A capability answerable only "no" is a design defect.
- **Guardian/DEX and similar consumers** split along the boundary test over time: engines/stores/wire stay core; interpretation layers and domain dashboards are future engine-module territory. No migration is scheduled by this ADR, but **migrating in this direction is the declared intent** — new work on these consumers should move toward the boundary, not deepen coupling to core.
- **Ship shape (eventual):** headless `yuzu-server` (with thin admin console) as a supported standalone deploy; first-party engine as a separate artifact customers may take, replace, or omit.
- **Works-council / SOC 2 posture improves:** one audit chokepoint records every actor — human, agent, engine, or engine-for-human.
