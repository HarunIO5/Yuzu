---
status: draft
date: 2026-07-06
owner: Dave Rae
scope: execution plan — phased program + first use-case-engine module scoping
---

# ADR-0022 Execution Plan — Program Ladder + Vulnerability-Management Module Scoping

This document is the execution plan for [ADR-0022](adr/0022-headless-platform-use-case-engines.md) (PR #1918): headless platform, use-case engines, agentic-first as a core principle. It is **not** an ADR — it does not make new binding architectural decisions; it sequences ADR-0022's decisions into a phased program and works out the detailed scoping of the first use-case engine (UCE) module, vulnerability management, which re-homes the shipped server-side NVD sync + CVE matching (ADR-0022 grandfathered surface #2).

Two items below are flagged as candidates for their own future ADRs rather than settled here: the UCE host stack/runtime choice (deferred pending a requirements doc) and the auth-architecture delegation follow-up (ADR-0022's own named prerequisite).

**Assumption:** this plan assumes ADR-0022 is accepted (independent review + tracking issue + status flip, handled separately).

## Decision log

These decisions resolve open scoping questions ADR-0022 deliberately left to "first module scoping" (Decision 6) and the execution sequencing it leaves to a follow-up program. None override or amend ADR-0022 itself.

1. **v1 vuln module is read-only against the server.** Write-back/orchestration (result-set materialization by the engine, remediation dispatch) waits for ADR-0022 Decision 5 delegation to ship.
2. **Hand-off seam included:** the module's findings page hands off a device cohort as a **server-side object created via the server's public API, under the operator's own session** (e.g. a result set) — actionable from the dashboard and by agentic workers alike. Never a GUI-only copy-paste hand-off, never a write performed with engine credentials.
3. **Consumer model:** agentic workers and orchestrators (e.g. a ServiceNow-style integration) consume the **Yuzu server directly** over REST/MCP and compose their own interpretation from server primitives. **No machine consumer of the UCE exists in this scoping** — the UCE's only external interface is its human UI. The UCE-host UI ↔ UCE-host backend seam is private (one product); ADR-0022's parity/discoverability obligations discharge at the *server* surface, not inside the UCE.
4. **Scale target:** build for 2,000 devices, **design for up to 500,000**.
5. **Catalogue-grain join; no fleet-inventory replica in the engine.** The module never syncs a copy of per-device installed-software inventory. Cycle: sync CVE feeds → match feed data against the server's `software_catalog` rollup (distinct name/version pairs — on the order of 10–50k entries even at 500k devices) → expand only the *matched* entries to affected devices via `query_software(name)` → persist **findings only**. This keeps egress at O(catalogue) + O(hits) instead of O(fleet), and removes bulk changed-since delta sync from this module's critical path.
6. **The UCE host owns one shared fleet-data access layer**, used by every module (vulnerability management now; software asset management and others later) — API-backed reads, cached, request-paced against a single shared budget toward the server. Modules store only their own derived domain state (findings, license positions, etc.), never a fleet copy. The interface is designed so a synced replica could be introduced behind it later; the trigger for that is a module demonstrating a genuine need for device-grain data residency, not module count.
7. **NVD re-home is a strangler migration, not a code move.** The UCE module builds and proves its own feed-ingest + matcher first; a parity gate (module output == existing `POST /api/nvd/match` output on a reference inventory) precedes any server-side deletion. **No `/api/v1/nvd/*` twin is built** on the server — the existing capability has no REST-versioned or MCP twin today, and building one would freeze the interpretation logic into the platform contract at the exact moment it's being extracted. The gap closes by removing the capability, not by twinning it.
8. **Agent-side `vuln_scan` plugin:** the `inventory` collection action and the generic rule-evaluation / content-delivery plumbing stay core (mechanism, per ADR-0022 Decision 2). The plugin's embedded static `cve_rules.hpp` CVE list and its use as an authoritative `cve_scan` finding source are **frozen (no further rule updates) and marked deprecated**. The long-term replacement is engine-published content delivered through the existing content-distribution plane — the ruleset becomes engine-authored content evaluated by the agent's existing generic engine, which is cleanly mechanism-side.
9. **Postgres migration interplay:**
   - ADR-0022 Decision 5's audit-row fields (engine principal id, `is_delegated`, delegated operator identity, delegation artifact id, `delegation_verification_status`) are added when `AuditStore` migrates to Postgres (PG migration-ladder Wave 1, already a mandatory-backfill item), rather than via an SQLite `ALTER TABLE` now — no producer can emit these fields correctly before the delegation phase ships, so there is nothing to gain from an earlier, throwaway schema change. If Wave 1 slips past the delegation phase, an additive SQLite column is the fallback.
   - The engine-principal class does **not** wait for `RbacStore`'s later Postgres migration wave — adding an `engine` value to `principal_type` is additive on either substrate. **`ApiTokenStore`'s Postgres migration is pulled forward** to precede the engine-principal work, since it is already marked unblocked-to-migrate and engine credentials are semantically new rows worth being born on Postgres rather than migrated later.
10. **The API versioning/deprecation policy is written early, in parallel with the auth follow-up — not gated behind it.** The two items gate different things (external credential issuance vs. principal existence), and ADR-0021 is landing new API surface now that needs a published compatibility posture regardless of delegation's timeline. MCP tool versioning follows the same posture as REST: additive-only evolution, with a versioned tool name (e.g. `query_software_v2`) only on a breaking change — no per-tool semver scheme.
11. **UCE host stack is deferred** until a committed requirements document exists; the runtime/language choice is then made via its own review (ADR-worthy: hard to reverse, a real trade-off, and will surprise a future reader without the context). What is decided now: the UCE host's data layer is **its own Postgres database**, never the server's connection pool (ADR-0022 Decision 3 — no new private seam, no shared database access). Location is **inside the Yuzu repository**, under `engines/` (`engines/host`, `engines/modules/vuln`), shipped as a separate deployable artifact from `yuzu-server`, with CI enforcing that nothing under `engines/` includes or links against `server/` code.
12. **Naming:** "UCE" is adopted as the canonical abbreviation for *use-case engine* (ADR-0022 already reserves bare "engine" for internal components); "UCE host" is the deployable. The source directory stays the plain-English `engines/`.
13. **Deferred out of this scoping** (tracked, not lost):
    - Everything delegation-dependent: engine-initiated write-back, result-set materialization by the engine itself, remediation dispatch, quota mechanisms beyond the minimum interlock.
    - Streaming/durable event-subscription egress — evaluated against the batch-join alternative per ADR-0022 Decision 6's mandate, and deferred in favor of batch-join (see Module scoping, egress decision, below).
    - Bulk changed-since delta sync (`/changes`-style endpoint) — removed from this module's critical path by the catalogue-grain join (decision 5); revisited only if a future module proves a device-grain residency need.
    - The vulnerability graph differentiator (topology, trust zones, attack-path scoring) — its own future scoping, with its own core-vs-engine boundary analysis.
    - Agent-side KEV pre-filter as engine-published content — waits on the module producing an authoritative ruleset.
    - SBOM ingest (roadmap 18.5) and compliance-framework report bundles (roadmap 18.2) as separate future modules.
    - Scope-aware `software_catalog` rollup — stays on its existing tracked issue; not a blocker for this module, since the module computes its own rollups from synced findings.
    - Server-only topology support-matrix implications, BYO-engine conformance/assurance package, published SLO numbers, dashboard-migration sequencing — placeholder tracking only, per ADR-0022's explicit "no migration scheduled" stance.
    - **Tripwire:** if any future module version syncs per-user or behavioral data, ADR-0022 Decision 5's bulk-PII security-guardian review triggers at that point. The v1 dataset (installed-software inventory) is machine-scope only and does not trigger it today.

## Program ladder

Critical path: **auth-architecture follow-up design → engine-principal class → delegation**. The widest parallelism is in Phase 2, which has four independent tracks.

```
P0 (docs) ──► P1 (interlocks) ─┐
   ├──► 2a versioning policy ───┼──────────────► gates external creds (P8)
   ├──► 2b auth follow-up design ──► P4 principals ──► P5 delegation ─► P6 ─► P7
   ├──► 2c UCE requirements + stack ADR ───────► P6
   └──► 2d module domain half (M1–M4, longest) ─► P7 parity gate
        PG Wave 1 audit + decision-9 fields = P3 ──► P5
```

### Phase 0 — Governance & doc wiring (docs-only, starts immediately)

- **PR 0.1 — governance wiring.** Add the ADR-0022 standing review question ("is every behavior of this capability reachable via versioned REST *and* MCP, or a recorded exception; discoverable; carrying the A4 error envelope; RBAC/audit enforced at the API?") to `.claude/skills/governance/SKILL.md` — the consistency-auditor Gate 4 preamble and the Gate 3 trigger matrix — plus a new/extended routed-concerns row in `CLAUDE.md` citing ADR-0022 and its exception ledger.
- **PR 0.2 — doc fan-out.** "Hardened by ADR-0022" note on A1 in `docs/agentic-first-principle.md` (a fragment endpoint is not a twin; both REST and MCP required); `CONTEXT.md` glossary entries for engine principal, use-case engine host (UCE), first-party UI, admin console, operator; `docs/capability-map.md` 9.4 grandfather note plus a `vuln_scan` embedded-rules freeze note; `docs/roadmap.md` annotations (11.1 ConsumerStore marked superseded by ADR-0022; 17.4 marked absorbed into the auth follow-up; 18.1 marked as re-homing into the UCE module; 18.2/18.5 marked boundary-affected); a reconciliation stanza in `docs/vuln-scan-engine-design.md` noting its server-side placement is superseded by ADR-0022 while its domain content (matcher quality bar, phased roadmap) stands.

### Phase 1 — Interim interlocks (2 small code PRs + 1 tracking issue)

- **PR 1.1 — reject on-behalf-of assertions.** Define the reserved header/field names and reject (not silently ignore) any such assertion at the single pre-routing chokepoint in `server/core/src/server.cpp`, returning the A4 error envelope and citing ADR-0022. Covers both REST and MCP paths, since both pass through the same chokepoint.
- **PR 1.2 — `principal_class` metric label** (`human` / `agent` today, `engine` reserved) on the HTTP request-count metric, with the class resolved and stashed during pre-routing.
- **Issue 1.3 — per-principal quota interlock tracker.** ADR-0022's interim rules block any engine principal from production until a minimum per-principal concurrency/quota cap exists; today's rate limiter is per-IP only. This issue is the tracked blocker for that gap; it closes when Phase 4's minimum cap ships.

### Phase 2 — Parallel tracks

- **2a — API versioning/deprecation policy (docs).** Promote the existing REST-only versioning statement into a formal cross-surface policy: versioning mechanics, additive-preferred posture, deprecation cycle length, and MCP tool versioning per decision 10. Gates external engine credential issuance and is cited by the NVD deprecation cycle (Phase 7).
- **2b — auth-architecture follow-up design.** Delegation token-exchange mechanics, principal granularity (per-module vs. per-host), credential lifetime/rotation ceilings, the change to token-session attribution needed for engine principals (today a service token's session is attributed to its human creator), the self-target-guard extension, and MCP tier applicability to engine principals. This is the program's critical-path deliverable.
- **2c — UCE host requirements doc**, capturing decisions 2–6 and 11–12 as functional/non-functional requirements; a stack ADR follows as its own PR once the requirements doc is settled.
- **2d — vuln module domain-logic half** (the module's longest-running, most independent track — buildable now per ADR-0022 Decision 6's "domain-logic half can start immediately" carve-out): see Module scoping below for the milestone breakdown (M1–M4).

### Phase 3 — Audit substrate

`AuditStore`'s Postgres migration (ladder Wave 1, mandatory backfill) carries decision 9's audit-row fields born into the target schema, with the corresponding `AuditEvent` struct extension landing with defaults only (no producers change yet).

### Phase 4 — Engine principal class

Gated on Phase 2b's design being accepted.

- **PR 4.1** — `ApiTokenStore` migrates to Postgres (pulled forward per decision 9).
- **PR 4.2** — introduce the `engine` RBAC principal type and a machine principal class on `Session`; engine token sessions attribute to the engine principal itself, not the creating human.
- **PR 4.3** — engine-principal lifecycle surface (create/rotate/revoke, named responsible human owner, least-privilege grants) on both REST and MCP, plus an admin-console page composing that API.
- **PR 4.4** — minimum per-principal concurrency/quota cap, closing Issue 1.3.
- **PR 4.5** — `principal_class=engine` becomes a live metric value.

### Phase 5 — Delegation

Gated on Phase 3 (audit shape) and Phase 4 (principals exist). Server-issued delegation artifact and verification (an engine-*asserted* delegation is rejected permanently, at every point in this program); effective authority computed as permissions ∩ scope through the existing ADR-0017 list-read chokepoint; self-target destruction guards re-keyed on the effective delegated identity; audit producers begin emitting the decision-9 fields, with pre-enforcement rows carrying `delegation_verification_status=unverified` per ADR-0022's incremental-shipping rule.

### Phase 6 — Module moves to engine auth

The vuln module switches from a plain API token to engine-principal credentials with least-privilege grants (explicitly not the union-of-permissions pattern of the existing ServiceNow integration). Keyset pagination on the fleet-wide software query (existing tracked gap) lands as an ordinary authenticated-read improvement, decoupled from engine auth and useful to every consumer.

### Phase 7 — NVD re-home surgery (server-side strangler)

- **PR A** — extract the pure `compare_versions()` helper out of the NVD store into a standalone core utility (it has two existing internal consumers and is mechanism, not interpretation — it stays in the server permanently).
- **PR B** — deprecation marks on the three legacy `/api/nvd/*` routes, plus a settings-fragment banner and a capability-map note, following the Phase 2a policy's announced cycle.
- **PR C** — remove the inert vulnerability-overlay seam in the fleet-visualization store (a dead private pointer into the NVD store; ADR-0022 Decision 3 forbids new private seams, and a dead one invites exactly that).
- **PR D** — deprecate the NVD CLI flags; default the sync off. Ships alongside PR B.
- **PR E** — after the module's parity gate (M3) passes and the deprecation window closes: delete the NVD store, client, and sync-manager source, their routes, the settings fragment, and the CLI flags; record the grandfathered surface's retirement in the ADR-0022 exception ledger.

### Phase 8 — Pre-GA gates

Capacity/isolation evaluation for API-serving load sharing the agent control plane's connection pool; the full (beyond-minimum) quota mechanism; an external-credential go/no-go checklist (versioning policy published, quota cap live, delegation verified); placeholder tracking issues for the remaining deferred-ledger items (decision 13).

## Module scoping — vulnerability management (first UCE module)

### What re-homes

The shipped server-side NVD sync + CVE matching capability (capability-map 9.4): its feed client, its sync manager, its CVE store, its three legacy un-versioned routes, its settings-fragment UI, and its four CLI flags. Consumption today is limited to the match route itself and an inert fleet-visualization overlay seam — coupling is shallow, which is what makes the strangler extraction (Phase 7) tractable as a small, independently-gated PR sequence.

### What stays core

The agent-side `vuln_scan` plugin's collection action, per decision 8 — with its embedded static rule list frozen and deprecated rather than carried forward.

### Module milestones (Phase 2d / 2c's longest track)

- **M1** — UCE host skeleton (server-API client with a min/max supported server-API version handshake, a sync scheduler, the shared fleet-data access layer from decision 6, a UI shell) plus NVD 2.0 feed sync with a watermark, landing in the module's own Postgres. *Acceptance: CVE count and watermark match a server-side sync over the same window.*
- **M2** — catalogue-grain inventory join per decision 5: read the fleet-wide software catalogue plus per-name device expansion, over a plain API token, autonomous reads only, request-paced. *Acceptance: the module's catalogue snapshot matches server reads for a pilot fleet.*
- **M3** — matcher parity, a findings store with a triage lifecycle (new / triaged / accepted-risk / remediated / reopened), findings UI, and the operator hand-off seam from decision 2. *Acceptance: identical match output to the existing server-side match route on a reference inventory — this is the re-home gate that authorizes Phase 7 PR E.*
- **M4** — surpass parity: real package/version identity matching, version-range evaluation, additional feed sources for reduced false positives. *Acceptance: a fully-patched reference OS image reports zero package-level CVEs.*

### Egress-primitive decision

ADR-0022 Decision 6 requires evaluating at least two consumer archetypes even if only one ships.

- **Batch-join** (changed-since reads over the catalogue rollup plus per-name device expansion): matches the module's actual data cadence — CVE feeds update on an hourly-to-daily cycle, and per-agent inventory changes at most once a day. At the 500,000-device design ceiling, catalogue-grain access keeps this to tens of thousands of rows per cycle, not a fleet-wide scan.
- **Streaming** (a durable, replayable event subscription on inventory or catalogue mutations): evaluated and **not selected for v1** — it would add a new durable-log/retention/backpressure subsystem for data that does not benefit from sub-daily latency in this module, and would reintroduce gap-detection/replay-horizon complexity that batch-join avoids by construction.

Decision: **batch-join ships**; streaming is deferred, not rejected, and nothing in this plan precludes adding it later behind the same shared fleet-data access layer (decision 6) if a future module demonstrates a genuine latency need.

## Verification

- **Phase 0:** a governance dry run on a synthetic capability-adding diff confirms the standing review question fires in Gate 3/4 output.
- **Phase 1:** a request carrying a reserved on-behalf-of header receives the A4 rejection envelope on both REST and MCP; the HTTP request metric shows the correct `principal_class` value for a browser session vs. an agent-daemon call.
- **Phase 2d:** milestone acceptance criteria as listed above (M1 watermark parity, M2 catalogue parity, M3 matcher parity against the existing match route).
- **Phase 4/5:** an engine token's session attributes to the engine principal (not its creator) in audit rows; a delegated read on behalf of a group-confined operator returns only that operator's groups; the self-target guard blocks an engine from acting against its own delegated operator's account.
- **Phase 7 PR E:** full server test suite passes; the server boots and reaches a healthy `/readyz` with no NVD flags set and no UCE reachable (confirms the server-only topology posture is preserved).
- Every server-side code change in this program runs the full governance pipeline per repository policy; no push or PR proceeds without explicit confirmation.
