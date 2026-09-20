# Implementation execution workflow

This document records the workflow used for the initial implementation and the rules for later authorized work. It is not a current progress report. See [qualification](qualification.md) for recorded results and remaining test limits.

[SPEC.md](../SPEC.md) defines behavior. [IMPLEMENTATION-PLAN.md](../IMPLEMENTATION-PLAN.md) defines P0 through P11 deliverables and acceptance gates. Waves 0 through 7 below define who does the work and when. CT remains a required implementation with runtime use disabled by default.

- [Ownership and configuration](#1-ownership-and-configuration)
- [Preparation and handoff](#2-preparation-and-lane-handoff)
- [Wave assignments](#3-wave-assignments)
- [Validation and stopping rules](#4-validation-and-stopping-rules)
- [Effort and escalation](#5-effort-and-escalation)
- [Start an implementation task](#6-starting-a-future-implementation-task)

## 1. Ownership and configuration

The primary task is the working lead on `gpt-5.6-sol`. The lead owns the branch, implements difficult work, settles shared contracts, integrates commits, and validates each wave. Do not create a separate manager or supervisor task.

Use `medium` for routine integration. Use `high` for contracts, difficult implementation, concurrent state, security boundaries, aggregation, and integrated review. Select the actual model and effort in the client or invocation. Prose alone does not change runtime settings. If a required model is unavailable, report the constraint; do not silently substitute Astra.

| Responsibility | Model | Effort | Role or dispatch |
| --- | --- | --- | --- |
| Working lead and routine integration | `gpt-5.6-sol` | `medium` | Primary task; no supervisor role |
| Contracts, architecture, hard implementation | `gpt-5.6-sol` | `high` | Primary task, or `sol-implementer` for an assigned parallel lane |
| Bounded package/behavior implementation | `gpt-5.6-terra` | `medium` | `implementer` |
| Narrow repository/dependency research | `gpt-5.6-terra` | `low` | `explorer`, read-only |
| Wave 1 dependency/source audit | `gpt-5.6-terra` | `medium` | `dependency-auditor`, read-only |
| Bounded API implementation on settled contracts | `gpt-5.6-terra` | `high` | `api-implementer` |
| Mechanical fixtures, snapshots, wiring, docs | `gpt-5.6-luna` | `low` | `mechanical-worker` |
| Integrated correctness review | `gpt-5.6-sol` | `high` | `reviewer`, read-only |
| Integrated security/lifecycle review | `gpt-5.6-sol` | `high` | `security-reviewer`, read-only |
| One unresolved architecture/security question | `gpt-6-astra` | `high` | Explicit one-off dispatch; no persistent role or default |

Terra and Luna receive bounded assignments with settled contracts. Work spanning several packages must be split into bounded assignments. The lead retains decisions that affect other packages. The lead can implement the Sol lane directly when no useful independent work justifies another agent.

[Project configuration](../.codex/config.toml) sets defaults and limits. [Agent roles](../.codex/agents) hold reusable instructions. `AGENTS.md` holds stable engineering rules. This workflow does not change user-level settings.

The limit is two child agents in addition to the lead. Some waves permit fewer. Only the lead delegates; role files prohibit recursive delegation. Finish implementation lanes before starting their scheduled reviewer. Unused slots are not a reason to add agents.

Custom role settings take precedence over spawn defaults. Use `dependency-auditor` for the medium-effort audit and `api-implementer` for the high-effort API lane. Do not try to override the lower-effort roles indirectly. If the tool cannot select a role, supply its instructions and exact model and effort in the dispatch, then inspect the resolved settings. Read-only roles prohibit edits in their instructions as well as their sandbox settings.

Configuration behavior was checked against [official subagent documentation](https://learn.chatgpt.com/docs/agent-configuration/subagents) on 2026-09-20. [AGENTS.md guidance](https://learn.chatgpt.com/docs/agent-configuration/agents-md) covers stable repository instructions. The model assignments here are the user's project decisions.

## 2. Preparation and lane handoff

Before editing, record the starting revision, branch, and existing changes. Preserve unrelated work. Create a reviewed baseline before making isolated worker checkouts if no committed baseline exists. Use the `codex/` branch prefix unless the user specifies another name.

Use separate worktrees for concurrent lanes that return independent commits. Assign owned paths and a shared contract revision. Agents must not commit through the same index concurrently. Read-only reviews may use the integrated checkout.

Every dispatch includes:

- Wave, role, exact model and effort, and input revision.
- Owned paths and shared contract references.
- Acceptance cases and focused checks.
- Whether a local commit is required.

Workers do not push, deploy, or merge. The lead integrates local commits. Keep shared interface changes with the lead. When a lane finds a contract conflict, return the smallest concrete question before changing behavior across that boundary.

Each completed implementation lane returns one coherent commit, changed files, exact check results, changed contracts or `none`, and unresolved blockers. For work split into smaller assignments, the lead assembles the lane result. Researchers return findings with revisions and sources. Reviewers return concrete defects against the integrated revision.

## 3. Wave assignments

### Wave 0: confirm and record specification contracts

Owner: Sol lead, `high`. One agent total; no delegation.

The product decisions below are settled in SPEC 2.1. Check their consistency and record package-facing details in [architecture.md](architecture.md). Do not reopen settled decisions or count workflow setup as completed contract work.

| Contract | Settled requirement | SPEC sections |
| --- | --- | --- |
| DNS rebinding and mixed answers | Validate each address; start HTTP on an approved public address, dial it exactly with Host/SNI, continue remaining queries, and never dial prohibited addresses. Apply the same policy to redirects. | 3.4, 4.2, 5.2 |
| Source availability | Preserve useful evidence with partial coverage. Partial is HTTP 200/CLI 3; no necessary usable execution path is HTTP 503/CLI 4. No unavailable source becomes a successful no-match. | 7.4, 14.2 |
| Batch bundle retention | Persist pins at admission in coordination with pruning; protect queued/retrying targets across restart until all targets are terminal. Unpinned target attempts capture the active bundle at start. | 3.4, 12.2, 13.2 |
| Replay time and provenance | Reinterpret immutable captures using a selected bundle; distinguish consulted source records and times. Do not reconstruct historical ownership. | 9.1–9.5, 12.3 |
| CT verification | Record checkpoint-signature, continuity, and entry-inclusion checks independently. `verified_log` requires inclusion in an authenticated tree. | 10.1 |
| Access and cancellation | One shared trusted-operator model; shared results and cancellation; stable caller identity scopes idempotency, not tenant isolation. | 11.3–11.4, 12.2 |
| Minimum coverage | Product-and-relationship fixtures with justified unsupported signals; provider-only results cannot replace supported product identification. SPF uses `sending_authorization`. | 8.5, 9.1 |

Exit with a consistent contract record linked to the specification. Isolate any unresolved question. This document-only wave needs no implementation or `make check`.

After a focused Sol attempt, the lead may send one unresolved question and its relevant sections to Astra at `high`. Return to Sol after the decision.

### Wave 1: audit and domain contracts

At most two agents total: the Sol lead at `high` and one Terra `dependency-auditor` at `medium`.

The auditor reads selected dependencies, licenses, dataset formats, network side effects, and fixture assumptions. It returns exact revisions, hashes, and primary-source references. It does not edit dependencies or fixtures.

The lead owns observations, dataset records, evidence, findings, coverage, policy, errors, package boundaries, and serialization. It integrates the audit directly and performs required contract probes or fixture preparation. The lead also owns the early CT feasibility measurement under explicit budgets. Production CT remains in wave 6.

Coverage: P0 and P1. Do not freeze P1 interfaces until relevant P0 findings are resolved. There is no second review. Run focused contract checks during edits. If code or dependencies changed, run one `make check` after integration. For documents alone, validate the documents.

### Wave 2: first vertical fixture

Owner: Sol lead, `high`, alone. No delegation.

Build E1 from the smallest working parts of P3 through P7:

```text
domain -> controlled DNS -> controlled HTTP -> observations
       -> evidence -> findings -> coverage -> CLI JSON
```

Use real collection and classification code with a small pinned dataset. Test missing-source coverage and an approved public address arriving before delayed or failed AAAA. Include valid provenance and assertions that reject unsupported commercial claims.

Run focused tests during implementation. Once the slice works, run `make check` once and record the revision. E1 does not mark every P3 through P7 requirement complete.

### Wave 3: data and collection

Use two implementation lanes, with no more than two child agents. The lead may own the Sol lane directly.

| Lane | Model and effort | Role | Scope |
| --- | --- | --- | --- |
| Provider and service importers, indexes, bundles | Terra `medium` | `implementer` | P2 and P3, one bounded behavior at a time |
| DNS, destination policy, HTTP, redirects, TLS | Sol `high` | Lead or `sol-implementer` | P4 and P5, including dialing, cancellation, budgets, and network state |

The lead owns shared bundle-lifecycle design. Terra reports unresolved atomicity or ownership questions rather than inventing a contract. Each lane returns one coherent commit and its checks, contract changes, and blockers.

Integrate on Sol at `medium`, then run the cross-package fixture and `make check` once. If the full gate already includes that exact fixture, use its result instead of running it twice.

### Wave 4: rules, aggregation, and CLI

| Lane | Model and effort | Role | Scope |
| --- | --- | --- | --- |
| Rules, aggregation, strength, coverage | Sol `high` | Lead or `sol-implementer` | P6 and P7 analyzer behavior |
| CLI, report formatting, fixtures | Terra `medium` | `implementer` | Bounded P7 commands and supplied acceptance cases |

Evidence strength uses the specification's categories, not invented probabilities. After integration, run the first independent Sol `reviewer` at `high`. Supply the full domain-to-report path, revision, specification cases, and existing test evidence.

Apply actionable findings together. Rerun affected tests, then run the final `make check` once. Do not assign multiple reviewers to unchanged code. This wave completes P6 and P7 with P2 through P5 integrated.

### Wave 5: persistence, jobs, and API

| Lane | Model and effort | Role | Scope |
| --- | --- | --- | --- |
| PostgreSQL, reports, queue, leases, retries, pins | Sol `high` | Lead or `sol-implementer` | P8 storage and lifecycle |
| Endpoints, access, cancellation, authorization | Terra `high` | `api-implementer` | Bounded endpoints using settled contracts |

The Sol lead integrates at `high` and owns decisions where jobs, pins, identity, cancellation, and replay meet. Terra implements the shared-operator model; it does not redesign authorization.

Run one Sol `security-reviewer` at `high` over admission and pruning, restart and retry, stale commits, backlog, access, and persistence failures. Apply findings together, rerun affected tests, then run `make check` once.

Use Astra only for one unresolved authorization or lifecycle question after a concrete Sol attempt.

### Wave 6: certificate transparency

Owner: Sol lead, `high`, alone.

Keep CT behind its interface and configuration. Prove acquisition, checkpoint handling, and entry verification before adding production wiring. Complete P9 from the early P0 feasibility results.

Repeat throughput, bandwidth, retained-storage, and ingestion-lag measurements under explicit budgets. Test valid checkpoints paired with altered entry bytes. CT remains required for delivery and optional at runtime.

Run focused CT tests, then one `make check` after integration. If a focused attempt leaves inclusion verification, log state, or feasibility disputed, send that question to Astra at `high`. Do not request a whole-project reread or implementation. Return ownership to Sol afterward.

### Wave 7: operations and qualification

The Sol lead owns final integration and release review at `high`. Add support only when useful, with at most two agents:

- Luna `mechanical-worker`, `low`: manifests and routine documentation from approved requirements. Security-sensitive deployment decisions stay with the lead.
- Terra `implementer`, `medium`: bounded qualification fixtures with specified outcomes.

Complete P10, P11, R01 through R23 traceability, and the product-and-relationship matrix. Review the release candidate and integrate corrections before running the full validation pipeline once.

`make check` is part of that gate. Run required integration, no-egress, migration and recovery, deployment, CT, and qualification checks once if the gate does not already include them. Record unavailable checks and untested platforms. Publishing, pushing, and deployment still require authorization.

## 4. Validation and stopping rules

Workers run focused checks, including focused race tests for affected lifecycle code. They do not run `make check`. The lead owns repository-wide validation at the wave boundary.

`make check` includes formatting, vet, tests, GolangCI-Lint, skill integrity, SBOM validation, race tests, and the build. PostgreSQL integration requires a configured disposable test database. A passing build alone does not establish application acceptance.

| Wave | Full-gate point | Independent review |
| --- | --- | --- |
| 0 | None; validate contract document only | None; one-question escalation only if unresolved |
| 1 | One `make check` after code/dependency integration; skip for documents alone | None |
| 2 | One `make check` after E1 works | None |
| 3 | One `make check` after lane integration; include the cross-package fixture once | None |
| 4 | One final `make check` after review fixes and affected tests | One Sol correctness review |
| 5 | One final `make check` after security-review fixes and affected tests | One Sol security/lifecycle review |
| 6 | One `make check` after CT integration | One-question escalation only if unresolved |
| 7 | Full release-candidate pipeline once, including `make check` | Sol lead release review |

Repeat `make check` only after code or dependencies change, or when the previous run failed. For later document-only changes, validate the documents. Reuse successful checks from the same unchanged candidate.

Record the revision, commands, results, blockers, and accepted limits at each gate. Stop work on a wave after its acceptance gate passes. Continue only into work covered by the user's authorization. At the authorized endpoint, report results and stop without speculative cleanup, features, or extra reviews.

## 5. Effort and escalation

Start bounded implementation at `medium`. Use `low` for narrow discovery and mechanical edits. Use `high` for contracts, concurrent state, security, aggregation, integrated review, and the explicit lane assignments above. Do not routinely use `xhigh`, `max`, or `ultra`.

Escalate one task only after a failed attempt or unresolved contradiction. Supply the question, attempted approach, contract sections, evidence, and expected decision. Select `gpt-6-astra` at `high` explicitly. Do not add a persistent Astra role or default. Return to the assigned lower-cost model after the decision.

## 6. Starting a future implementation task

Select Sol at `high` for wave 0 or 1 contract work. For example:

```sh
codex --model gpt-5.6-sol -c 'model_reasoning_effort="high"'
```

Give the task its authorized scope, then refer to the workflow:

> Implement the assigned work according to IMPLEMENTATION-PLAN.md and docs/execution-plan.md. Remain the working lead on gpt-5.6-sol. Use high effort for contracts and difficult integration, and medium for routine integration. Delegate only at the named points, preserve concurrency limits, and record validation before proceeding.

This example does not authorize implementation by itself.
