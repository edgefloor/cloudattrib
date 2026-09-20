# Implementation execution workflow

Status: prepared, not started. This document and the project agent configuration establish how future implementation runs. They do not authorize starting a wave, downloading project datasets, changing application code, or launching implementation agents. Begin only after an explicit instruction to implement.

[SPEC.md](../SPEC.md) defines behavior. [IMPLEMENTATION-PLAN.md](../IMPLEMENTATION-PLAN.md) defines P0–P11 deliverables and acceptance gates. Waves 0–7 below define the execution order and ownership across those deliverables. They preserve the full scope, including CT implementation with CT disabled by default at runtime.

## 1. Ownership and configuration

The primary task is the working integrating lead on `gpt-5.6-sol`. It owns the implementation branch, implements hard work, resolves contracts, integrates lane commits, and runs wave-level validation. Do not create a separate manager or supervisor task.

Use `medium` for routine lead integration and `high` for contract design, difficult implementation, concurrent state, security boundaries, aggregation, and integrated review. The project config defaults the primary model to Sol at medium effort. Select the appropriate model/effort in the client or invocation before a phase requiring another setting; prose instructions alone do not establish that runtime settings changed. If the required model is unavailable, report that constraint instead of silently substituting Astra.

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

Terra and Luna receive bounded assignments with settled contracts. A lane spanning several packages is a sequence of bounded work packets, not an instruction to redesign a subsystem. The lead retains decisions affecting other packages. A Sol lane may be implemented directly by the lead; this avoids an extra agent when no useful independent lead work remains.

Project configuration lives in [.codex/config.toml](../.codex/config.toml). Reusable roles live in [.codex/agents](../.codex/agents). `AGENTS.md` continues to contain stable engineering conventions, not wave scheduling or model policy. User-level settings are not changed by this workflow.

The spawn limit is two child agents, excluding the primary task. Individual waves impose tighter limits below. Only the lead dispatches agents; all project role files disable further delegation. Close finished lane sessions before starting a scheduled reviewer. Never fill unused slots merely because they exist.

Custom role files explicitly set their model and effort. Those values take precedence over spawn settings, so use `dependency-auditor` for the medium-effort audit rather than trying to override the low-effort `explorer`; use `api-implementer` for the high-effort API lane rather than overriding `implementer`. If the current tool cannot select custom roles, supply their instructions and exact model/effort explicitly in a bounded dispatch. Inspect the resolved settings. Read-only roles also forbid edits in their instructions because parent permission overrides can affect the effective sandbox.

Configuration behavior was checked against [official subagent documentation](https://learn.chatgpt.com/docs/agent-configuration/subagents) on 2026-09-20. See [AGENTS.md guidance](https://learn.chatgpt.com/docs/agent-configuration/agents-md) for stable repository instructions. The exact model assignments here are project decisions supplied by the user.

## 2. Preparation and lane handoff

Before the first implementation edit, the lead checks repository status and records the starting revision and existing changes. At workflow preparation, this repository has an unborn `main` branch and untracked scaffolding. Do not assume a clean committed baseline exists. Preserve the reviewed scaffold and user changes, and establish a reviewed baseline before making isolated worker checkouts. Do not stage unrelated files or run destructive cleanup. Use `codex/` for implementation branch names unless the user specifies otherwise.

Use separate worktrees for concurrently editing lanes that must return independent commits. Record each lane's owned paths and shared contract revision. Do not let agents commit against the same index concurrently. Read-only audit/review can use the integrated checkout. Workers do not push, deploy, or merge. The lead integrates local commits and owns the final branch state.

Every dispatch names the wave, role, exact model/effort, input revision, owned files, contract references, acceptance cases, focused checks, and whether a local commit is required. Keep shared interface changes with the lead. If a lane discovers a contract conflict, return the smallest concrete question before proceeding across the boundary.

Each implementation lane returns one coherent local commit per completed assigned lane, its changed files, exact focused checks/results, changed contracts or `none`, and unresolved blockers. If a lane needs several bounded work packets, the lead coordinates them and assembles the coherent lane result before integration. Research returns exact findings with source revisions and references, not code. Review returns concrete defects against the integrated revision, not another implementation.

## 3. Wave assignments

### Wave 0: confirm and record specification contracts

Owner: primary Sol lead at `high`. One agent total. Do not delegate this wave.

The substantive decisions below are already recorded in SPEC 2.1. Confirm their consistency and record any remaining package-facing details in `docs/architecture.md` during execution. Do not reopen settled product decisions or mark this wave complete merely because workflow setup exists.

| Contract | Settled requirement | SPEC sections |
| --- | --- | --- |
| DNS rebinding and mixed answers | Validate each address; start HTTP on an approved public address, dial it exactly with Host/SNI, continue remaining queries, and never dial prohibited addresses. Apply the same policy to redirects. | 3.4, 4.2, 5.2 |
| Source availability | Preserve useful evidence with partial coverage. Partial is HTTP 200/CLI 3; no necessary usable execution path is HTTP 503/CLI 4. No unavailable source becomes a successful no-match. | 7.4, 14.2 |
| Batch bundle retention | Persist pins at admission in coordination with pruning; protect queued/retrying targets across restart until all targets are terminal. Unpinned target attempts capture the active bundle at start. | 3.4, 12.2, 13.2 |
| Replay time and provenance | Reinterpret immutable captures using a selected bundle; distinguish consulted source records and times. Do not reconstruct historical ownership. | 9.1–9.5, 12.3 |
| CT verification | Record checkpoint-signature, continuity, and entry-inclusion checks independently. `verified_log` requires inclusion in an authenticated tree. | 10.1 |
| Access and cancellation | One shared trusted-operator model; shared results and cancellation; stable caller identity scopes idempotency, not tenant isolation. | 11.3–11.4, 12.2 |
| Minimum coverage | Product-and-relationship fixtures with justified unsupported signals; provider-only results cannot replace supported product identification. SPF uses `sending_authorization`. | 8.5, 9.1 |

Exit: a consistent contract record with each item linked to its SPEC requirement and any remaining issue isolated. No implementation or `make check` is needed for this document-only wave. Only if one issue remains unresolved after a focused Sol pass may the lead send that exact question and relevant sections to Astra at high effort. Continue on Sol after the decision.

### Wave 1: audit and domain contracts

At most two agents total: the Sol lead at `high`, plus one `dependency-auditor` on Terra at `medium`.

The auditor inspects explicitly selected dependencies, licenses, dataset formats, network side effects, and fixture assumptions. It returns read-only findings with exact revisions, hashes, and primary-source references. It does not edit `go.mod`, generate fixtures, or pin dependencies.

The lead owns observations, consulted dataset records, evidence, findings, coverage, target policy, error contracts, package boundaries, and serialization. It integrates audit findings directly and performs any required contract probes or fixture preparation. The P0 CT feasibility measurement remains an early explicit-budget probe, owned by the lead; production CT stays in wave 6. Freeze P1 interfaces only after the relevant P0 findings have been resolved. There is no second review here.

Coverage: P0 and P1. Run focused model/normalization/schema/adapter-contract checks during edits. If executable code or dependencies changed, the lead runs one `make check` after integration. If only audit documents changed, validate those artifacts without running the application pipeline.

### Wave 2: first vertical fixture

Owner: primary Sol lead at `high`, alone. Do not delegate.

Build E1 using the smallest working paths from P3–P7:

```text
domain -> controlled DNS -> controlled HTTP -> observations
       -> evidence -> findings -> coverage -> CLI JSON
```

Use a small pinned dataset and real collection/classification code for the chosen path. Prove the partial-source and approved-public-address plus delayed/failed-AAAA variants. Include schema-valid provenance and the absence of unsupported commercial claims. Do not wait for every provider importer or service relation.

Run focused tests while implementing. Once the slice works, run `make check` once and record the revision. This validates E1; it does not mark all P3–P7 deliverables complete.

### Wave 3: data and collection

Two implementation lanes, with at most two child agents. The lead can own the Sol lane directly if that is more economical.

| Lane | Model and effort | Role | Ownership |
| --- | --- | --- | --- |
| Provider/service importers, indexes, bundles | Terra `medium` | `implementer` | P2/P3, one bounded package/behavior at a time against frozen source and bundle contracts |
| DNS, destination policy, HTTP, redirects, TLS | Sol `high` | Lead or `sol-implementer` | P4/P5, including exact-address dialing, cancellation, shared budgets, and network state |

The lead retains cross-package bundle-lifecycle design. Terra reports unresolved atomicity or ownership questions instead of inventing contracts. Each lane returns one coherent commit, focused test results, contract changes, and blockers. The lead integrates at Sol `medium`, runs the cross-package fixture, then runs `make check` once. Reuse the full gate's fixture result if that exact fixture is already included; do not run it twice without a reason.

### Wave 4: rules, aggregation, and CLI

| Lane | Model and effort | Role | Ownership |
| --- | --- | --- | --- |
| Rule evaluation, aggregation, evidence strength, coverage | Sol `high` | Lead or `sol-implementer` | P6 and analyzer behavior from P7 |
| CLI, report formatting, fixture expansion | Terra `medium` | `implementer` | Bounded P7 commands/output contracts and supplied acceptance cases |

Evidence strength means the SPEC's categorical support levels, not invented confidence probabilities. After integration, commission the first independent review with `reviewer` on Sol at `high`. Give it the full domain-to-report path, integrated revision, SPEC cases, and existing focused-test evidence.

Apply actionable findings as one batch. Rerun affected focused tests, then the final `make check` once. Do not commission multiple reviewers for the same unchanged code. Coverage: complete P6/P7, with P2–P5 integrated.

### Wave 5: persistence, jobs, and API

| Lane | Model and effort | Role | Ownership |
| --- | --- | --- | --- |
| PostgreSQL, reports, queue state, leases, retries, pins | Sol `high` | Lead or `sol-implementer` | P8 storage and lifecycle behavior |
| Endpoints, result access, cancellation, authorization wiring | Terra `high` | `api-implementer` | Bounded endpoints implementing the already agreed application/access contracts |

The lead integrates on Sol at `high`. It owns decisions where job state, bundle retention, caller identity, cancellation, and replay meet. Terra implements the settled shared-operator rules; it does not design a new authorization model.

Run one integrated security/lifecycle review with `security-reviewer` on Sol at `high`. Give it pin admission/pruning, restart/retry, stale-attempt commits, backlog reservations, access, and persistence-failure cases. Apply findings together, rerun affected tests, then run `make check` once. Use Astra only for one unresolved authorization or lifecycle question after a concrete Sol attempt.

### Wave 6: certificate transparency

Owner: primary Sol lead at `high`, alone. Keep CT behind its interface and configuration. Prove acquisition, checkpoint handling, and entry verification before adding production plumbing.

Complete P9 using the early P0 feasibility results. Repeat throughput, bandwidth, retained-storage, and ingestion-lag measurements under explicit budgets. Test valid checkpoints paired with altered entry bytes. CT remains required for delivery and optional at runtime.

Use focused CT tests during implementation and one `make check` when integration is complete. If inclusion verification, log state, or feasibility remains disputed after a focused attempt, send that exact issue to Astra at `high`; do not request a project-wide reread or implementation. Return ownership to Sol afterward.

### Wave 7: operations and qualification

The Sol lead owns final integration and release review at `high`. Split only when useful, with no more than two support agents:

- `mechanical-worker`, Luna `low`: deployment manifests and routine documentation from explicit approved requirements. The lead owns security-sensitive deployment decisions.
- `implementer`, Terra `medium`: bounded qualification fixtures and acceptance scenarios with specified expected behavior.

Complete P10/P11, all R01–R23 traceability, and the product-and-relationship matrix. The lead reviews the release candidate, integrates corrections, and runs the full validation pipeline once on that candidate. `make check` is one part of this gate; also run the required integration, no-egress, migration/recovery, deployment, CT, and qualification checks when they are not included in it. Record untested platforms or unavailable checks explicitly.

Do not rerun tests already covered by the same successful release-candidate gate. Do not push, deploy, or publish without the separate authorization required by repository policy.

## 4. Validation and stopping rules

Workers run focused package or behavior checks. They use explicit synchronization for concurrency tests and focused race tests for affected lifecycle code. They do not run `make check`. The lead owns formatting and repository-wide checks at the specified wave boundary.

The current `make check` includes formatting, vet, unit tests, GolangCI-Lint, skill integrity, race tests, and build. Do not separately repeat those full checks on the same unchanged revision. New integration or operational checks must be included once when required by the phase; a passing scaffold build is not evidence of application acceptance.

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

Repeat `make check` only if code/dependencies changed or the previous run exposed a failure. If only a document changes afterward, validate that document. Apply integrated review findings as a batch and rerun affected tests before the final gate. Do not add reviews or broaden testing after successful acceptance without a new concrete concern.

Record each gate's revision, commands, results, remaining blockers, and accepted limits in the implementation task handoff. After a wave passes its acceptance gate, stop work on that wave. Continue only to the next wave covered by the implementation authorization. At the authorized endpoint, report the result and stop; do not add cleanup, extra reviews, or speculative features.

## 5. Effort and escalation

Start bounded implementation at `medium`. Use `low` for narrow discovery and mechanical edits. Use `high` for contracts, concurrent state, security, aggregation, and integrated review, including the explicit lane assignments above. Do not routinely use `xhigh`, `max`, or `ultra`.

Escalate only one task after a concrete failed attempt or unresolved contradiction. Give the escalation agent the exact question, attempted approach, relevant contract sections, evidence, and expected decision. Use `gpt-6-astra` at `high` explicitly; do not create an Astra config default or standing role. Return implementation to the assigned lower-cost model once the question is settled.

## 6. Starting a future implementation task

Select `gpt-5.6-sol` at `high` for wave 0/1 contract work. A CLI invocation may explicitly select the initial settings:

```sh
codex --model gpt-5.6-sol -c 'model_reasoning_effort="high"'
```

Then give the implementation instruction:

> Implement the project according to IMPLEMENTATION-PLAN.md and docs/execution-plan.md. Remain the working integrating lead on gpt-5.6-sol. Use high effort for contracts and hard integration, and medium for routine integration. Use project agent roles only at the named delegation points, preserve the wave concurrency limits, and record each validation gate before proceeding.

This launch example is documentation only. No wave, dependency audit, implementation, review agent, or application validation is started by preparing these files.
