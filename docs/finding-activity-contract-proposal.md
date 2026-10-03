# Finding activity and network conflict contract (proposal)

Issue #22 leaves two product decisions open. This document proposes a contract for review; it is not yet an adopted report contract. The current aggregator selects `activity` and `category` from the evidence with the lexicographically first ID and links every pair of different network providers on the same hostname, relation, and scope. Those choices change conclusions when IDs change and can label two legitimate endpoints as contradictory.

## Recommended activity representation

Keep the existing `activity` field for historical report decoding. New findings would add `activity_states`: sorted, unique activity labels from their supporting evidence. If there is exactly one state, `activity` equals it. If there are several, `activity` is `mixed`. This gives a concise summary without ranking `responding`, `configured`, `verification_only`, `historical`, and `unknown` as if they were interchangeable levels of certainty. `unknown` remains a state only when evidence itself says unknown.

For example, a DNS CNAME and a successful HTTP response supporting one web-delivery finding produce `activity: mixed` and `activity_states: [configured, responding]`. A verification token alone remains `verification_only`; adding unrelated responding evidence cannot turn that token into active-product proof because grouping still separates relations. A retired prefix and a current observation supporting the same network relation produce `[historical, responding]` and `mixed`, with both evidence references retained.

An alternative is a documented scalar precedence with a list of retained states. It avoids a new `mixed` value, but any precedence would need to say whether a single response outweighs configuration, historical context, or verification-only evidence. The issue does not establish that policy. I recommend the explicit mixed value.

The proposed output for each semantic input set is:

| Supporting activity states | `activity` | `activity_states` | Meaning |
| --- | --- | --- | --- |
| `configured` | `configured` | `[configured]` | Configuration observed; no response implied. |
| `responding` | `responding` | `[responding]` | A response or connection was observed. |
| `verification_only` | `verification_only` | `[verification_only]` | Token or verification evidence only. |
| `historical` | `historical` | `[historical]` | Retired or historical context only. |
| `unknown` | `unknown` | `[unknown]` | Available evidence does not establish activity. |
| `configured`, `responding` | `mixed` | `[configured, responding]` | Both are retained without promoting configuration to response. |
| `historical`, `unknown` | `mixed` | `[historical, unknown]` | An unknown state is retained, not dropped because another source is historical. |

The list is sorted by label solely for deterministic serialization, not by semantic strength. A group's empty activity input needs an explicit compatibility rule: use `unknown` for newly classified evidence and preserve the stored scalar field when decoding an older report. This should be confirmed with the representation decision.

## Recommended category treatment

If supporting evidence agrees on one nonempty category, use it. If categories differ, leave the scalar `category` empty, add a sorted `categories` list, and add a limitation explaining the ambiguity. An empty category from one evidence item does not override a known category from another. Evidence IDs and arrival order never select the category. The technology-only schema rule still requires `web_technology` for those findings; incompatible categories in that case must fail validation or remain separate evidence rather than produce an invalid finding.

## Recommended endpoint and time comparison

Conflict links remain restricted to `network_provider`, `network_origin`, and `service_range`. Within one relation, subject, and scope, different providers may coexist on distinct observed endpoint addresses. A conflict requires incompatible provider or product claims about the **same address from the same retained observation occurrence**. Reusing an IP in observations made at different times does not prove simultaneity, so it does not automatically create a conflict. A report may explain the older observation as historical context.

For example, `example.com` resolving to provider A at `192.0.2.10` and provider B at `192.0.2.11` produces two findings without conflict links. Two incompatible prefix classifications that reference the same `dns_address` observation for `192.0.2.10` produce reciprocal conflict links, with both dataset records and the shared observation available for inspection.

| Endpoint evidence | Time/occurrence evidence | Proposed result |
| --- | --- | --- |
| Distinct observed IPs, different providers | Same report | Coexist; no conflict link. |
| Same IP, incompatible providers | Same retained `dns_address` or HTTP peer occurrence | Reciprocal conflict links and preserved source records. |
| Same IP, different providers | Distinct observation occurrences at different times | Preserve both; no automatic simultaneous conflict. |
| Provider evidence without an endpoint | Missing or historical occurrence details | Preserve support and explain that endpoint comparison is unavailable. |
| Same endpoint and occurrence, compatible product/provider aliases | Same source claim | Deduplicate compatible support rather than manufacture a conflict. |

Evidence without a retained endpoint or observation time cannot prove this conflict predicate. It remains supporting evidence, and the finding should carry a limitation that endpoint comparison was unavailable. This favors an explicit unknown over inferring a contradiction from hostname alone. If a broader temporal overlap rule is wanted, its validity window and clock semantics need a separate decision before implementation.

## Identity, deduplication, and compatibility

Findings continue grouping by subject, provider/product, relation, and scope. Evidence deduplication must preserve semantically distinct activity and category states even when provenance matches. IDs only order output and identify references; renaming IDs without changing semantic inputs must leave activity, category, and conflict conclusions unchanged. Every retained supporting evidence ID must resolve in the report.

Historical reports keep their stored scalar fields and IDs. New readers accept missing `activity_states` and `categories` without rewriting old reports. Reclassification emits the selected new representation from retained observations and selected dataset records, while preserving the original report unchanged. The implementation should update the report schema, API schema, aggregation tests, and live/replay tests after this contract is selected.

The current `aggregate.Build` receives only evidence. Endpoint claims are generated in `app.addressInputs`, which groups `dns_address` and HTTP peer observations by subject, scope, and IP and attaches their observation IDs to prefix and ASN evidence. That grouping combines repeated observations of the same address even when they occurred at different times. A strict same-occurrence conflict rule therefore cannot infer occurrence identity from the current grouped input alone. The implementation must preserve each occurrence while enriching a deduplicated address set, pass observation context into aggregation, or attach a validated endpoint occurrence key before linking conflicts. Historical evidence with incomplete observation detail needs an explicit unknown path; a shared arbitrary evidence ID must not stand in for a parsed endpoint. This is an implementation implication of the proposed policy, not a chosen public contract.

The report reader already accepts historical findings with only the scalar `activity` and `category`. New slice fields must be copied by `Report.Clone` and sorted by canonical serialization so content IDs remain deterministic for new reports. The existing content-ID version 1 projection must continue to hash older reports as it did before this change. Schema validation must accept both the old scalar-only shape and the selected new shape; no stored report should be rewritten merely to populate the new fields.

## Decision needed before implementation

Choose the explicit `mixed` representation above or specify a scalar precedence. Also confirm whether conflict requires a shared endpoint observation occurrence, or provide the validity-window rule for comparing distinct observations over time. Until selected, this remains a proposal and the public finding representation should not be changed.
