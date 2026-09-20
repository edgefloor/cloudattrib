# Source contracts

These are the source formats reviewed on 2026-09-20. Importers read local files populated by an operator-controlled download or mirror.

For each artifact, retain the bytes, URL, HTTP metadata, SHA-256 digest, retrieval time, known publication time, adapter version, and activation time.

## Local file layout

Paths are relative to `data.source_directory`, which defaults to `./data/sources`.

| File or directory | Source |
| --- | --- |
| `cloudranges/json/` | Primary provider files from one `disposable/cloud-ip-ranges` revision |
| `aws-ip-ranges.json` | Official AWS service ranges |
| `gcp-cloud.json` | Official GCP cloud ranges |
| `azure-service-tags.json` | Azure Service Tags download |
| `cdncheck-sources-data.json` | Pinned `cdncheck` generated data |
| `iptoasn-v4.tsv` | Decompressed IPtoASN IPv4 data with integer endpoints |
| `iptoasn-v6.tsv` | Decompressed IPtoASN IPv6 data with textual endpoints |

Missing sources reduce runtime coverage. A malformed selected source fails candidate validation. See [operations](operations.md#import-and-activate-data) for staging and activation.

## Broad cloud ranges

The reviewed `disposable/cloud-ip-ranges` revision is `0c4c204e650a47a6f57d3709893a9dc96f942ed9`. The inspected A2Hosting file has Git blob `1bc51f7e3f2a8a8f8b9106cdb5ed60d0b35d42cd`.

Primary discovery reads selected regular `json/*.json` files. It excludes `json/all-providers.json`, `*-details.json`, and `misc/`. Detail files use a separate validated join. A selected missing or malformed provider fails the candidate; it does not become an empty source.

Known fields include `provider`, `provider_id`, `method`, `coverage_notes`, `generated_at`, `source_updated_at`, `source`, `last_update`, `ipv4`, `ipv6`, `source_http`, and lifecycle detail arrays. Archive unknown fields and reject invalid types for known fields.

Join retirement information by provider ID and canonical prefix. The reviewed upstream README describes four weeks of retained retired ranges with `retired_at` metadata. A base-array prefix must not become active merely because it still appears in the list.

The pinned tree has no top-level license or notice file. Review the provider inputs and history database terms before redistributing their data.

## AWS service ranges

Input: [AWS IP ranges](https://ip-ranges.amazonaws.com/ip-ranges.json).

Preserve root `syncToken` and `createDate`. Each IPv4 `ip_prefix` or IPv6 `ipv6_prefix` retains its `region`, `service`, and `network_border_group`.

Identical prefixes can have several service rows. Preserve each row. An EC2 tag proves membership in a published range, not that the analyzed organization owns an EC2 deployment.

## GCP service ranges

Input: [Google Cloud ranges](https://www.gstatic.com/ipranges/cloud.json).

Preserve root `syncToken` and `creationTime`. Each row has either `ipv4Prefix` or `ipv6Prefix`, plus `service` and `scope`.

Generic `Google Cloud` rows support provider or service-range evidence. They do not identify BigQuery, GKE, or Cloud Run.

## Azure service tags

Find the current artifact through Microsoft Download Center item `56519`. Record the discovered dated URL in the fetch receipt. A dated URL must not be treated as permanently current.

The reviewed format has root `changeNumber`, `cloud`, and `values`. Each value has `name`, `id`, and `properties`. Properties include `changeNumber`, `region`, `systemService`, `platform`, and `addressPrefixes`.

Reviewed mappings preserve direction and purpose. At the audit date, the download page described weekly updates and an IPv4-only artifact. Check that limitation for each new revision.

## IPtoASN

Download inputs:

- [IPv4 integer intervals](https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz)
- [IPv6 textual intervals](https://iptoasn.com/data/ip2asn-v6.tsv.gz)

The importer consumes decompressed TSV, not gzip files. Each row contains five fields:

| Field | Meaning |
| --- | --- |
| Start | Inclusive start address; unsigned integer for IPv4, text for IPv6 |
| End | Inclusive end address in the same family |
| ASN | Unsigned autonomous system number |
| Country | Source country code |
| Description | Source organization description |

Intervals must be ordered, disjoint, and within family bounds. The index stores intervals without expanding them into individual addresses. ASN zero or unknown does not become a provider.

The publisher states PDDL v1.0 for the database. Retain the publisher notice with each artifact. Country and description are source metadata, not proof of server location or product use.

## Converted CDN data

The reviewed input is `sources_data.json` from `projectdiscovery/cdncheck` revision `a06260a272dc92cec0747f2f369b697088899bc7`. The adapter converts data only; it does not import the upstream runtime package.

Preserve the top-level category, provider key, CIDR or suffix, source revision, file digest, and provenance group. Validate CIDRs and DNS suffixes before publication.

A match in both this data and a mirrored cloud-range source is not independent corroboration unless the provenance groups differ.

## Normalized manifests

Each source manifest retains:

- Source ID, revision, digest, adapter version, and record count.
- Selected files and explicit exclusions.
- Acquisition URL and HTTP metadata when fetched.
- Publication, retrieval, and activation times as separate values.
- Supported families, roles, methods, lifecycle states, and raw labels.
- Validation warnings, rejected records, and coverage changes.
- Terms or notice reference and unresolved redistribution questions.

Re-fetching unchanged bytes does not change publication time. A timestamp without a timezone remains timezone-unknown. A failed candidate never partially replaces the previous valid snapshot.
