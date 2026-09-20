# Source contracts

Status: wave 1 source inventory, checked 2026-09-20.

This reference defines updater inputs. Every fetched artifact keeps its exact bytes, retrieval URL, HTTP metadata, SHA-256 digest, source publication time when supplied, retrieval time, adapter version, and local activation time.

## Broad cloud ranges

Pin `disposable/cloud-ip-ranges` at revision `0c4c204e650a47a6f57d3709893a9dc96f942ed9`. The inspected A2Hosting provider file has Git blob `1bc51f7e3f2a8a8f8b9106cdb5ed60d0b35d42cd`.

The adapter discovers selected regular `json/*.json` provider files. It excludes `json/all-providers.json`, every `*-details.json` file, and `misc/` from primary discovery. Detail files use a separate validated join. A selected missing or malformed provider fails the candidate instead of becoming an empty source.

Known top-level fields include `provider`, `provider_id`, `method`, `coverage_notes`, `generated_at`, `source_updated_at`, `source`, `last_update`, `ipv4`, `ipv6`, `source_http`, and lifecycle detail arrays. The adapter archives unknown fields, rejects invalid known-field types, and joins retirement by provider ID and canonical prefix. The upstream README states that retired ranges remain for four weeks with `retired_at` metadata.

The pinned tree has no top-level license or notice file. Its many provider inputs and history database need separate terms review before redistribution.

## AWS service ranges

Input URL: `https://ip-ranges.amazonaws.com/ip-ranges.json`.

Preserve root `syncToken` and `createDate`. Preserve each IPv4 `ip_prefix` and IPv6 `ipv6_prefix` with `region`, `service`, and `network_border_group`. Identical prefixes can have several service rows and must remain separate records. An EC2 service tag establishes range membership, not a customer deployment.

## GCP service ranges

Input URL: `https://www.gstatic.com/ipranges/cloud.json`.

Preserve root `syncToken` and `creationTime`. Each row contains either `ipv4Prefix` or `ipv6Prefix`, plus `service` and `scope`. Generic `Google Cloud` rows remain provider or service-range evidence. They do not identify BigQuery, GKE, or Cloud Run.

## Azure service tags

Discover the current artifact from Microsoft Download Center item `56519`. Store the discovered dated URL in the fetch receipt. Do not hard-code a dated URL as permanent.

The inspected shape has root `changeNumber`, `cloud`, and `values`. Each value has `name`, `id`, and `properties` containing `changeNumber`, `region`, `systemService`, `platform`, and `addressPrefixes`. Preserve direction and purpose through reviewed mappings. The page currently describes weekly updates and an IPv4-only artifact. Recheck that limitation for every fetched revision.

## IPtoASN

Input URLs:

- `https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz`
- `https://iptoasn.com/data/ip2asn-v6.tsv.gz`

Each row contains inclusive start and end addresses, ASN, country code, and description. IPv4 uses integer endpoints. IPv6 uses textual endpoints. Validate ordering, family consistency, disjoint intervals, and bounds without expanding ranges into addresses. ASN zero or unknown does not become a provider. The publisher states PDDL v1.0 for the database; retain the publisher notice with each local artifact.

## Converted CDN data

Use `sources_data.json` from `projectdiscovery/cdncheck` revision `a06260a272dc92cec0747f2f369b697088899bc7`. Convert only data. Do not import the runtime package.

Preserve the top-level category, provider key, CIDR or suffix, source revision, source-file digest, and provenance group. Validate CIDRs and DNS suffixes before publication. Matching both this data and a mirrored cloud-range source does not create independent corroboration unless their provenance groups differ.

## Normalized manifests

Every normalized source manifest records:

- the source ID, input revision, input digest, adapter version, and record count;
- selected files and explicit exclusions;
- source URLs and HTTP metadata when fetched;
- publication, retrieval, and activation times as separate values;
- supported address families, roles, methods, lifecycle states, and raw labels;
- validation warnings, rejected records, and coverage changes;
- the terms or notice reference and any unresolved redistribution question.

An unchanged re-fetch keeps the original source publication time. A timestamp without a timezone remains timezone-unknown. A failed candidate never partially replaces the previous valid source snapshot.
