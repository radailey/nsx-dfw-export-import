#!/usr/bin/env python3
"""Import NSX-T DFW policy objects into a destination NSX Manager cluster.

Idempotency behavior:
- Uses source object IDs to avoid creating duplicates.
- Skips existing objects by default.
- Optional --update-existing performs PATCH updates on existing IDs.
- Rules also use a content-based duplicate check when IDs differ.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from nsx_dfw_common import (
    ImportCounters,
    NSXApiError,
    NSXClient,
    canonical_rule_for_compare,
    is_system_owned,
    sanitize_for_import,
    strip_rules,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import DFW objects into NSX Manager")
    parser.add_argument("--dest-host", required=True, help="Destination NSX Manager FQDN or IP")
    parser.add_argument("--username", required=True, help="NSX API username")
    parser.add_argument(
        "--password",
        default=os.getenv("NSX_DEST_PASSWORD"),
        help="NSX API password (or set NSX_DEST_PASSWORD)",
    )
    parser.add_argument("--input", required=True, help="Path to exported JSON file")
    parser.add_argument(
        "--domain",
        default=None,
        help="Destination policy domain (defaults to exported metadata domain or 'default')",
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify NSX TLS certificates (disabled by default)",
    )
    parser.add_argument(
        "--update-existing",
        action="store_true",
        help="Update objects when same ID already exists (default: skip existing)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Show what would be changed")
    parser.add_argument(
        "--page-size",
        type=int,
        default=1000,
        help="Page size for paginated API calls (default: 1000)",
    )
    parser.add_argument(
        "--requests-per-second",
        type=float,
        default=25.0,
        help="Throttle API calls to this rate to avoid NSX rate limiting (default: 25)",
    )
    parser.add_argument(
        "--rate-limit-retries",
        type=int,
        default=8,
        help="Retry count for HTTP 429 responses (default: 8)",
    )
    return parser.parse_args()


def load_export(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Input file must contain a JSON object")
    return data


def endpoint_for_object(kind: str, object_id: str, domain: str) -> str:
    if kind == "service":
        return f"/policy/api/v1/infra/services/{object_id}"
    if kind == "group":
        return f"/policy/api/v1/infra/domains/{domain}/groups/{object_id}"
    if kind == "context_profile":
        return f"/policy/api/v1/infra/context-profiles/{object_id}"
    if kind == "policy":
        return f"/policy/api/v1/infra/domains/{domain}/security-policies/{object_id}"
    raise ValueError(f"Unsupported kind: {kind}")


def import_single_object(
    client: NSXClient,
    *,
    kind: str,
    obj: Dict[str, Any],
    domain: str,
    update_existing: bool,
    dry_run: bool,
) -> Tuple[str, Optional[str]]:
    object_id = obj.get("id")
    if not object_id:
        return ("error", f"ERROR [{kind}]: object missing 'id'; skipping")

    if is_system_owned(obj):
        return ("skipped_system_owned", None)

    path = endpoint_for_object(kind, object_id, domain)
    payload = sanitize_for_import(obj)

    try:
        existing = client.get_object(path)
    except NSXApiError as exc:
        return ("error", f"ERROR [{kind}:{object_id}] existence check failed: {exc}")

    if existing is not None and not update_existing:
        return ("skipped_exists", None)

    action = "update" if existing is not None else "create"
    if dry_run:
        if action == "create":
            return ("created", None)
        return ("updated", None)

    try:
        client.patch_object(path, payload)
        if action == "create":
            return ("created", None)
        return ("updated", None)
    except NSXApiError as exc:
        return ("error", f"ERROR [{kind}:{object_id}] failed to {action}: {exc}")


def bump_counter(counters: ImportCounters, status: str) -> None:
    if status == "created":
        counters.created += 1
    elif status == "updated":
        counters.updated += 1
    elif status == "skipped_exists":
        counters.skipped_exists += 1
    elif status == "skipped_system_owned":
        counters.skipped_system_owned += 1
    elif status == "duplicate_matches":
        counters.duplicate_matches += 1
    elif status == "error":
        counters.errors += 1


def import_objects(
    client: NSXClient,
    *,
    kind: str,
    objects: List[Dict[str, Any]],
    domain: str,
    update_existing: bool,
    dry_run: bool,
    retry_passes: int = 1,
) -> ImportCounters:
    counters = ImportCounters()
    pending = list(objects)

    for current_pass in range(1, retry_passes + 1):
        if not pending:
            break

        next_pending: List[Dict[str, Any]] = []
        progress_made = False

        for obj in pending:
            status, message = import_single_object(
                client,
                kind=kind,
                obj=obj,
                domain=domain,
                update_existing=update_existing,
                dry_run=dry_run,
            )

            if status in {"created", "updated", "skipped_exists", "skipped_system_owned"}:
                bump_counter(counters, status)
                if status in {"created", "updated"}:
                    progress_made = True
                continue

            if current_pass < retry_passes:
                next_pending.append(obj)
            else:
                bump_counter(counters, status)
                if message:
                    print(message)

        if not next_pending:
            pending = []
            break
        if not progress_made:
            pending = next_pending
            break
        pending = next_pending

    if pending:
        for obj in pending:
            status, message = import_single_object(
                client,
                kind=kind,
                obj=obj,
                domain=domain,
                update_existing=update_existing,
                dry_run=dry_run,
            )
            bump_counter(counters, status)
            if message:
                print(message)

    return counters


def find_equivalent_rule(
    source_rule_payload: Dict[str, Any],
    existing_rules: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    source_fingerprint = canonical_rule_for_compare(source_rule_payload)
    for existing_rule in existing_rules:
        if canonical_rule_for_compare(existing_rule) == source_fingerprint:
            return existing_rule
    return None


def import_policies_and_rules(
    client: NSXClient,
    *,
    policies: List[Dict[str, Any]],
    domain: str,
    update_existing: bool,
    dry_run: bool,
    page_size: int,
) -> ImportCounters:
    counters = ImportCounters()

    for policy in policies:
        policy_id = policy.get("id")
        if not policy_id:
            counters.errors += 1
            print("ERROR [policy]: object missing 'id'; skipping")
            continue

        if is_system_owned(policy):
            counters.skipped_system_owned += 1
            continue

        policy_path = endpoint_for_object("policy", policy_id, domain)
        policy_payload = sanitize_for_import(strip_rules(policy))

        try:
            existing_policy = client.get_object(policy_path)
        except NSXApiError as exc:
            counters.errors += 1
            print(f"ERROR [policy:{policy_id}] existence check failed: {exc}")
            continue

        action = None
        policy_created_in_run = False
        if existing_policy is None:
            action = "create"
        elif update_existing:
            action = "update"
        else:
            counters.skipped_exists += 1
            # In default idempotent mode, do not modify the existing policy
            # object itself, but continue to reconcile any missing child rules.

        if action:
            if dry_run:
                if action == "create":
                    counters.created += 1
                    policy_created_in_run = True
                else:
                    counters.updated += 1
            else:
                try:
                    client.patch_object(policy_path, policy_payload)
                    if action == "create":
                        counters.created += 1
                        policy_created_in_run = True
                    else:
                        counters.updated += 1
                except NSXApiError as exc:
                    counters.errors += 1
                    print(f"ERROR [policy:{policy_id}] failed to {action}: {exc}")
                    continue

        policy_rules_path = f"{policy_path}/rules"
        # If we are creating the policy in this run, there cannot be any
        # pre-existing child rules to reconcile yet.
        if policy_created_in_run:
            existing_rules = []
        else:
            try:
                existing_rules = client.get_paginated(policy_rules_path, page_size=page_size)
            except NSXApiError as exc:
                counters.errors += 1
                print(f"ERROR [policy:{policy_id}] could not list existing rules: {exc}")
                continue

        existing_rules_by_id = {r.get("id"): r for r in existing_rules if r.get("id")}

        for source_rule in policy.get("rules", []):
            rule_id = source_rule.get("id")
            if not rule_id:
                counters.errors += 1
                print(f"ERROR [policy:{policy_id}] rule missing 'id'; skipping")
                continue

            if is_system_owned(source_rule):
                counters.skipped_system_owned += 1
                continue

            rule_payload = sanitize_for_import(copy.deepcopy(source_rule))
            rule_path = f"{policy_rules_path}/{rule_id}"

            existing_by_id = existing_rules_by_id.get(rule_id)
            if existing_by_id is not None:
                if update_existing:
                    action = "update"
                else:
                    counters.skipped_exists += 1
                    continue
            else:
                duplicate = find_equivalent_rule(rule_payload, existing_rules)
                if duplicate is not None:
                    counters.duplicate_matches += 1
                    continue
                action = "create"

            if dry_run:
                if action == "create":
                    counters.created += 1
                else:
                    counters.updated += 1
                continue

            try:
                client.patch_object(rule_path, rule_payload)
                if action == "create":
                    counters.created += 1
                    existing_rules.append(source_rule)
                    existing_rules_by_id[rule_id] = source_rule
                else:
                    counters.updated += 1
            except NSXApiError as exc:
                counters.errors += 1
                print(f"ERROR [policy:{policy_id} rule:{rule_id}] failed to {action}: {exc}")

    return counters


def print_summary(header: str, counters: ImportCounters) -> None:
    print(
        f"{header}: created={counters.created}, updated={counters.updated}, "
        f"skipped_exists={counters.skipped_exists}, skipped_system_owned={counters.skipped_system_owned}, "
        f"duplicate_matches={counters.duplicate_matches}, errors={counters.errors}"
    )


def merge_counters(items: List[ImportCounters]) -> ImportCounters:
    total = ImportCounters()
    for c in items:
        total.created += c.created
        total.updated += c.updated
        total.skipped_exists += c.skipped_exists
        total.skipped_system_owned += c.skipped_system_owned
        total.duplicate_matches += c.duplicate_matches
        total.errors += c.errors
    return total


def main() -> int:
    args = parse_args()
    if not args.password:
        print("ERROR: Password is required (use --password or NSX_DEST_PASSWORD)", file=sys.stderr)
        return 2

    try:
        export_data = load_export(args.input)
    except Exception as exc:
        print(f"ERROR: Failed to load input file: {exc}", file=sys.stderr)
        return 2

    metadata = export_data.get("metadata", {})
    domain = args.domain or metadata.get("domain") or "default"

    services = export_data.get("services", [])
    groups = export_data.get("groups", [])
    context_profiles = export_data.get("context_profiles", [])
    policies = export_data.get("policies", [])

    client = NSXClient(
        host=args.dest_host,
        username=args.username,
        password=args.password,
        verify_ssl=args.verify_ssl,
        requests_per_second=args.requests_per_second,
        rate_limit_retries=args.rate_limit_retries,
    )

    try:
        service_counts = import_objects(
            client,
            kind="service",
            objects=services,
            domain=domain,
            update_existing=args.update_existing,
            dry_run=args.dry_run,
        )
        print_summary("Services", service_counts)

        context_profile_counts = import_objects(
            client,
            kind="context_profile",
            objects=context_profiles,
            domain=domain,
            update_existing=args.update_existing,
            dry_run=args.dry_run,
        )
        print_summary("Context Profiles", context_profile_counts)

        group_counts = import_objects(
            client,
            kind="group",
            objects=groups,
            domain=domain,
            update_existing=args.update_existing,
            dry_run=args.dry_run,
            retry_passes=5,
        )
        print_summary("Groups", group_counts)

        policy_counts = import_policies_and_rules(
            client,
            policies=policies,
            domain=domain,
            update_existing=args.update_existing,
            dry_run=args.dry_run,
            page_size=args.page_size,
        )
        print_summary("Policies + Rules", policy_counts)

        total = merge_counters([service_counts, context_profile_counts, group_counts, policy_counts])
        print_summary("TOTAL", total)

        return 1 if total.errors > 0 else 0

    except NSXApiError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
