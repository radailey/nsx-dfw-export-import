#!/usr/bin/env python3
"""Export NSX-T DFW policy objects from a source NSX Manager cluster.

Exports:
- Services (/infra/services)
- Groups (/infra/domains/<domain>/groups)
- Security Policies + Rules (/infra/domains/<domain>/security-policies)
- Context Profiles (/infra/context-profiles)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List

from nsx_dfw_common import NSXApiError, NSXClient, now_utc_iso


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export DFW objects from NSX Manager")
    parser.add_argument("--source-host", required=True, help="Source NSX Manager FQDN or IP")
    parser.add_argument("--username", required=True, help="NSX API username")
    parser.add_argument(
        "--password",
        default=os.getenv("NSX_SOURCE_PASSWORD"),
        help="NSX API password (or set NSX_SOURCE_PASSWORD)",
    )
    parser.add_argument("--domain", default="default", help="Policy domain (default: default)")
    parser.add_argument(
        "--output",
        default="nsx_dfw_export.json",
        help="Output JSON file (default: nsx_dfw_export.json)",
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify NSX TLS certificates (disabled by default)",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=1000,
        help="Page size for paginated API calls (default: 1000)",
    )
    return parser.parse_args()


def fetch_node_version(client: NSXClient) -> Dict[str, Any]:
    # Management-plane endpoint; may be unavailable based on RBAC/API config.
    try:
        version_data = client.request("GET", "/api/v1/node/version")
        if isinstance(version_data, dict):
            return version_data
    except NSXApiError:
        pass
    return {"version": "unknown"}


def fetch_policies_with_rules(client: NSXClient, domain: str, page_size: int) -> List[Dict[str, Any]]:
    policy_path = f"/policy/api/v1/infra/domains/{domain}/security-policies"
    policy_summaries = client.get_paginated(policy_path, page_size=page_size)

    policies: List[Dict[str, Any]] = []
    for summary in policy_summaries:
        policy_id = summary.get("id")
        if not policy_id:
            continue

        full_policy_path = f"{policy_path}/{policy_id}"
        policy_obj = client.request("GET", full_policy_path)
        rules = client.get_paginated(f"{full_policy_path}/rules", page_size=page_size)
        if isinstance(policy_obj, dict):
            policy_obj["rules"] = rules
            policies.append(policy_obj)

    return policies


def main() -> int:
    args = parse_args()
    if not args.password:
        print("ERROR: Password is required (use --password or NSX_SOURCE_PASSWORD)", file=sys.stderr)
        return 2

    client = NSXClient(
        host=args.source_host,
        username=args.username,
        password=args.password,
        verify_ssl=args.verify_ssl,
    )

    try:
        services = client.get_paginated("/policy/api/v1/infra/services", page_size=args.page_size)
        groups = client.get_paginated(
            f"/policy/api/v1/infra/domains/{args.domain}/groups", page_size=args.page_size
        )
        context_profiles = client.get_paginated(
            "/policy/api/v1/infra/context-profiles", page_size=args.page_size
        )
        policies = fetch_policies_with_rules(client, args.domain, args.page_size)

        payload = {
            "metadata": {
                "exported_at_utc": now_utc_iso(),
                "source_host": args.source_host,
                "source_version": fetch_node_version(client),
                "domain": args.domain,
            },
            "services": services,
            "groups": groups,
            "context_profiles": context_profiles,
            "policies": policies,
        }

        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)

        print(
            "Export complete: "
            f"services={len(services)}, groups={len(groups)}, context_profiles={len(context_profiles)}, "
            f"policies={len(policies)} -> {args.output}"
        )
        return 0

    except NSXApiError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
