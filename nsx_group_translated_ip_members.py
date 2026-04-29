#!/usr/bin/env python3
"""Materialize translated NSX Group members as hardcoded IPAddressExpressions.

The script finds Policy Groups that contain at least one non-IP expression
(for example VM, VIF, segment, segment port, tag/condition, path, or nested
criteria), asks NSX for the group's effective translated IP addresses, then
adds those IP addresses back to the same Group as managed IP address entries.

It uses Policy APIs that are present in NSX 3.2.x and 4.2.x.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from nsx_dfw_common import NSXClient


EXPRESSION_OPERATOR_TYPES = {"ConjunctionOperator"}
IP_EXPRESSION_TYPE = "IPAddressExpression"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Find NSX Groups with non-IP membership and add their translated "
            "effective IP addresses as hardcoded IPAddressExpressions."
        )
    )
    parser.add_argument("--host", required=True, help="NSX Manager FQDN or IP")
    parser.add_argument("--username", required=True, help="NSX API username")
    parser.add_argument(
        "--password",
        default=os.getenv("NSX_PASSWORD"),
        help="NSX API password (or set NSX_PASSWORD)",
    )
    parser.add_argument("--domain", default="default", help="Policy domain (default: default)")
    parser.add_argument(
        "--expression-id-prefix",
        default="translated-ip-members",
        help="Managed IPAddressExpression ID prefix (default: translated-ip-members)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes. Without this flag, the script only reports planned changes.",
    )
    parser.add_argument(
        "--source-report",
        default=None,
        help=(
            "Replay a JSON report from a source NSX onto this NSX Manager instead of "
            "resolving effective IPs locally."
        ),
    )
    parser.add_argument(
        "--remove-managed",
        action="store_true",
        help=(
            "Remove the managed IPAddressExpressions created by this script. If "
            "--source-report is provided, only groups in that report are considered."
        ),
    )
    parser.add_argument(
        "--include-ipv6",
        action="store_true",
        help="Also materialize translated IPv6 addresses. Default is IPv4 only.",
    )
    parser.add_argument(
        "--enforcement-point-path",
        default=None,
        help=(
            "Optional enforcement point path for effective member lookup, "
            "for example /infra/sites/default/enforcement-points/default."
        ),
    )
    parser.add_argument(
        "--report",
        default="nsx_group_translated_ip_members_report.json",
        help="JSON report path (default: nsx_group_translated_ip_members_report.json)",
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
    parser.add_argument(
        "--requests-per-second",
        type=float,
        default=15.0,
        help="Throttle API calls to this rate to avoid NSX rate limiting (default: 15)",
    )
    parser.add_argument(
        "--rate-limit-retries",
        type=int,
        default=8,
        help="Retry count for HTTP 429 responses (default: 8)",
    )
    return parser.parse_args()


def group_base_path(domain: str) -> str:
    return f"/policy/api/v1/infra/domains/{domain}/groups"


def expression_path(domain: str, group_id: str, expression_id: str) -> str:
    return f"{group_base_path(domain)}/{group_id}/ip-address-expressions/{expression_id}"


def safe_expression_id(prefix: str, family: str) -> str:
    safe_prefix = re.sub(r"[^A-Za-z0-9_.-]+", "-", prefix.strip()).strip("-")
    if not safe_prefix:
        safe_prefix = "translated-ip-members"
    return f"{safe_prefix}-{family}"


def iter_expressions(group: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    expression = group.get("expression", [])
    if isinstance(expression, list):
        for item in expression:
            if isinstance(item, dict):
                yield item


def iter_expression_tree(expression: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    yield expression
    children = expression.get("expressions", [])
    if isinstance(children, list):
        for child in children:
            if isinstance(child, dict):
                yield from iter_expression_tree(child)


def group_has_non_ip_membership(group: Dict[str, Any]) -> bool:
    for expression in iter_expressions(group):
        for node in iter_expression_tree(expression):
            resource_type = node.get("resource_type")
            if not resource_type:
                continue
            if resource_type in EXPRESSION_OPERATOR_TYPES:
                continue
            if resource_type != IP_EXPRESSION_TYPE:
                return True
    return False


def existing_direct_ip_members(
    group: Dict[str, Any],
    *,
    exclude_expression_ids: Optional[Set[str]] = None,
) -> Set[str]:
    ips: Set[str] = set()
    exclude_expression_ids = exclude_expression_ids or set()
    for expression in iter_expressions(group):
        for node in iter_expression_tree(expression):
            if node.get("resource_type") != IP_EXPRESSION_TYPE:
                continue
            if node.get("id") in exclude_expression_ids:
                continue
            ip_addresses = node.get("ip_addresses", [])
            if isinstance(ip_addresses, list):
                ips.update(str(ip).strip() for ip in ip_addresses if str(ip).strip())
    return ips


def expression_ip_members(group: Dict[str, Any], expression_id: str) -> Set[str]:
    ips: Set[str] = set()
    for expression in iter_expressions(group):
        for node in iter_expression_tree(expression):
            if node.get("resource_type") != IP_EXPRESSION_TYPE:
                continue
            if node.get("id") != expression_id:
                continue
            ip_addresses = node.get("ip_addresses", [])
            if isinstance(ip_addresses, list):
                ips.update(str(ip).strip() for ip in ip_addresses if str(ip).strip())
    return ips


def classify_ip_element(ip_element: str) -> str:
    """Return ipv4, ipv6, or unknown for an IP, range, or CIDR string."""
    candidate = ip_element.strip()
    if "-" in candidate:
        candidate = candidate.split("-", 1)[0].strip()
    if "/" in candidate:
        try:
            return "ipv6" if ipaddress.ip_network(candidate, strict=False).version == 6 else "ipv4"
        except ValueError:
            return "unknown"
    try:
        return "ipv6" if ipaddress.ip_address(candidate).version == 6 else "ipv4"
    except ValueError:
        return "unknown"


def split_ip_members(ip_members: Iterable[str], include_ipv6: bool) -> Tuple[List[str], List[str], List[str]]:
    ipv4: Set[str] = set()
    ipv6: Set[str] = set()
    unknown: Set[str] = set()

    for ip_member in ip_members:
        value = str(ip_member).strip()
        if not value:
            continue
        family = classify_ip_element(value)
        if family == "ipv4":
            ipv4.add(value)
        elif family == "ipv6":
            if include_ipv6:
                ipv6.add(value)
        else:
            unknown.add(value)

    return sorted(ipv4), sorted(ipv6), sorted(unknown)


def fetch_group(client: NSXClient, domain: str, group_id: str) -> Dict[str, Any]:
    data = client.request("GET", f"{group_base_path(domain)}/{group_id}")
    if not isinstance(data, dict):
        raise NSXApiError(f"Expected JSON object for group {group_id}, got {type(data)}")
    return data


def fetch_effective_ips(
    client: NSXClient,
    *,
    domain: str,
    group_id: str,
    page_size: int,
    enforcement_point_path: Optional[str],
) -> List[str]:
    params: Dict[str, Any] = {}
    if enforcement_point_path:
        params["enforcement_point_path"] = enforcement_point_path

    results = client.get_paginated(
        f"{group_base_path(domain)}/{group_id}/members/ip-addresses",
        page_size=page_size,
        params=params,
    )
    return [str(item).strip() for item in results if str(item).strip()]


def patch_ip_expression(
    client: NSXClient,
    *,
    domain: str,
    group_id: str,
    expression_id: str,
    ip_addresses: List[str],
) -> None:
    payload = {
        "id": expression_id,
        "display_name": expression_id,
        "resource_type": IP_EXPRESSION_TYPE,
        "ip_addresses": ip_addresses,
    }
    client.patch_object(expression_path(domain, group_id, expression_id), payload)


def delete_ip_expression(
    client: NSXClient,
    *,
    domain: str,
    group_id: str,
    expression_id: str,
) -> None:
    client.request(
        "DELETE",
        expression_path(domain, group_id, expression_id),
        expected_statuses=(200, 204),
    )


def load_report(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Report must contain a JSON object")
    if not isinstance(data.get("groups"), list):
        raise ValueError("Report must contain a 'groups' list")
    return data


def report_group_ip_members(group: Dict[str, Any], include_ipv6: bool) -> List[str]:
    ipv4 = group.get("desired_ipv4", group.get("missing_ipv4", []))
    ipv6 = group.get("desired_ipv6", group.get("missing_ipv6", []))
    values: List[str] = []
    if isinstance(ipv4, list):
        values.extend(str(item).strip() for item in ipv4 if str(item).strip())
    if include_ipv6 and isinstance(ipv6, list):
        values.extend(str(item).strip() for item in ipv6 if str(item).strip())
    return values


def reconcile_managed_ip_expressions(
    client: "NSXClient",
    *,
    full_group: Dict[str, Any],
    domain: str,
    group_id: str,
    display_name: Optional[str],
    desired_ip_members: Iterable[str],
    expression_id_prefix: str,
    apply: bool,
    include_ipv6: bool,
    extra_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ipv4_expression_id = safe_expression_id(expression_id_prefix, "ipv4")
    ipv6_expression_id = safe_expression_id(expression_id_prefix, "ipv6")
    managed_expression_ids = {ipv4_expression_id, ipv6_expression_id}
    unmanaged_direct_ips = existing_direct_ip_members(
        full_group,
        exclude_expression_ids=managed_expression_ids,
    )
    desired_ips = sorted(set(desired_ip_members) - unmanaged_direct_ips)
    current_ipv4_managed_ips = expression_ip_members(full_group, ipv4_expression_id)
    current_ipv6_managed_ips = expression_ip_members(full_group, ipv6_expression_id)
    current_managed_ips = current_ipv4_managed_ips | current_ipv6_managed_ips
    ipv4, ipv6, unknown = split_ip_members(desired_ips, include_ipv6=include_ipv6)
    desired_managed_ips = set(ipv4) | set(ipv6)
    add_count = len(desired_managed_ips - current_managed_ips)
    remove_count = len(current_managed_ips - desired_managed_ips)

    result: Dict[str, Any] = {
        "id": group_id,
        "display_name": display_name or group_id,
        "status": "planned" if add_count or remove_count else "no_change",
        "unmanaged_direct_ip_count": len(unmanaged_direct_ips),
        "current_managed_ip_count": len(current_managed_ips),
        "desired_managed_ip_count": len(desired_managed_ips),
        "managed_add_count": add_count,
        "managed_remove_count": remove_count,
        "desired_ipv4_count": len(ipv4),
        "desired_ipv6_count": len(ipv6),
        "unknown_ip_element_count": len(unknown),
        "desired_ipv4": ipv4,
        "desired_ipv6": ipv6,
        "unknown_ip_elements": unknown,
    }
    if extra_result:
        result.update(extra_result)

    if not add_count and not remove_count:
        return result

    if not ipv4 and not ipv6:
        if current_managed_ips and apply:
            try:
                if current_ipv4_managed_ips:
                    delete_ip_expression(
                        client,
                        domain=domain,
                        group_id=group_id,
                        expression_id=ipv4_expression_id,
                    )
                if current_ipv6_managed_ips:
                    delete_ip_expression(
                        client,
                        domain=domain,
                        group_id=group_id,
                        expression_id=ipv6_expression_id,
                    )
                result["status"] = "updated"
            except NSXApiError as exc:
                result["status"] = "error"
                result["error"] = str(exc)
        elif current_managed_ips:
            result["status"] = "planned"
        elif desired_ips and not include_ipv6 and unknown:
            result["status"] = "skipped_no_supported_ips"
        elif desired_ips:
            result["status"] = "skipped_ipv6_disabled_or_unknown"
        return result

    if len(ipv4) > 25000 or len(ipv6) > 25000:
        result["status"] = "error"
        result["error"] = "A managed IPAddressExpression would exceed NSX maximum of 25000 entries"
        return result

    if apply:
        try:
            if ipv4:
                patch_ip_expression(
                    client,
                    domain=domain,
                    group_id=group_id,
                    expression_id=ipv4_expression_id,
                    ip_addresses=ipv4,
                )
                result["ipv4_expression_id"] = ipv4_expression_id
            elif current_ipv4_managed_ips:
                delete_ip_expression(
                    client,
                    domain=domain,
                    group_id=group_id,
                    expression_id=ipv4_expression_id,
                )
            if ipv6:
                patch_ip_expression(
                    client,
                    domain=domain,
                    group_id=group_id,
                    expression_id=ipv6_expression_id,
                    ip_addresses=ipv6,
                )
                result["ipv6_expression_id"] = ipv6_expression_id
            elif current_ipv6_managed_ips:
                delete_ip_expression(
                    client,
                    domain=domain,
                    group_id=group_id,
                    expression_id=ipv6_expression_id,
                )
            result["status"] = "updated"
        except NSXApiError as exc:
            result["status"] = "error"
            result["error"] = str(exc)
    else:
        result["ipv4_expression_id"] = ipv4_expression_id if ipv4 else None
        result["ipv6_expression_id"] = ipv6_expression_id if ipv6 else None

    return result


def process_group(
    client: NSXClient,
    *,
    group: Dict[str, Any],
    domain: str,
    expression_id_prefix: str,
    apply: bool,
    include_ipv6: bool,
    page_size: int,
    enforcement_point_path: Optional[str],
) -> Dict[str, Any]:
    group_id = group.get("id")
    display_name = group.get("display_name") or group_id
    if not group_id:
        return {"status": "error", "error": "Group missing id", "display_name": display_name}

    full_group = fetch_group(client, domain, group_id)
    if is_system_owned(full_group):
        return {"id": group_id, "display_name": display_name, "status": "skipped_system_owned"}

    if not group_has_non_ip_membership(full_group):
        return {"id": group_id, "display_name": display_name, "status": "skipped_ip_only"}

    effective_ips = fetch_effective_ips(
        client,
        domain=domain,
        group_id=group_id,
        page_size=page_size,
        enforcement_point_path=enforcement_point_path,
    )
    return reconcile_managed_ip_expressions(
        client,
        full_group=full_group,
        domain=domain,
        group_id=group_id,
        display_name=display_name,
        desired_ip_members=effective_ips,
        expression_id_prefix=expression_id_prefix,
        apply=apply,
        include_ipv6=include_ipv6,
        extra_result={"effective_ip_count": len(effective_ips)},
    )


def process_report_group(
    client: "NSXClient",
    *,
    report_group: Dict[str, Any],
    domain: str,
    expression_id_prefix: str,
    apply: bool,
    include_ipv6: bool,
) -> Dict[str, Any]:
    group_id = report_group.get("id")
    display_name = report_group.get("display_name") or group_id
    if not group_id:
        return {"status": "error", "error": "Report group missing id", "display_name": display_name}

    full_group = client.get_object(f"{group_base_path(domain)}/{group_id}")
    if full_group is None:
        return {"id": group_id, "display_name": display_name, "status": "error", "error": "Group not found"}
    if is_system_owned(full_group):
        return {"id": group_id, "display_name": display_name, "status": "skipped_system_owned"}

    desired_ips = report_group_ip_members(report_group, include_ipv6=include_ipv6)
    return reconcile_managed_ip_expressions(
        client,
        full_group=full_group,
        domain=domain,
        group_id=group_id,
        display_name=display_name,
        desired_ip_members=desired_ips,
        expression_id_prefix=expression_id_prefix,
        apply=apply,
        include_ipv6=include_ipv6,
        extra_result={"source_report_ip_count": len(desired_ips)},
    )


def remove_managed_from_group(
    client: "NSXClient",
    *,
    group: Dict[str, Any],
    domain: str,
    expression_id_prefix: str,
    apply: bool,
) -> Dict[str, Any]:
    group_id = group.get("id")
    display_name = group.get("display_name") or group_id
    if not group_id:
        return {"status": "error", "error": "Group missing id", "display_name": display_name}

    full_group = client.get_object(f"{group_base_path(domain)}/{group_id}")
    if full_group is None:
        return {"id": group_id, "display_name": display_name, "status": "error", "error": "Group not found"}
    if is_system_owned(full_group):
        return {"id": group_id, "display_name": display_name, "status": "skipped_system_owned"}

    ipv4_expression_id = safe_expression_id(expression_id_prefix, "ipv4")
    ipv6_expression_id = safe_expression_id(expression_id_prefix, "ipv6")
    current_ipv4 = expression_ip_members(full_group, ipv4_expression_id)
    current_ipv6 = expression_ip_members(full_group, ipv6_expression_id)
    remove_count = len(current_ipv4 | current_ipv6)
    result: Dict[str, Any] = {
        "id": group_id,
        "display_name": display_name,
        "status": "planned" if remove_count else "no_change",
        "managed_remove_count": remove_count,
        "current_managed_ip_count": remove_count,
    }

    if not remove_count or not apply:
        return result

    try:
        if current_ipv4:
            delete_ip_expression(
                client,
                domain=domain,
                group_id=group_id,
                expression_id=ipv4_expression_id,
            )
        if current_ipv6:
            delete_ip_expression(
                client,
                domain=domain,
                group_id=group_id,
                expression_id=ipv6_expression_id,
            )
        result["status"] = "updated"
    except NSXApiError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
    return result


def write_report(path: str, payload: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)


def summarize_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "groups_total": len(results),
        "groups_updated": sum(1 for item in results if item.get("status") == "updated"),
        "groups_planned": sum(1 for item in results if item.get("status") == "planned"),
        "groups_no_change": sum(1 for item in results if item.get("status") == "no_change"),
        "groups_skipped_ip_only": sum(1 for item in results if item.get("status") == "skipped_ip_only"),
        "groups_skipped_system_owned": sum(1 for item in results if item.get("status") == "skipped_system_owned"),
        "groups_errors": sum(1 for item in results if item.get("status") == "error"),
        "desired_ipv4_total": sum(int(item.get("desired_ipv4_count", 0)) for item in results),
        "desired_ipv6_total": sum(int(item.get("desired_ipv6_count", 0)) for item in results),
        "managed_add_total": sum(int(item.get("managed_add_count", 0)) for item in results),
        "managed_remove_total": sum(int(item.get("managed_remove_count", 0)) for item in results),
    }


def main() -> int:
    args = parse_args()
    if not args.password:
        print("ERROR: Password is required (use --password or NSX_PASSWORD)", file=sys.stderr)
        return 2

    global NSXApiError, NSXClient, is_system_owned, now_utc_iso
    try:
        from nsx_dfw_common import NSXApiError, NSXClient, is_system_owned, now_utc_iso
    except ModuleNotFoundError as exc:
        if exc.name == "requests":
            print(
                "ERROR: Missing dependency 'requests'. Install it with: python3 -m pip install requests",
                file=sys.stderr,
            )
            return 2
        raise

    client = NSXClient(
        host=args.host,
        username=args.username,
        password=args.password,
        verify_ssl=args.verify_ssl,
        requests_per_second=args.requests_per_second,
        rate_limit_retries=args.rate_limit_retries,
    )

    try:
        results: List[Dict[str, Any]] = []
        source_report: Optional[Dict[str, Any]] = None
        report_groups: Optional[List[Dict[str, Any]]] = None
        if args.source_report:
            source_report = load_report(args.source_report)
            report_groups = [
                group for group in source_report.get("groups", []) if isinstance(group, dict)
            ]

        if args.remove_managed:
            if report_groups is not None:
                groups = report_groups
                mode = "remove-managed-from-report"
            else:
                groups = client.get_paginated(group_base_path(args.domain), page_size=args.page_size)
                mode = "remove-managed"

            for index, group in enumerate(groups, start=1):
                group_id = group.get("id", "<missing-id>")
                print(f"[{index}/{len(groups)}] Checking managed expressions on group {group_id}")
                try:
                    results.append(
                        remove_managed_from_group(
                            client,
                            group=group,
                            domain=args.domain,
                            expression_id_prefix=args.expression_id_prefix,
                            apply=args.apply,
                        )
                    )
                except NSXApiError as exc:
                    results.append({"id": group_id, "status": "error", "error": str(exc)})
        elif report_groups is not None:
            groups = report_groups
            mode = "replay-source-report"
            for index, group in enumerate(groups, start=1):
                group_id = group.get("id", "<missing-id>")
                print(f"[{index}/{len(groups)}] Replaying report group {group_id}")
                try:
                    results.append(
                        process_report_group(
                            client,
                            report_group=group,
                            domain=args.domain,
                            expression_id_prefix=args.expression_id_prefix,
                            apply=args.apply,
                            include_ipv6=args.include_ipv6,
                        )
                    )
                except NSXApiError as exc:
                    results.append({"id": group_id, "status": "error", "error": str(exc)})
        else:
            groups = client.get_paginated(group_base_path(args.domain), page_size=args.page_size)
            mode = "apply" if args.apply else "dry-run"
            for index, group in enumerate(groups, start=1):
                group_id = group.get("id", "<missing-id>")
                print(f"[{index}/{len(groups)}] Inspecting group {group_id}")
                try:
                    results.append(
                        process_group(
                            client,
                            group=group,
                            domain=args.domain,
                            expression_id_prefix=args.expression_id_prefix,
                            apply=args.apply,
                            include_ipv6=args.include_ipv6,
                            page_size=args.page_size,
                            enforcement_point_path=args.enforcement_point_path,
                        )
                    )
                except NSXApiError as exc:
                    results.append({"id": group_id, "status": "error", "error": str(exc)})

        summary = summarize_results(results)
        report = {
            "metadata": {
                "generated_at_utc": now_utc_iso(),
                "host": args.host,
                "domain": args.domain,
                "mode": mode,
                "apply": args.apply,
                "expression_id_prefix": args.expression_id_prefix,
                "include_ipv6": args.include_ipv6,
                "enforcement_point_path": args.enforcement_point_path,
                "source_report": args.source_report,
            },
            "source_report_metadata": source_report.get("metadata") if source_report else None,
            "summary": summary,
            "groups": results,
        }
        write_report(args.report, report)

        print(
            "Complete: "
            f"mode={report['metadata']['mode']}, total={summary['groups_total']}, "
            f"planned={summary['groups_planned']}, updated={summary['groups_updated']}, "
            f"errors={summary['groups_errors']}, report={args.report}"
        )
        return 1 if summary["groups_errors"] else 0

    except (NSXApiError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
