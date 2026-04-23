#!/usr/bin/env python3
"""Shared helpers for exporting/importing NSX DFW Policy objects."""

from __future__ import annotations

import copy
import json
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import requests
import urllib3


READ_ONLY_FIELDS = {
    "_create_time",
    "_create_user",
    "_last_modified_time",
    "_last_modified_user",
    "_links",
    "_protection",
    "_revision",
    "marked_for_delete",
    "overridden",
    "owner_id",
    "origin_site_id",
    "realization_id",
    "remote_path",
    "relative_path",
    "unique_id",
}

ENVIRONMENT_FIELDS = {
    "path",
    "parent_path",
    "remote_path",
    "realization_id",
    "relative_path",
}


class NSXApiError(RuntimeError):
    """Raised on API errors talking to NSX Manager."""


@dataclass
class ImportCounters:
    created: int = 0
    updated: int = 0
    skipped_exists: int = 0
    skipped_system_owned: int = 0
    duplicate_matches: int = 0
    errors: int = 0


class NSXClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        verify_ssl: bool = False,
        timeout: int = 60,
    ) -> None:
        self.base_url = f"https://{host.strip().rstrip('/')}"
        self.timeout = timeout

        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.verify = verify_ssl
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            warnings.filterwarnings(
                "ignore",
                message="Unverified HTTPS request",
                category=urllib3.exceptions.InsecureRequestWarning,
            )
            try:
                requests.packages.urllib3.disable_warnings(  # type: ignore[attr-defined]
                    requests.packages.urllib3.exceptions.InsecureRequestWarning  # type: ignore[attr-defined]
                )
            except AttributeError:
                pass

    def request(
        self,
        method: str,
        path: str,
        *,
        expected_statuses: Iterable[int] = (200,),
        params: Optional[Dict[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = self._to_url(path)
        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                params=params,
                json=payload,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise NSXApiError(f"Request failed: {method} {url} :: {exc}") from exc

        if response.status_code not in set(expected_statuses):
            body = response.text.strip()
            if len(body) > 1000:
                body = f"{body[:1000]}..."
            raise NSXApiError(
                f"Unexpected status {response.status_code} for {method} {url}. "
                f"Response: {body or '<empty>'}"
            )

        if not response.content:
            return None

        ctype = response.headers.get("Content-Type", "")
        if "application/json" in ctype:
            return response.json()

        return response.text

    def object_exists(self, path: str) -> bool:
        try:
            data = self._get_with_404(path)
            return data is not None
        except NSXApiError:
            raise
        except Exception as exc:
            raise NSXApiError(f"Failed existence check for {path}: {exc}") from exc

    def get_object(self, path: str) -> Optional[Dict[str, Any]]:
        return self._get_with_404(path)

    def patch_object(self, path: str, payload: Dict[str, Any]) -> None:
        self.request("PATCH", path, expected_statuses=(200, 201), payload=payload)

    def get_paginated(
        self,
        path: str,
        *,
        page_size: int = 1000,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        query = dict(params or {})
        query.setdefault("page_size", page_size)

        while True:
            data = self.request("GET", path, params=query)
            if not isinstance(data, dict):
                raise NSXApiError(f"Expected paginated JSON object for {path}, got {type(data)}")

            page_results = data.get("results", [])
            if not isinstance(page_results, list):
                raise NSXApiError(f"Expected list in 'results' for {path}")
            results.extend(page_results)

            cursor = data.get("cursor")
            if not cursor:
                break
            query = {"cursor": cursor, "page_size": page_size}

        return results

    def _to_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self.base_url}{path if path.startswith('/') else '/' + path}"

    def _get_with_404(self, path: str) -> Optional[Dict[str, Any]]:
        url = self._to_url(path)
        try:
            response = self.session.request(
                method="GET",
                url=url,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise NSXApiError(f"Request failed: GET {url} :: {exc}") from exc

        if response.status_code == 404:
            return None
        if response.status_code != 200:
            body = response.text.strip()
            if len(body) > 1000:
                body = f"{body[:1000]}..."
            raise NSXApiError(
                f"Unexpected status {response.status_code} for GET {url}. "
                f"Response: {body or '<empty>'}"
            )

        if not response.content:
            return None

        ctype = response.headers.get("Content-Type", "")
        if "application/json" not in ctype:
            raise NSXApiError(f"Expected JSON response for GET {url}, got {ctype or 'unknown'}")

        data = response.json()
        if isinstance(data, dict):
            return data
        raise NSXApiError(f"Expected JSON object for GET {url}, got {type(data)}")


def sanitize_for_import(obj: Any) -> Any:
    """Remove read-only and environment-specific fields before import."""
    if isinstance(obj, list):
        return [sanitize_for_import(item) for item in obj]

    if isinstance(obj, dict):
        cleaned: Dict[str, Any] = {}
        for key, value in obj.items():
            if key in READ_ONLY_FIELDS or key in ENVIRONMENT_FIELDS:
                continue
            if key.startswith("_"):
                continue
            cleaned[key] = sanitize_for_import(value)
        return cleaned

    return obj


def strip_rules(policy: Dict[str, Any]) -> Dict[str, Any]:
    copy_policy = copy.deepcopy(policy)
    copy_policy.pop("rules", None)
    return copy_policy


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_rule_for_compare(rule: Dict[str, Any]) -> str:
    """Normalize a rule for duplicate checks across environments."""
    candidate = sanitize_for_import(copy.deepcopy(rule))
    candidate.pop("id", None)
    candidate.pop("display_name", None)
    return json.dumps(candidate, sort_keys=True, separators=(",", ":"))


def is_system_owned(obj: Dict[str, Any]) -> bool:
    return bool(obj.get("_system_owned") or obj.get("system_owned"))
