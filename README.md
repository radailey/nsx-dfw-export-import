# NSX DFW Export/Import Scripts

These scripts support one-time or repeatable migration of NSX-T DFW policy objects between NSX Manager clusters.

## Files
- `nsx_dfw_export.py`: exports services, groups, context profiles, security policies, and policy rules.
- `nsx_dfw_import.py`: imports exported objects into the destination NSX Manager with idempotent behavior.
- `nsx_dfw_common.py`: shared NSX API client, retry logic, throttling, and object sanitization.

## Requirements
- Python 3.8+
- `requests`

Install dependency:

```bash
python3 -m pip install requests
```

## What Gets Exported
- Services from `/infra/services`
- Groups from `/infra/domains/<domain>/groups`
- Context profiles from `/infra/context-profiles`
- Security policies and their rules from `/infra/domains/<domain>/security-policies`

## Export
Basic example:

```bash
python3 nsx_dfw_export.py \
  --source-host nsx-source.example.local \
  --username admin \
  --password 'YOUR_PASSWORD' \
  --domain default \
  --output nsx_dfw_export.json
```

Export with conservative rate limiting:

```bash
python3 nsx_dfw_export.py \
  --source-host nsx-source.example.local \
  --username admin \
  --password 'YOUR_PASSWORD' \
  --domain default \
  --output nsx_dfw_export.json \
  --requests-per-second 10 \
  --rate-limit-retries 12
```

## Import
Default import behavior is idempotent:
- Existing objects with the same destination path and ID are skipped.
- Existing policies are skipped as full subtrees unless `--update-existing` is used.
- Rules are duplicate-checked by ID and also by normalized rule content.
- Groups are retried across multiple passes to handle group-to-group dependencies.

Basic import:

```bash
python3 nsx_dfw_import.py \
  --dest-host nsx-dest.example.local \
  --username admin \
  --password 'YOUR_PASSWORD' \
  --input nsx_dfw_export.json
```

Dry-run:

```bash
python3 nsx_dfw_import.py \
  --dest-host nsx-dest.example.local \
  --username admin \
  --password 'YOUR_PASSWORD' \
  --input nsx_dfw_export.json \
  --dry-run
```

Update existing objects in place:

```bash
python3 nsx_dfw_import.py \
  --dest-host nsx-dest.example.local \
  --username admin \
  --password 'YOUR_PASSWORD' \
  --input nsx_dfw_export.json \
  --update-existing
```

Import with conservative rate limiting:

```bash
python3 nsx_dfw_import.py \
  --dest-host nsx-dest.example.local \
  --username admin \
  --password 'YOUR_PASSWORD' \
  --input nsx_dfw_export.json \
  --requests-per-second 10 \
  --rate-limit-retries 12
```

## Command Options
Both scripts support:
- `--verify-ssl`
- `--page-size`
- `--requests-per-second`
- `--rate-limit-retries`

Import also supports:
- `--dry-run`
- `--update-existing`
- `--domain`

## Rate Limiting
Some NSX Manager environments enforce API rate limits such as `100 requests per second`. The shared client now:
- throttles requests client-side
- retries HTTP `429` responses with backoff

If you still see rate-limit errors in a busy environment, rerun with a lower request rate such as:

```bash
--requests-per-second 10 --rate-limit-retries 12
```

## Dependency Behavior
The importer creates objects in this order:
1. Services
2. Context Profiles
3. Groups
4. Policies and Rules

That ordering handles most dependencies, but some imports can still fail if the exported objects reference items that do not exist in the destination, for example:
- a group that references another group not present in the export
- a group that references a segment path that is not valid in the destination
- a rule that references a missing service or group

Typical examples from real runs:
- missing referenced groups such as `RAMCO-Preprod-Web`
- missing services such as `SNMP-Recieve`
- invalid destination-specific paths such as `/infra/segments/vlan51`

When that happens, the importer will continue and report the remaining failures at the end.

## Notes and Caveats
- TLS certificate verification is disabled by default. Use `--verify-ssl` if the NSX certificate chain is trusted.
- When SSL verification is disabled, the client suppresses the noisy `InsecureRequestWarning` output.
- System-owned NSX objects are skipped.
- A rerun after a partial import is expected to show many `skipped_exists` counts. That usually means the earlier run already created those objects successfully.
- A dry-run only predicts actions. It does not create parent objects, so it is mainly useful for confirming counts and catching obvious path or dependency issues.

## Shell Note
In `zsh`, passwords containing `!!` must be quoted or the shell may expand them through history substitution.

Example:

```bash
--password 'VMwar3!!VMwar3!!'
```
