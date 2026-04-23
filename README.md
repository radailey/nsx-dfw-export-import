# NSX DFW Export/Import Scripts

These scripts are designed for one-time (or repeatable) migration of NSX DFW policy objects between NSX Manager clusters.

## Files
- `nsx_dfw_export.py`: exports services, groups, context profiles, security policies, and rules.
- `nsx_dfw_import.py`: imports exported objects into destination NSX, skipping existing objects by default.
- `nsx_dfw_common.py`: shared NSX API client and object-sanitization logic.

## Requirements
- Python 3.8+
- `requests`

Install dependency:
```bash
python3 -m pip install requests
```

## Export
```bash
python3 nsx_dfw_export.py \
  --source-host nsx-source.example.local \
  --username admin \
  --password 'YOUR_PASSWORD' \
  --domain default \
  --output nsx_dfw_export.json
```

## Import (idempotent, no duplicates)
Default mode skips existing IDs:
```bash
python3 nsx_dfw_import.py \
  --dest-host nsx-dest.example.local \
  --username admin \
  --password 'YOUR_PASSWORD' \
  --input nsx_dfw_export.json
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

Dry-run preview:
```bash
python3 nsx_dfw_import.py \
  --dest-host nsx-dest.example.local \
  --username admin \
  --password 'YOUR_PASSWORD' \
  --input nsx_dfw_export.json \
  --dry-run
```

## Notes
- By default, TLS certificate verification is off. Add `--verify-ssl` if your certificates are trusted.
- System-owned NSX objects are skipped.
- Rules are duplicate-checked by ID and also by normalized rule content to avoid re-importing equivalent rules.
