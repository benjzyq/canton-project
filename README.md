# Canton Workshop 1 - Low-Level Ledger Lab

This repository contains the public verification artifacts for Workshop 1:
"Touching the Ledger: A Canton Low-Level Lab".

## Completion Evidence

- External party hint: `benjbenj`
- External party id: `benjbenj::122056a0cd87f23a7163a7b38e601644b72c579d7adec34ec0da9535054c3cd8d00b`
- Topology submitted: `yes`
- Transfer preapproval visible: `yes`
- Transfer preapproval contracts visible through ACS: `1`
- Holding contracts visible through ACS: `0`

The full sanitized run report is in [WORKSHOP_REPORT.md](WORKSHOP_REPORT.md).

## Files

- `canton_low_level_lab.py` - reusable low-level script for OAuth, external-party topology, Ledger interactive submission, TransferPreapproval lookup, and ACS checks.
- `WORKSHOP_REPORT.md` - sanitized completion report generated from the DevNet run.
- `requirements.txt` - Python dependency list.

## Security

This repository intentionally excludes:

- OAuth client secrets
- private keys
- local state files such as `work/canton_lab_state_*.json`
- downloaded workshop prompt text
- raw logs containing credentials

To rerun locally, provide credentials through environment variables:

```powershell
$env:CANTON_CLIENT_ID='hackathon'
$env:CANTON_CLIENT_SECRET='<from workshop instructions>'
python canton_low_level_lab.py --party-hint benjbenj --state work\canton_lab_state_benjbenj.json --report WORKSHOP_REPORT.md
```

Do not commit the generated `work\canton_lab_state_benjbenj.json` file.
