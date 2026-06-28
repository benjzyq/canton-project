# Canton DevNet Low-Level Lab Report

Generated UTC: 2026-06-28T20:00:15.872443+00:00

No OAuth secret or private key material is included in this report.

## Parties

- External party: `benjbenj::122056a0cd87f23a7163a7b38e601644b72c579d7adec34ec0da9535054c3cd8d00b`
- Validator party: `cantor8-digik-1::12204e94c0e449c0efcd270dd1e68259c36471cebef132e5c7dfc2750fe8c9eed77f`
- DSO party: `DSO::1220be58c29e65de40bf273be1dc2b266d43a9a002ea5b18955aeef7aac881bb471a`
- Active synchronizer: `global-domain::1220be58c29e65de40bf273be1dc2b266d43a9a002ea5b18955aeef7aac881bb471a`

## Lab Steps

- External party topology submitted: `yes`
- Transfer preapproval visible: `yes`
- Transfer preapproval contracts visible via ACS: `1`
- Ledger ACS query offset: `2182949`
- Holding contracts visible for the external party: `0`
- Transfer preapproval contract id: `00c4b7fa983d8aac50121c6003d3250dd9f5e4fe5e0e6eb419f0c13c300712d881ca1212200be10098b9c6ac4be39fd7e7b985330c97b1fd3981386f39bc22e2539c83a702`

## Remaining External Action

Canton Coins are not minted by this script. Ask the DevNet team to send CC to the external party above, then rerun the script to refresh the Holding ACS query.

Optional Token Standard transfer was not executed because no funded balance and no recipient party were provided.

## Rerun

```powershell
$env:CANTON_CLIENT_ID='hackathon'
$env:CANTON_CLIENT_SECRET='<from the lab document>'
python outputs\canton_low_level_lab.py --report outputs\canton_lab_report.md
```

The default path uses external-party topology plus Ledger interactive submission. The validator setup-proposal helper is only used when rerun with `--allow-setup-proposal-fallback`.
