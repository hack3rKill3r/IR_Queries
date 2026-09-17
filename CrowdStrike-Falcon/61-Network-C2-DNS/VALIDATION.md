# Validation record: IR-501–520

## Completed locally

Confirmed 20 unique query IDs and paths, matching IR-501 through IR-520. Compiled regex literals with Python after translating named capture syntax where needed. Exercised positive and negative examples for DNS suffix boundaries, SSH forwarding switch case and attached values, curl proxy/DoH options, netsh mutations versus read-only commands, and scanner executable boundaries. Checked fixed-window arithmetic and synthetic regular/jittered interval calculations.

These checks are **not Falcon CQL compilation or runtime tests**. Python regex behavior is not identical to every LogScale regex engine. The CQL functions and correlation structure were checked against the linked primary documentation, but parser acceptance, field availability, cardinality, telemetry completeness and false-positive rates still require tenant validation.

## Required before operational use

1. Run IR-501 and IR-502, inspect a raw record for each required event type, and record the view, sensor platform and relevant field names without publishing sensitive data.
2. Execute each query in a small static search. Record any syntax or resource errors. For interval and correlation queries, confirm the necessary functions are available in the tenant.
3. Use approved benign activity with known endpoint/process identifiers to verify expected matches and negative controls. Do not perform unauthorized scans or install remote-access tooling merely to test these hunts.
4. Compare results to original events. Confirm `aid`, Falcon process IDs, timestamps and address/port roles. Check for missing process starts, name enrichment, DNS evidence and listener evidence.
5. Review result caps and warnings, then tune thresholds and exceptions to the environment. Version-control sanitized query improvements and the validation outcome.

No endpoint commands, scans or Falcon searches were executed as part of publishing this batch.
