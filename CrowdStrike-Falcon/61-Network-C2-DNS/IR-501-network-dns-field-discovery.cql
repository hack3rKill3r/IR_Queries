// IR-501 - Network and DNS Field Discovery
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: List the fields actually present before choosing a hunt.
// Requires: #event_simpleName; one or more listed event families.
// Analyst notes: Start with 15 minutes. Rerun for one event type to avoid assuming a field appears on every family. No rows can mean wrong view, time range, access, or absent telemetry.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-fieldstats.html

#event_simpleName=/^(ProcessRollup2|NetworkConnectIP4|NetworkListenIP4|DnsRequest)$/
| fieldstats(limit=1000)
| sort(field, type=string, order=asc, limit=1000)
