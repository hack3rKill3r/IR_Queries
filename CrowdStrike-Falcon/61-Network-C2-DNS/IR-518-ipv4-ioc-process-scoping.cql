// IR-518 - IPv4 IOC Scoping by Endpoint and Process
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Scope a known destination across endpoints and Falcon process IDs with first/last observations.
// Requires: NetworkConnectIP4: aid, ContextProcessId, RemoteAddressIP4. Replace REPLACE_IPV4.
// Analyst notes: FirstSeen and LastSeen apply only to the selected retained time window. Process names/users require a process pivot; connection events alone do not prove compromise or exfiltration.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-groupby.html

#event_simpleName=NetworkConnectIP4
RemoteAddressIP4="REPLACE_IPV4" aid=* ContextProcessId=*
| groupBy([aid, ContextProcessId, RemoteAddressIP4], function=[
    count(as=ObservedEvents), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen),
    collect([ComputerName, LocalAddressIP4, RemotePort, Protocol], limit=100)
], limit=max)
| sort(FirstSeen, order=asc, limit=20000)
