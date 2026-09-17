// IR-505 - Internal Management-Port Fan-Out
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Scope a process contacting multiple RFC1918 hosts on management-associated TCP ports.
// Requires: NetworkConnectIP4: aid, ContextProcessId, RemoteAddressIP4, RemotePort, Protocol, @timestamp.
// Analyst notes: 10-minute bins; five destinations triggers review. Port numbers alone do not prove the application protocol or lateral movement. Includes only the three RFC1918 ranges.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-cidr.html
// Reference: https://library.humio.com/crowdstrike-query-language/functions-math-floor.html

#event_simpleName=NetworkConnectIP4
Protocol=6 aid=* ContextProcessId=* RemoteAddressIP4=*
| in(field=RemotePort, values=["22", "135", "445", "3389", "5985", "5986"])
| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| WindowStart := @timestamp / 600000
| math:floor(WindowStart, as=WindowStart)
| WindowStart := WindowStart * 600000
| groupBy([aid, ContextProcessId, WindowStart], function=[
    count(as=ObservedEvents),
    count(RemoteAddressIP4, distinct=true, as=UniqueDestinations),
    min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen),
    collect([ComputerName, RemoteAddressIP4, RemotePort], limit=100)
], limit=max)
| UniqueDestinations>=5
| sort(UniqueDestinations, order=desc, limit=20000)
