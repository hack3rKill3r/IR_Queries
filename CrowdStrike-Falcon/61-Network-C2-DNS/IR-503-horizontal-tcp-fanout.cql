// IR-503 - Horizontal TCP Fan-Out in Five Minutes
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Find one process contacting many IPv4 addresses on the same TCP port.
// Requires: NetworkConnectIP4: aid, ContextProcessId, RemoteAddressIP4, RemotePort, Protocol, @timestamp.
// Analyst notes: 20 destinations is a starting threshold. Approved scanners and management software match. This counts observed events, not every scan attempt or successful authentication.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-math-floor.html
// Reference: https://library.humio.com/crowdstrike-query-language/functions-groupby.html

#event_simpleName=NetworkConnectIP4
Protocol=6 aid=* ContextProcessId=* RemoteAddressIP4=* RemotePort=*
| WindowStart := @timestamp / 300000
| math:floor(WindowStart, as=WindowStart)
| WindowStart := WindowStart * 300000
| groupBy([aid, ContextProcessId, RemotePort, WindowStart], function=[
    count(as=ObservedEvents),
    count(RemoteAddressIP4, distinct=true, as=UniqueDestinations),
    min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen),
    collect([ComputerName, RemoteAddressIP4], limit=50)
], limit=max)
| UniqueDestinations>=20
| sort(UniqueDestinations, order=desc, limit=20000)
