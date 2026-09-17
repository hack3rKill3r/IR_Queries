// IR-504 - Vertical TCP Port Fan-Out in Five Minutes
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Find one process contacting many ports on a single IPv4 destination.
// Requires: NetworkConnectIP4: aid, ContextProcessId, RemoteAddressIP4, RemotePort, Protocol, @timestamp.
// Analyst notes: 15 ports is a starting threshold, not a maliciousness verdict. RPC, service discovery and authorized scans can match. Pivot to the Falcon process ID.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-math-floor.html
// Reference: https://library.humio.com/crowdstrike-query-language/functions-groupby.html

#event_simpleName=NetworkConnectIP4
Protocol=6 aid=* ContextProcessId=* RemoteAddressIP4=* RemotePort=*
| WindowStart := @timestamp / 300000
| math:floor(WindowStart, as=WindowStart)
| WindowStart := WindowStart * 300000
| groupBy([aid, ContextProcessId, RemoteAddressIP4, WindowStart], function=[
    count(as=ObservedEvents),
    count(RemotePort, distinct=true, as=UniquePorts),
    min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen),
    collect([ComputerName, RemotePort], limit=50)
], limit=max)
| UniquePorts>=15
| sort(UniquePorts, order=desc, limit=20000)
