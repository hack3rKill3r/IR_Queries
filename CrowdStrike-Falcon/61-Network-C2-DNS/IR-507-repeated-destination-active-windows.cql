// IR-507 - Repeated Destination Activity Across Time Windows
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Find process/destination tuples observed in at least twelve separate five-minute windows.
// Requires: NetworkConnectIP4: aid, ContextProcessId, RemoteAddressIP4, RemotePort, @timestamp.
// Analyst notes: Use a 2-24 hour search. Active windows need not be consecutive. This is a persistence-of-contact screen, not periodicity or C2 confirmation; use IR-508 next.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-math-floor.html
// Reference: https://library.humio.com/crowdstrike-query-language/functions-groupby.html

#event_simpleName=NetworkConnectIP4
aid=* ContextProcessId=* RemoteAddressIP4=* RemotePort=*
| WindowStart := @timestamp / 300000
| math:floor(WindowStart, as=WindowStart)
| WindowStart := WindowStart * 300000
| groupBy([aid, ContextProcessId, RemoteAddressIP4, RemotePort, WindowStart], function=[
    count(as=WindowEvents), min(@timestamp, as=WindowFirst), max(@timestamp, as=WindowLast),
    collect([ComputerName], limit=10)
], limit=max)
| groupBy([aid, ContextProcessId, RemoteAddressIP4, RemotePort], function=[
    count(as=ActiveFiveMinuteWindows), sum(WindowEvents, as=ObservedEvents),
    min(WindowFirst, as=FirstSeen), max(WindowLast, as=LastSeen), collect([ComputerName], limit=10)
], limit=max)
| ActiveFiveMinuteWindows>=12 ObservedEvents>=20
| sort(ActiveFiveMinuteWindows, order=desc, limit=20000)
