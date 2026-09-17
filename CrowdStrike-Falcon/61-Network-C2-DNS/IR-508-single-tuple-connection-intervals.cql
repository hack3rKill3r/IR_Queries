// IR-508 - Connection Interval Analysis for One Process and Destination
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Calculate observed inter-event timing and coefficient of variation for a candidate beacon.
// Requires: Replace REPLACE_AID, REPLACE_FALCON_PID, REPLACE_IPV4 and REPLACE_PORT from a network event.
// Analyst notes: Requires at least 11 events. Sorting retains the earliest 20,000 rows; reduce the search window at the cap. Low CV is not proof of malware. Duplicate or missing telemetry can distort timing.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-neighbor.html
// Reference: https://library.humio.com/crowdstrike-query-language/functions-stddev.html
// Reference: https://library.humio.com/crowdstrike-query-language/functions-sort.html

#event_simpleName=NetworkConnectIP4
aid="REPLACE_AID" ContextProcessId="REPLACE_FALCON_PID"
RemoteAddressIP4="REPLACE_IPV4" RemotePort="REPLACE_PORT"
| EventTime := @timestamp
| sort(EventTime, order=asc, limit=20000)
| neighbor(include=[EventTime], prefix=previous)
| previous.EventTime=*
| GapMs := EventTime - previous.EventTime
| stats([
    count(as=IntervalCount), avg(GapMs, as=MeanGapMs), stdDev(GapMs, as=StdDevGapMs),
    min(GapMs, as=MinGapMs), max(GapMs, as=MaxGapMs),
    min(previous.EventTime, as=FirstSeen), max(EventTime, as=LastSeen),
    collect([aid, ComputerName, ContextProcessId, RemoteAddressIP4, RemotePort], limit=10)
])
| IntervalCount>=10 MeanGapMs>0
| IntervalCV := StdDevGapMs / MeanGapMs
