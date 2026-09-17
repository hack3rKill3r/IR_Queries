// IR-516 - Process with Listener and Outbound Connection
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Find process executions with both IPv4 listener and connection evidence.
// Requires: ProcessRollup2, NetworkListenIP4 and NetworkConnectIP4; aid and corresponding Falcon process IDs.
// Analyst notes: Replace REPLACE_AID; static search, short window. No order is imposed; all three events must be within one hour. This does not prove traffic was forwarded between the sockets.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-correlate.html

correlate(
    proc: {
        #event_simpleName=ProcessRollup2 aid="REPLACE_AID" TargetProcessId=*
        | EventTime := @timestamp
    } include:[EventTime, aid, ComputerName, UserName, ImageFileName, CommandLine, TargetProcessId],
    listener: {
        #event_simpleName=NetworkListenIP4 aid=* ContextProcessId=*
        | EventTime := @timestamp
        | aid <=> proc.aid
        | ContextProcessId <=> proc.TargetProcessId
    } include:[EventTime, LocalAddressIP4, LocalPort],
    net: {
        #event_simpleName=NetworkConnectIP4 aid=* ContextProcessId=*
        | EventTime := @timestamp
        | aid <=> proc.aid
        | ContextProcessId <=> proc.TargetProcessId
    } include:[EventTime, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort],
    sequence=false, within=1h
)
| sort(net.EventTime, order=asc, limit=20000)
