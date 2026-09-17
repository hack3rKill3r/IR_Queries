// IR-519 - Named Scanner Process to Observed Connection
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Correlate scanner-named process execution with native IPv4 connection telemetry.
// Requires: ProcessRollup2: aid, TargetProcessId, ImageFileName; NetworkConnectIP4: aid, ContextProcessId.
// Analyst notes: Static search; one-hour start-to-connection bound. Raw-packet scans may not appear as process connection events. Name matching misses renamed tools; check approved scanning.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-correlate.html

correlate(
    proc: {
        #event_simpleName=ProcessRollup2 aid=* TargetProcessId=*
        ImageFileName=/(^|[\\\/])(nmap|masscan|rustscan)(\.exe)?$/i
        | EventTime := @timestamp
    } include:[EventTime, aid, ComputerName, UserName, ImageFileName, CommandLine, TargetProcessId, SHA256HashData],
    net: {
        #event_simpleName=NetworkConnectIP4 aid=* ContextProcessId=*
        | aid <=> proc.aid
        | ContextProcessId <=> proc.TargetProcessId
        | EventTime := @timestamp
    } include:[EventTime, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort, Protocol],
    sequence=true, within=1h
)
| sort(net.EventTime, order=asc, limit=20000)
