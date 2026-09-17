// IR-506 - Interpreter or LOLBin to IPv4 Connection
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Attach actual process execution context to a later connection from that Falcon process.
// Requires: ProcessRollup2: aid, TargetProcessId, ImageFileName; NetworkConnectIP4: aid, ContextProcessId.
// Analyst notes: Static search. One-hour process-start-to-connection bound; older processes are intentionally missed. Network events do not need UserName or ContextBaseFileName.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-correlate.html

correlate(
    proc: {
        #event_simpleName=ProcessRollup2 event_platform=Win
        aid=* TargetProcessId=*
        ImageFileName=/\\(powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin)\.exe$/i
        | EventTime := @timestamp
    } include:[EventTime, aid, ComputerName, UserName, ImageFileName, CommandLine, TargetProcessId, ParentProcessId, SHA256HashData],
    net: {
        #event_simpleName=NetworkConnectIP4 aid=* ContextProcessId=*
        | EventTime := @timestamp
        | aid <=> proc.aid
        | ContextProcessId <=> proc.TargetProcessId
    } include:[EventTime, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort, Protocol, ContextProcessId],
    sequence=true, within=1h
)
| sort(net.EventTime, order=asc, limit=20000)
