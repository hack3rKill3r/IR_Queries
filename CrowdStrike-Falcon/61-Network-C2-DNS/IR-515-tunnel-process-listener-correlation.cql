// IR-515 - Named Tunneling Tool to IPv4 Listener
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Correlate a named tunneling-capable process with its local listener event.
// Requires: ProcessRollup2: aid, TargetProcessId, ImageFileName; NetworkListenIP4: aid, ContextProcessId.
// Analyst notes: Static search; one-hour start-to-listener bound. Filename matching misses renamed tools. Listening does not establish Internet exposure, an inbound session, or malicious use.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-correlate.html

correlate(
    proc: {
        #event_simpleName=ProcessRollup2 aid=* TargetProcessId=*
        ImageFileName=/(^|[\\\/])(ssh|plink|chisel|gost|cloudflared|ngrok)(\.exe)?$/i
        | EventTime := @timestamp
    } include:[EventTime, aid, ComputerName, UserName, ImageFileName, CommandLine, TargetProcessId, SHA256HashData],
    listener: {
        #event_simpleName=NetworkListenIP4 aid=* ContextProcessId=*
        | aid <=> proc.aid
        | ContextProcessId <=> proc.TargetProcessId
        | EventTime := @timestamp
    } include:[EventTime, LocalAddressIP4, LocalPort, ContextProcessId],
    sequence=true, within=1h
)
| sort(listener.EventTime, order=asc, limit=20000)
