// IR-520 - Process-Centric Network and DNS Timeline
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Show process start, DNS, listeners and IPv4 connections for exactly one endpoint/process.
// Requires: Replace REPLACE_AID and REPLACE_FALCON_PID. Use the Falcon Target/Context process ID, not the Windows PID.
// Analyst notes: Includes events missing usernames or context names. Sorts before table selection. Earliest 20,000 events only; split the search window at the cap. Does not infer DNS-answer-to-IP causality.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-sort.html
// Reference: https://library.humio.com/crowdstrike-query-language/functions-table.html

aid="REPLACE_AID"
(
    (#event_simpleName=ProcessRollup2 TargetProcessId="REPLACE_FALCON_PID")
    OR
    (
        #event_simpleName=/^(NetworkConnectIP4|NetworkListenIP4|DnsRequest)$/
        ContextProcessId="REPLACE_FALCON_PID"
    )
)
| sort(@timestamp, order=asc, limit=20000)
| table([
    @timestamp, #event_simpleName, aid, ComputerName, UserName,
    ImageFileName, CommandLine, ParentBaseFileName,
    TargetProcessId, ParentProcessId, ContextProcessId,
    DomainName, LocalAddressIP4, LocalPort, RemoteAddressIP4, RemotePort, Protocol,
    SHA256HashData
], limit=20000)
