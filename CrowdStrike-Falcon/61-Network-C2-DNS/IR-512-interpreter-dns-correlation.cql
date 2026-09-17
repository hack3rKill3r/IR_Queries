// IR-512 - Interpreter or LOLBin to DNS Request
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Associate DNS requests with matching process execution records.
// Requires: ProcessRollup2: aid, TargetProcessId, ImageFileName; DnsRequest: aid, ContextProcessId, DomainName.
// Analyst notes: Static search; one-hour start-to-DNS bound. Does not establish which later IP connection used a DNS answer. Cached DNS and delegated resolver processes can prevent matches.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-correlate.html

correlate(
    proc: {
        #event_simpleName=ProcessRollup2 event_platform=Win aid=* TargetProcessId=*
        ImageFileName=/\\(powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin)\.exe$/i
        | EventTime := @timestamp
    } include:[EventTime, aid, ComputerName, UserName, ImageFileName, CommandLine, TargetProcessId, SHA256HashData],
    dns: {
        #event_simpleName=DnsRequest aid=* ContextProcessId=* DomainName=*
        | EventTime := @timestamp
        | aid <=> proc.aid
        | ContextProcessId <=> proc.TargetProcessId
    } include:[EventTime, DomainName, ContextProcessId],
    sequence=true, within=1h
)
| sort(dns.EventTime, order=asc, limit=20000)
