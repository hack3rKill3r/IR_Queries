// IR-502 - Native Field Coverage by Event Type
// Status: Draft hunt; not executed against a Falcon tenant.
// Purpose: Measure which event families populate process IDs, ports, images and user fields.
// Requires: #event_simpleName; the other fields are tested, not required.
// Analyst notes: With* values count field presence, not nonempty/valid values. RPort/LPort are diagnostic alternatives only; do not substitute without inspecting raw events.
// Scope: Native Falcon sensor telemetry, not normalized third-party logs.
// Limits: Search warnings and result caps can make output incomplete; see README.md.
// Reference: https://library.humio.com/crowdstrike-query-language/functions-count.html

#event_simpleName=/^(ProcessRollup2|NetworkConnectIP4|NetworkListenIP4|DnsRequest)$/
| groupBy([#event_simpleName], function=[
    count(as=Events),
    count(aid, as=WithAid),
    count(TargetProcessId, as=WithTargetProcessId),
    count(ContextProcessId, as=WithContextProcessId),
    count(ImageFileName, as=WithImageFileName),
    count(ContextBaseFileName, as=WithContextBaseFileName),
    count(UserName, as=WithUserName),
    count(RemoteAddressIP4, as=WithRemoteAddressIP4),
    count(RemotePort, as=WithRemotePort),
    count(LocalPort, as=WithLocalPort),
    count(RPort, as=WithRPort),
    count(LPort, as=WithLPort),
    count(DomainName, as=WithDomainName)
], limit=max)
| sort(Events, order=desc, limit=100)
