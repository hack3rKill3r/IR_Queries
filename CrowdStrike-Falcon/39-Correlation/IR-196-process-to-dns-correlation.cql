// IR-196 - Process + DNS Correlation
// Purpose: Correlate process execution with DNS activity using a normalized Falcon process ID.
(
  #event_simpleName=ProcessRollup2
  OR #event_simpleName=DnsRequest
)
| falconPID:=TargetProcessId
| falconPID:=ContextProcessId
| selfJoinFilter(
    field=[aid,falconPID],
    where=[{#event_simpleName=ProcessRollup2},{#event_simpleName=DnsRequest}]
)
| groupBy([aid,falconPID], function=[collect([ComputerName,UserName,FileName,CommandLine,DomainName])], limit=max)