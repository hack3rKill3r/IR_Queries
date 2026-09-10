// IR-198 - Process + DNS + Network Correlation
// Purpose: Tie process execution, DNS resolution, and network connection telemetry to the same endpoint/process.
(
  #event_simpleName=ProcessRollup2
  OR #event_simpleName=DnsRequest
  OR #event_simpleName=NetworkConnectIP4
)
| falconPID:=TargetProcessId
| falconPID:=ContextProcessId
| selfJoinFilter(
    field=[aid,falconPID],
    where=[
      {#event_simpleName=ProcessRollup2},
      {#event_simpleName=DnsRequest},
      {#event_simpleName=NetworkConnectIP4}
    ]
)
| groupBy([aid,falconPID], function=[collect([ComputerName,UserName,FileName,CommandLine,DomainName,RemoteAddressIP4,RemotePort])], limit=max)