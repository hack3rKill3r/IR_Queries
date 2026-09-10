// IR-255 - Process + DNS + External Network Correlation
// Purpose: Correlate process execution, DNS, and public network connections.
(
  #event_simpleName=ProcessRollup2
  OR #event_simpleName=DnsRequest
  OR #event_simpleName=NetworkConnectIP4
)
| falconPID:=TargetProcessId
| falconPID:=ContextProcessId
| selfJoinFilter(field=[aid,falconPID],where=[
  {#event_simpleName=ProcessRollup2},
  {#event_simpleName=DnsRequest},
  {#event_simpleName=NetworkConnectIP4 !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"])}
])
| groupBy([aid,falconPID], function=[collect([ComputerName,UserName,FileName,CommandLine,DomainName,RemoteAddressIP4,RemotePort])], limit=max)