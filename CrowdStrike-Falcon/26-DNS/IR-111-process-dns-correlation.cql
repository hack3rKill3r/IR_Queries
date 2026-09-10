// IR-111 - Process + DNS Correlation
// Purpose: Tie ProcessRollup2 and DnsRequest events together using Falcon process IDs.
(
  #event_simpleName=ProcessRollup2
  OR #event_simpleName=DnsRequest
)
| falconPID:=TargetProcessId
| falconPID:=ContextProcessId
| selfJoinFilter(field=[aid,falconPID], where=[{#event_simpleName=ProcessRollup2},{#event_simpleName=DnsRequest}])
| groupBy([aid,falconPID], function=[collect([@timestamp,ComputerName,UserName,FileName,CommandLine,DomainName,IP4Records])], limit=max)