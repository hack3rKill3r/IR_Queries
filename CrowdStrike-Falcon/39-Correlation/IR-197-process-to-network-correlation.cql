// IR-197 - Process + Network Correlation
// Purpose: Correlate process execution with IPv4 network connections.
(
  #event_simpleName=ProcessRollup2
  OR #event_simpleName=NetworkConnectIP4
)
| falconPID:=TargetProcessId
| falconPID:=ContextProcessId
| selfJoinFilter(
    field=[aid,falconPID],
    where=[{#event_simpleName=ProcessRollup2},{#event_simpleName=NetworkConnectIP4}]
)
| groupBy([aid,falconPID], function=[collect([ComputerName,UserName,FileName,CommandLine,RemoteAddressIP4,RemotePort])], limit=max)