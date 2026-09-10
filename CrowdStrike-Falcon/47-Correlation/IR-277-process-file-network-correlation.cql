// IR-277 - Process + File Write + Network Correlation
// Purpose: Correlate execution, file creation, and network activity to the same process where telemetry permits.
(
  #event_simpleName=ProcessRollup2
  OR #event_simpleName=/FileWritten$/
  OR #event_simpleName=NetworkConnectIP4
)
| falconPID:=TargetProcessId
| falconPID:=ContextProcessId
| selfJoinFilter(field=[aid,falconPID],where=[
  {#event_simpleName=ProcessRollup2},
  {#event_simpleName=/FileWritten$/},
  {#event_simpleName=NetworkConnectIP4}
])
| groupBy([aid,falconPID], function=[collect([@timestamp,ComputerName,UserName,FileName,CommandLine,TargetFileName,RemoteAddressIP4,RemotePort])], limit=max)