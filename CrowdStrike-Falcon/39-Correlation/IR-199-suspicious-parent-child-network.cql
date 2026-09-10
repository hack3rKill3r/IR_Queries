// IR-199 - Suspicious Child Process with Network Activity
// Purpose: Find high-interest child processes that also generated IPv4 connections.
(
  #event_simpleName=ProcessRollup2
  OR #event_simpleName=NetworkConnectIP4
)
| falconPID:=TargetProcessId
| falconPID:=ContextProcessId
| selfJoinFilter(
    field=[aid,falconPID],
    where=[
      {#event_simpleName=ProcessRollup2 FileName=/^(powershell|pwsh|cmd|mshta|rundll32|regsvr32|wscript|cscript)\.exe$/i},
      {#event_simpleName=NetworkConnectIP4}
    ]
)
| groupBy([aid,falconPID], function=[collect([ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,RemoteAddressIP4,RemotePort])], limit=max)