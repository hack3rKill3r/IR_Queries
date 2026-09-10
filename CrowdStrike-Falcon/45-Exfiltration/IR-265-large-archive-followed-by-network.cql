// IR-265 - Large Archive Followed by Network Activity
// Purpose: Find large archive writes on hosts that also generate external connections.
// MITRE ATT&CK: T1560.001 / T1048
(
  #event_simpleName=/FileWritten$/
  TargetFileName=/\.(zip|7z|rar|tar|gz|tgz)$/i
  FileSize>104857600
)
OR
(
  #event_simpleName=NetworkConnectIP4
  !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"])
)
| groupBy([aid,ComputerName], function=[collect([@timestamp,#event_simpleName,TargetFileName,FileSize,ContextBaseFileName,RemoteAddressIP4,RemotePort])], limit=max)