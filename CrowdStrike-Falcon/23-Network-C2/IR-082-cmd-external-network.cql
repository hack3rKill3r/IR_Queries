// IR-082 - CMD External Network Connections
#event_simpleName=NetworkConnectIP4 ContextBaseFileName="cmd.exe"
!cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16"])
| table([@timestamp,ComputerName,ContextBaseFileName,ContextProcessId,RemoteAddressIP4,RemotePort], limit=20000)