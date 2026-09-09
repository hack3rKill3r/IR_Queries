// IR-090 - SMB Network Connections
#event_simpleName=NetworkConnectIP4 RemotePort=445
| table([@timestamp,ComputerName,ContextBaseFileName,ContextProcessId,LocalAddressIP4,RemoteAddressIP4,RemotePort], limit=20000)