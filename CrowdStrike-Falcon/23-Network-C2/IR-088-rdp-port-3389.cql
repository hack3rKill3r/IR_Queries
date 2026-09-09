// IR-088 - RDP Network Connections
#event_simpleName=NetworkConnectIP4 RemotePort=3389
| table([@timestamp,ComputerName,ContextBaseFileName,ContextProcessId,LocalAddressIP4,RemoteAddressIP4,RemotePort], limit=20000)