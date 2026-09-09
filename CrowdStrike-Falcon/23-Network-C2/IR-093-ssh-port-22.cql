// IR-093 - SSH Network Connections
#event_simpleName=NetworkConnectIP4 RemotePort=22
| table([@timestamp,ComputerName,ContextBaseFileName,ContextProcessId,RemoteAddressIP4,RemotePort], limit=20000)