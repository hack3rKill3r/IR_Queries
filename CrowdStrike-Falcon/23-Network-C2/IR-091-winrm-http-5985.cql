// IR-091 - WinRM HTTP Connections
#event_simpleName=NetworkConnectIP4 RemotePort=5985
| table([@timestamp,ComputerName,ContextBaseFileName,ContextProcessId,RemoteAddressIP4,RemotePort], limit=20000)