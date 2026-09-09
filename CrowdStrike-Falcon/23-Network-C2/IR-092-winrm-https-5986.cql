// IR-092 - WinRM HTTPS Connections
#event_simpleName=NetworkConnectIP4 RemotePort=5986
| table([@timestamp,ComputerName,ContextBaseFileName,ContextProcessId,RemoteAddressIP4,RemotePort], limit=20000)