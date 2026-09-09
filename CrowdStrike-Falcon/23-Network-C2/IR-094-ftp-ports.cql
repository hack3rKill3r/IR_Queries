// IR-094 - FTP Network Connections
#event_simpleName=NetworkConnectIP4 RemotePort=/^(20|21)$/
| table([@timestamp,ComputerName,ContextBaseFileName,ContextProcessId,RemoteAddressIP4,RemotePort], limit=20000)