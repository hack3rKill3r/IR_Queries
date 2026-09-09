// IR-079 - Detailed IPv4 Network Connections
// Purpose: Detailed connection timeline suitable for host/process pivots.
#event_simpleName=NetworkConnectIP4
| table([@timestamp,aid,ComputerName,ContextBaseFileName,ContextProcessId,LocalAddressIP4,LocalPort,RemoteAddressIP4,RemotePort], limit=20000)