// IR-075 - All IPv4 Network Connections
// Purpose: Baseline or timeline IPv4 connection telemetry.
#event_simpleName=NetworkConnectIP4
| table([@timestamp,ComputerName,ContextBaseFileName,LocalAddressIP4,LocalPort,RemoteAddressIP4,RemotePort,ContextProcessId], limit=20000)