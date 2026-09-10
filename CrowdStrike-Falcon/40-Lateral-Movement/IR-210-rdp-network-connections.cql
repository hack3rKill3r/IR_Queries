// IR-210 - RDP Network Connections
// Purpose: Identify outbound RDP connections.
// MITRE ATT&CK: T1021.001
#event_simpleName=NetworkConnectIP4
RemotePort=3389
| table([@timestamp,ComputerName,ContextBaseFileName,LocalAddressIP4,RemoteAddressIP4,RemotePort,ContextProcessId], limit=20000)