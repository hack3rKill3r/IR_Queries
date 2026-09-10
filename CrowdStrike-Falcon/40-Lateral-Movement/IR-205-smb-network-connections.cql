// IR-205 - SMB Network Connections
// Purpose: Identify outbound SMB connections that may support lateral movement.
// MITRE ATT&CK: T1021.002
#event_simpleName=NetworkConnectIP4
RemotePort=445
| table([@timestamp,ComputerName,ContextBaseFileName,LocalAddressIP4,RemoteAddressIP4,RemotePort,ContextProcessId], limit=20000)