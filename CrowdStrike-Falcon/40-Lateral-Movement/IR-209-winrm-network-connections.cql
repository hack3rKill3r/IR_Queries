// IR-209 - WinRM Network Connections
// Purpose: Identify outbound WinRM connections to TCP/5985 and 5986.
// MITRE ATT&CK: T1021.006
#event_simpleName=NetworkConnectIP4
(RemotePort=5985 OR RemotePort=5986)
| table([@timestamp,ComputerName,ContextBaseFileName,LocalAddressIP4,RemoteAddressIP4,RemotePort,ContextProcessId], limit=20000)