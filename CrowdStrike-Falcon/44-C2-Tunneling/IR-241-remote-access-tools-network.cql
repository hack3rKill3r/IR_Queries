// IR-241 - Remote Access Tool Network Activity
// Purpose: Identify network activity from commonly abused remote access software.
// MITRE ATT&CK: T1219
#event_simpleName=NetworkConnectIP4
ContextBaseFileName=/(anydesk|teamviewer|rustdesk|screenconnect|connectwisecontrol|atera|splashtop)/i
| table([@timestamp,ComputerName,ContextBaseFileName,LocalAddressIP4,RemoteAddressIP4,RemotePort,ContextProcessId], limit=20000)