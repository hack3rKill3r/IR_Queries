// IR-474 - RMM Network Activity
// Purpose: Identify outbound connections from common RMM processes.
// MITRE ATT&CK: T1219
#event_simpleName=NetworkConnectIP4
ContextBaseFileName=/(AnyDesk|TeamViewer|ScreenConnect|Splashtop|Atera|RustDesk|meshagent|SimpleHelp|rutserv|Supremo|DWAgent|Ninja|Kaseya|Syncro)/i
| table([@timestamp,ComputerName,ContextBaseFileName,LocalAddressIP4,RemoteAddressIP4,RemotePort,ContextProcessId],limit=20000)