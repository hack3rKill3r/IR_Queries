// IR-475 - RMM DNS Activity
// Purpose: Review domains resolved by remote-access software.
// MITRE ATT&CK: T1219
#event_simpleName=DnsRequest
ContextBaseFileName=/(AnyDesk|TeamViewer|ScreenConnect|Splashtop|Atera|RustDesk|meshagent|SimpleHelp|rutserv|Supremo|DWAgent|Ninja|Kaseya|Syncro)/i
| table([@timestamp,ComputerName,ContextBaseFileName,DomainName,IP4Records,ContextProcessId],limit=20000)