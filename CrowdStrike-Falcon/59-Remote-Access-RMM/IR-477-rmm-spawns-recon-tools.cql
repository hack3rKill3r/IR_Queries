// IR-477 - RMM Tool Spawning Reconnaissance Utilities
// Purpose: Identify discovery activity initiated from RMM sessions.
#event_simpleName=ProcessRollup2
ParentBaseFileName=/(AnyDesk|TeamViewer|ScreenConnect|Splashtop|Atera|RustDesk|meshagent|SimpleHelp|rutserv|Supremo|DWAgent|Ninja|Kaseya|Syncro)/i
FileName=/^(whoami|ipconfig|systeminfo|nltest|net|net1|quser|qwinsta|tasklist|netstat)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)