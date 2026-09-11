// IR-471 - RMM Tool from User-Writable Path
// Purpose: Highlight portable or freshly staged remote-access tools.
// MITRE ATT&CK: T1219
#event_simpleName=ProcessRollup2
FileName=/(AnyDesk|TeamViewer|ScreenConnect|Splashtop|Atera|RustDesk|meshagent|SimpleHelp|rutserv|Supremo|DWAgent)/i
FilePath=/(\\Users\\|\\Downloads\\|\\AppData\\|\\Temp\\|\\ProgramData\\)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)