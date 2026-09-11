// IR-476 - RMM Tool Spawning Shell/Interpreter
// Purpose: High-value pivot for interactive post-exploitation through RMM.
// MITRE ATT&CK: T1219 / T1059
#event_simpleName=ProcessRollup2
ParentBaseFileName=/(AnyDesk|TeamViewer|ScreenConnect|Splashtop|Atera|RustDesk|meshagent|SimpleHelp|rutserv|Supremo|DWAgent|Ninja|Kaseya|Syncro)/i
FileName=/^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)