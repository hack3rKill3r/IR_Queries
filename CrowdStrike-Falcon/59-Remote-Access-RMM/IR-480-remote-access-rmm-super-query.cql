// IR-480 - Remote Access / RMM Super Query
// Purpose: Broad first-pass hunt for common RMM tools and suspicious child activity.
// MITRE ATT&CK: T1219
(
 #event_simpleName=ProcessRollup2
 (
  FileName=/(AnyDesk|TeamViewer|ScreenConnect|ConnectWise|Splashtop|Atera|RustDesk|meshagent|SimpleHelp|RemoteUtilities|rutserv|DWAgent|Supremo|LogMeIn|GoToAssist|Ninja|Kaseya|Syncro)/i
  OR
  ParentBaseFileName=/(AnyDesk|TeamViewer|ScreenConnect|Splashtop|Atera|RustDesk|meshagent|SimpleHelp|rutserv|Supremo|DWAgent|Ninja|Kaseya|Syncro)/i
 )
)
OR
(
 #event_simpleName=NetworkConnectIP4
 ContextBaseFileName=/(AnyDesk|TeamViewer|ScreenConnect|Splashtop|Atera|RustDesk|meshagent|SimpleHelp|rutserv|Supremo|DWAgent|Ninja|Kaseya|Syncro)/i
)
| table([@timestamp,#event_simpleName,ComputerName,UserName,ParentBaseFileName,ContextBaseFileName,FileName,FilePath,CommandLine,RemoteAddressIP4,RemotePort,SHA256HashData],limit=20000)