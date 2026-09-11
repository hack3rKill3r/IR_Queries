// IR-461 - RMM / Remote Access Process Discovery
// Purpose: Identify common legitimate remote access tools that may be abused by threat actors.
// MITRE ATT&CK: T1219
#event_simpleName=ProcessRollup2
FileName=/(AnyDesk|TeamViewer|ScreenConnect|ConnectWiseControl|Splashtop|AteraAgent|AgentPackage|RustDesk|SimpleHelp|MeshAgent|TacticalRMM|RemoteUtilities|rutserv|DWAgent|Supremo|LogMeIn|GoToAssist|GoToResolve|NinjaRMMAgent|Kaseya|VSAService|Syncro|Level|Action1|ZohoAssist|BeyondTrust|bomgar|TakeControl|N-able)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)