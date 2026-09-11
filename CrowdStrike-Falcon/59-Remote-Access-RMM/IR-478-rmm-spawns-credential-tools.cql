// IR-478 - RMM Tool Spawning Credential-Access Indicators
// Purpose: Identify suspicious credential-access commands launched from remote management contexts.
// MITRE ATT&CK: T1219 / T1003
#event_simpleName=ProcessRollup2
ParentBaseFileName=/(AnyDesk|TeamViewer|ScreenConnect|Splashtop|Atera|RustDesk|meshagent|SimpleHelp|rutserv|Supremo|DWAgent|Ninja|Kaseya|Syncro)/i
CommandLine=/(lsass|mimikatz|secretsdump|procdump|comsvcs|sam.*save|security.*save|ntds\.dit)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)