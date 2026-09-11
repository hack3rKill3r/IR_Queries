// IR-472 - RMM Service Installation
// Purpose: Identify service creation/configuration referencing remote-access tooling.
// MITRE ATT&CK: T1219 / T1543.003
#event_simpleName=ProcessRollup2
FileName="sc.exe"
CommandLine=/(create|config).*(AnyDesk|TeamViewer|ScreenConnect|ConnectWise|Splashtop|Atera|RustDesk|MeshAgent|SimpleHelp|RemoteUtilities|DWAgent|Supremo|Ninja|Kaseya|Syncro)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)