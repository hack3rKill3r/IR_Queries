// IR-473 - PowerShell Download/Install of RMM
// Purpose: Identify scripted retrieval or installation of remote-access tools.
// MITRE ATT&CK: T1105 / T1219
#event_simpleName=ProcessRollup2
FileName=/^(powershell|pwsh)\.exe$/i
CommandLine=/(AnyDesk|TeamViewer|ScreenConnect|ConnectWise|Splashtop|Atera|RustDesk|MeshCentral|SimpleHelp|Supremo|DWAgent|NinjaRMM|Kaseya|Syncro)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)