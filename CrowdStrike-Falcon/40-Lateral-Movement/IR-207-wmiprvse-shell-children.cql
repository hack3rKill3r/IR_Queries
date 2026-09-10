// IR-207 - WMI Provider Spawning Shells
// Purpose: Identify WMI-triggered cmd.exe or PowerShell execution.
// MITRE ATT&CK: T1047 / T1059
#event_simpleName=ProcessRollup2
ParentBaseFileName="wmiprvse.exe"
FileName=/^(cmd|powershell|pwsh)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)