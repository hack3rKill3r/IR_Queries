// IR-185 - Browser -> Shell
// Purpose: Identify browsers directly spawning command shells or PowerShell.
// MITRE ATT&CK: T1204.002 / T1059
#event_simpleName=ProcessRollup2
ParentBaseFileName=/^(chrome|msedge|firefox|iexplore|brave)\.exe$/i
FileName=/^(cmd|powershell|pwsh)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)