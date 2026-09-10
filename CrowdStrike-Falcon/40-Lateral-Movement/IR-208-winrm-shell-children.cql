// IR-208 - WinRM Spawning Shells
// Purpose: Identify commands executed through wsmprovhost.exe.
// MITRE ATT&CK: T1021.006
#event_simpleName=ProcessRollup2
ParentBaseFileName="wsmprovhost.exe"
FileName=/^(cmd|powershell|pwsh)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)