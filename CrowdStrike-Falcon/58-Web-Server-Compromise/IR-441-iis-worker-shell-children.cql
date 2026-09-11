// IR-441 - IIS Worker Spawning Shells
// Purpose: Identify w3wp.exe launching command shells/interpreters.
// MITRE ATT&CK: T1505.003 / T1059
#event_simpleName=ProcessRollup2
ParentBaseFileName="w3wp.exe"
FileName=/^(cmd|powershell|pwsh|wscript|cscript|mshta)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)