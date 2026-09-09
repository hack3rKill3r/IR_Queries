// IR-070 - Office Spawning Suspicious Child Process
// Purpose: Identify Office applications launching shells, script hosts, or proxy-execution binaries.
// MITRE ATT&CK: T1204 / T1059
#event_simpleName=ProcessRollup2
ParentBaseFileName=/^(winword|excel|powerpnt|outlook)\.exe$/i
FileName=/^(cmd|powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)