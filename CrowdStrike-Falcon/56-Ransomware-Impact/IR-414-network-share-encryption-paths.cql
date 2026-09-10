// IR-414 - UNC Path Encryption/Write Indicators
// Purpose: Identify command lines referencing administrative/network shares during suspected ransomware activity.
// MITRE ATT&CK: T1021.002 / T1486
#event_simpleName=ProcessRollup2
CommandLine=/\\\\[^\\\s]+\\[^\s]+/i
FileName=/^(cmd|powershell|pwsh|robocopy|xcopy|psexec|psexec64|wmic|sc|schtasks)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)