// IR-328 - PowerShell Clear-EventLog
// MITRE ATT&CK: T1070.001
#event_simpleName=ProcessRollup2
FileName=/^(powershell|pwsh)\.exe$/i
CommandLine=/Clear-EventLog/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)