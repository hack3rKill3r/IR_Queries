// IR-344 - PowerShell New-Service
// Purpose: Identify service creation using PowerShell.
// MITRE ATT&CK: T1543.003
#event_simpleName=ProcessRollup2
CommandLine=/New-Service/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)