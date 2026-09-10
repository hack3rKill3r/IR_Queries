// IR-348 - Winlogon Registry Persistence
// Purpose: Hunt for modifications to Winlogon Shell/Userinit values.
// MITRE ATT&CK: T1547.004
#event_simpleName=ProcessRollup2
FileName="reg.exe"
CommandLine=/Winlogon.*(Shell|Userinit)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)