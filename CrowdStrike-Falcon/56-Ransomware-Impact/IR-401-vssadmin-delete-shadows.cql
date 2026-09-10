// IR-401 - VSSAdmin Delete Shadows
// MITRE ATT&CK: T1490
#event_simpleName=ProcessRollup2
FileName="vssadmin.exe"
CommandLine=/delete.*shadows/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)