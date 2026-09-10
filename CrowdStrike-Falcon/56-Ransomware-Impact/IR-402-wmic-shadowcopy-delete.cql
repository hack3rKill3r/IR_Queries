// IR-402 - WMIC ShadowCopy Delete
// MITRE ATT&CK: T1490
#event_simpleName=ProcessRollup2
FileName="wmic.exe"
CommandLine=/shadowcopy.*delete/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)