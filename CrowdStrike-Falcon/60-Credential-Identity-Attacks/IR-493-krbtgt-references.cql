// IR-493 - KRBTGT References
// MITRE ATT&CK: T1558.001
#event_simpleName=ProcessRollup2
CommandLine=/krbtgt/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)