// IR-485 - NTDS.dit Copy/Reference
// MITRE ATT&CK: T1003.003
#event_simpleName=ProcessRollup2
CommandLine=/(ntds\.dit|\\Windows\\NTDS\\ntds\.dit)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)