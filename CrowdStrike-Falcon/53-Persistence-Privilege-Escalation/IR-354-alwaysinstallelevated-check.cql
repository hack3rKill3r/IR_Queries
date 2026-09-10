// IR-354 - AlwaysInstallElevated Registry Check
// Purpose: Identify commands querying or setting AlwaysInstallElevated.
// MITRE ATT&CK: T1548.002
#event_simpleName=ProcessRollup2
CommandLine=/AlwaysInstallElevated/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)