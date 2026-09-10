// IR-172 - Startup Folder References
// Purpose: Identify process command lines referencing Windows Startup folders.
// MITRE ATT&CK: T1547.001
#event_simpleName=ProcessRollup2
CommandLine=/\\Start Menu\\Programs\\Startup\\/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)