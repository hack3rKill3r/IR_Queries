// IR-046 - Scheduled Task Creation
// Purpose: Focus on schtasks.exe task creation activity.
// MITRE ATT&CK: T1053.005
#event_simpleName=ProcessRollup2
FileName="schtasks.exe"
CommandLine=/\/create/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)