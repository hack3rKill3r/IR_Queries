// IR-215 - Remote Scheduled Task
// Purpose: Identify schtasks.exe targeting remote systems with /S.
// MITRE ATT&CK: T1053.005
#event_simpleName=ProcessRollup2
FileName="schtasks.exe"
CommandLine=/\/S\s+[^\s]+/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)