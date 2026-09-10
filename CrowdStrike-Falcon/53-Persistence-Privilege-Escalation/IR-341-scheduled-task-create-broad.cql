// IR-341 - Scheduled Task Creation Broad Hunt
// Purpose: Identify scheduled-task creation via schtasks.exe.
// MITRE ATT&CK: T1053.005
#event_simpleName=ProcessRollup2
FileName="schtasks.exe"
CommandLine=/\/create/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)