// IR-045 - Scheduled Task Utility Execution
// Purpose: Identify use of schtasks.exe for task discovery, creation, modification, or execution.
// MITRE ATT&CK: T1053.005
#event_simpleName=ProcessRollup2
FileName="schtasks.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)