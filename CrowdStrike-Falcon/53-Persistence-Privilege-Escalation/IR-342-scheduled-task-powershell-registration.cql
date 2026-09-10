// IR-342 - PowerShell Scheduled Task Registration
// Purpose: Identify Register-ScheduledTask and New-ScheduledTask usage.
// MITRE ATT&CK: T1053.005
#event_simpleName=ProcessRollup2
CommandLine=/(Register-ScheduledTask|New-ScheduledTask|New-ScheduledTaskAction|New-ScheduledTaskTrigger)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine],limit=20000)