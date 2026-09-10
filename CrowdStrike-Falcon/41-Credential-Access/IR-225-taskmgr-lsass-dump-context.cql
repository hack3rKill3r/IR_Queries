// IR-225 - Task Manager LSASS Dump Context
// Purpose: Review Task Manager execution around suspected credential dumping windows.
// MITRE ATT&CK: T1003.001
#event_simpleName=ProcessRollup2
FileName="taskmgr.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FilePath,CommandLine,TargetProcessId], limit=20000)