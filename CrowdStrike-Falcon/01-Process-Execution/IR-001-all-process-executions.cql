# IR-001 - All Process Executions
# Category: Process Execution
# Purpose: Broad process execution timeline.
#event_simpleName=ProcessRollup2
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData,TargetProcessId,ParentProcessId],limit=20000)