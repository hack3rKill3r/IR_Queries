# IR-002 - Process Execution on One Host
# Replace HOSTNAME.
#event_simpleName=ProcessRollup2
ComputerName="HOSTNAME"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData,TargetProcessId,ParentProcessId],limit=20000)