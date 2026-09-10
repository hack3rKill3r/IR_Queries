// IR-123 - Large Archive Files Written
// Purpose: Surface large archive writes that may indicate bulk data staging.
// Threshold: 100 MB. Adjust as needed for the environment.
#event_simpleName=/FileWritten$/
TargetFileName=/\.(zip|7z|rar|tar|gz|tgz)$/i
FileSize>104857600
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,FileSize,ContextProcessId], limit=20000)