// IR-122 - Archive Files Written
// Purpose: Identify common archive formats written to disk.
#event_simpleName=/FileWritten$/
TargetFileName=/\.(zip|7z|rar|tar|gz|tgz)$/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId], limit=20000)