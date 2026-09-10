// IR-116 - Batch and Command Files Written
// Purpose: Identify .bat and .cmd files written to disk.
#event_simpleName=/FileWritten$/
TargetFileName=/\.(bat|cmd)$/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId], limit=20000)