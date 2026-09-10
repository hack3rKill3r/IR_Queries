// IR-113 - Executable Files Written
// Purpose: Identify .exe files written to disk.
#event_simpleName=/FileWritten$/
TargetFileName=/\.exe$/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId], limit=20000)