// IR-114 - DLL Files Written
// Purpose: Identify .dll files written to disk.
#event_simpleName=/FileWritten$/
TargetFileName=/\.dll$/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId], limit=20000)