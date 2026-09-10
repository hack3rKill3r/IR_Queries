// IR-118 - Executables Written to Temp
// Purpose: Identify executable payloads written into temporary directories.
#event_simpleName=/FileWritten$/
TargetFileName=/\.exe$/i
FilePath=/\\Temp\\/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId], limit=20000)