// IR-119 - Executables Written to AppData
// Purpose: Identify executable payloads written into user AppData directories.
#event_simpleName=/FileWritten$/
TargetFileName=/\.exe$/i
FilePath=/\\AppData\\/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId], limit=20000)