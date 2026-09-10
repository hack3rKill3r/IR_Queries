// IR-120 - Executables Written to ProgramData
// Purpose: Identify executable payloads written into ProgramData.
#event_simpleName=/FileWritten$/
TargetFileName=/\.exe$/i
FilePath=/\\ProgramData\\/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId], limit=20000)