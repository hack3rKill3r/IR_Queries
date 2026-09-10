// IR-125 - Ransom Note-Like Files
// Purpose: Identify filenames commonly associated with ransomware instructions.
#event_simpleName=/FileWritten$/
TargetFileName=/(README|RECOVER|RESTORE|DECRYPT|HOW_TO|RANSOM)/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId], limit=20000)