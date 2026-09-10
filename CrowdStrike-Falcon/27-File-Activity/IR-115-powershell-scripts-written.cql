// IR-115 - PowerShell Scripts Written
// Purpose: Identify PowerShell script files written to disk.
#event_simpleName=/FileWritten$/
TargetFileName=/\.ps1$/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId], limit=20000)