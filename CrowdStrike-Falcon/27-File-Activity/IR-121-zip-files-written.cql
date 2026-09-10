// IR-121 - ZIP Files Written
// Purpose: Identify ZIP archive creation/writes for staging investigations.
#event_simpleName=ZipFileWritten
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId], limit=20000)