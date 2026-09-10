// IR-112 - All File Write Events
// Purpose: Broad file-write timeline for payload, staging, and artifact investigations.
#event_simpleName=/FileWritten$/
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId], limit=20000)