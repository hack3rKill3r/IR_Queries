// IR-222 - LSASS Dump File Creation
// Purpose: Identify dump-like files written to disk that may contain LSASS memory.
// MITRE ATT&CK: T1003.001
#event_simpleName=/FileWritten$/
TargetFileName=/(lsass.*\.(dmp|dump)|\.dmp$)/i
| table([@timestamp,ComputerName,UserName,ContextBaseFileName,TargetFileName,FilePath,ContextProcessId], limit=20000)