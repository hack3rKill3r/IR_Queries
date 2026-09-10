// IR-327 - wevtutil Clear Logs
// MITRE ATT&CK: T1070.001
#event_simpleName=ProcessRollup2
FileName="wevtutil.exe"
CommandLine=/\b(cl|clear-log)\b/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)