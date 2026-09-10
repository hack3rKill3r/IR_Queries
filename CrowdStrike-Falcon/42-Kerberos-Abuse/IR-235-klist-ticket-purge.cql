// IR-235 - Kerberos Ticket Purge
// Purpose: Identify klist purge operations that may accompany ticket abuse or cleanup.
// MITRE ATT&CK: T1070 / T1550.003
#event_simpleName=ProcessRollup2
FileName="klist.exe"
CommandLine=/\bpurge\b/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)