// IR-236 - Kerberos Ticket Enumeration
// Purpose: Identify klist-based ticket enumeration.
// MITRE ATT&CK: T1558
#event_simpleName=ProcessRollup2
FileName="klist.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)