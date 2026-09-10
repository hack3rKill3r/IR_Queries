// IR-144 - Domain Admins Enumeration
// Purpose: Identify commands querying Domain Admins membership.
// MITRE ATT&CK: T1069.002
#event_simpleName=ProcessRollup2
CommandLine=/domain\s+admins/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)