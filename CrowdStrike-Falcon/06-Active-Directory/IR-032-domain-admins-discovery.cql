// IR-032 - Domain Admins Discovery
// Purpose: Find commands querying Domain Admins membership.
// MITRE ATT&CK: T1069.002
#event_simpleName=ProcessRollup2
CommandLine=/domain admins/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)