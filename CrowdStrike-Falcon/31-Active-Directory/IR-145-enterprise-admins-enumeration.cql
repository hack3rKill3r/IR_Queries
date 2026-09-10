// IR-145 - Enterprise Admins Enumeration
// Purpose: Identify commands querying Enterprise Admins membership.
// MITRE ATT&CK: T1069.002
#event_simpleName=ProcessRollup2
CommandLine=/enterprise\s+admins/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)