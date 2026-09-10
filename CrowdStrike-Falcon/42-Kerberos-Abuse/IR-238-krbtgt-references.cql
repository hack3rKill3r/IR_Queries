// IR-238 - KRBTGT References
// Purpose: Surface commands referencing the KRBTGT account during suspected Golden Ticket/domain compromise activity.
// MITRE ATT&CK: T1558.001
#event_simpleName=ProcessRollup2
CommandLine=/krbtgt/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)