// IR-239 - Golden / Silver Ticket Tool Strings
// Purpose: Identify common command-line indicators for forged Kerberos tickets.
// MITRE ATT&CK: T1558.001 / T1558.002
#event_simpleName=ProcessRollup2
CommandLine=/(golden|silver|kerberos::golden|Rubeus.*(golden|silver))/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)