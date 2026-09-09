// IR-051 - Netsh Firewall Changes
// Purpose: Identify Windows Firewall manipulation via netsh.
// MITRE ATT&CK: T1562.004
#event_simpleName=ProcessRollup2
FileName="netsh.exe"
CommandLine=/firewall|advfirewall/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)