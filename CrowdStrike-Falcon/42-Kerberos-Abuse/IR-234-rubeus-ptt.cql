// IR-234 - Rubeus Pass-the-Ticket
// Purpose: Identify Rubeus ptt usage.
// MITRE ATT&CK: T1550.003
#event_simpleName=ProcessRollup2
CommandLine=/Rubeus.*\bptt\b/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)