// IR-492 - Rubeus Ticket Abuse
// Purpose: Identify Rubeus ticket dump, pass-the-ticket, golden/silver, and triage operations.
// MITRE ATT&CK: T1550.003 / T1558
#event_simpleName=ProcessRollup2
CommandLine=/Rubeus.*(dump|triage|ptt|golden|silver|kerberoast|asreproast)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData],limit=20000)