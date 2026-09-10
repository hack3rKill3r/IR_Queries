// IR-233 - Rubeus Dump / Triage / Klist-Like Activity
// Purpose: Identify Rubeus commands used to enumerate or dump Kerberos tickets.
// MITRE ATT&CK: T1558
#event_simpleName=ProcessRollup2
CommandLine=/Rubeus.*(dump|triage|klist|monitor)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)