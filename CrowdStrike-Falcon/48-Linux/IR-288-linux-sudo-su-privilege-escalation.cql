// IR-288 - Linux sudo/su Privilege Escalation
// Purpose: Identify privilege transition commands.
// MITRE ATT&CK: T1548.003
event_platform=Lin
#event_simpleName=ProcessRollup2
FileName=/^(sudo|su)$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)