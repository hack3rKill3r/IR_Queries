// IR-286 - Linux SSH Lateral Movement
// Purpose: Identify outbound ssh/scp/sftp activity.
// MITRE ATT&CK: T1021.004
event_platform=Lin
#event_simpleName=ProcessRollup2
FileName=/^(ssh|scp|sftp)$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)