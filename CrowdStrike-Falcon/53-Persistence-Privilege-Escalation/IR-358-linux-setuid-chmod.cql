// IR-358 - Linux SUID/SGID Permission Changes
// Purpose: Identify chmod commands setting SUID/SGID bits.
// MITRE ATT&CK: T1548.001
event_platform=Lin
#event_simpleName=ProcessRollup2
FileName="chmod"
CommandLine=/(u\+s|g\+s|\b4[0-7]{3}\b|\b2[0-7]{3}\b)/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)