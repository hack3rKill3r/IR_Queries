// IR-162 - SAM Hive References
// Purpose: Hunt for command lines referencing the SAM hive.
// MITRE ATT&CK: T1003.002
#event_simpleName=ProcessRollup2
CommandLine=/\\SAM\b/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)