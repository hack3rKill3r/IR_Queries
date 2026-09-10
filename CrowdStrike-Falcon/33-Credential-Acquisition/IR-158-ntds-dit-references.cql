// IR-158 - NTDS.dit References
// Purpose: Identify process command lines referencing the Active Directory database.
// MITRE ATT&CK: T1003.003
#event_simpleName=ProcessRollup2
CommandLine=/ntds\.dit/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)