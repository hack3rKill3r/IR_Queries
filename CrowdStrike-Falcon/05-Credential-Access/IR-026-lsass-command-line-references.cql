// IR-026 - LSASS Command-Line References
// Purpose: Find process executions explicitly referencing LSASS.
// MITRE ATT&CK: T1003.001
#event_simpleName=ProcessRollup2
CommandLine=/lsass/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)