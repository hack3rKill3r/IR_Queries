// IR-034 - ADFind Execution
// Purpose: Identify ADFind use for LDAP/AD reconnaissance.
// MITRE ATT&CK: T1087.002 / T1018
#event_simpleName=ProcessRollup2
(FileName=/adfind/i OR CommandLine=/adfind/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData], limit=20000)