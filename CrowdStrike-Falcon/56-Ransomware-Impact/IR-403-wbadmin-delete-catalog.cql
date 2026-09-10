// IR-403 - WBAdmin Delete Catalog
// MITRE ATT&CK: T1490
#event_simpleName=ProcessRollup2
FileName="wbadmin.exe"
CommandLine=/delete.*catalog/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine],limit=20000)