// IR-175 - Delete Windows Backup Catalog
// Purpose: Identify wbadmin catalog deletion.
// MITRE ATT&CK: T1490
#event_simpleName=ProcessRollup2
FileName="wbadmin.exe"
CommandLine=/delete.*catalog/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)