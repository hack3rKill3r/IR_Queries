// IR-054 - WBAdmin Execution
// Purpose: Identify Windows Backup command-line activity for ransomware preparation or legitimate administration.
// MITRE ATT&CK: T1490
#event_simpleName=ProcessRollup2
FileName="wbadmin.exe"
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,CommandLine], limit=20000)