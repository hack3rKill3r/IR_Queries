// IR-058 - Password-Protected Archive Creation
// Purpose: Find archive-tool command lines using password switches, often seen during staging.
// MITRE ATT&CK: T1560.001
#event_simpleName=ProcessRollup2
FileName=/^(7z|7za|7zz|rar|winrar)\.exe$/i
CommandLine=/\s-p\S*/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine], limit=20000)