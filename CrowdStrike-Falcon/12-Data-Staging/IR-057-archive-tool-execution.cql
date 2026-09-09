// IR-057 - Archive Tool Execution
// Purpose: Identify common archive utilities used for data staging.
// MITRE ATT&CK: T1560.001
#event_simpleName=ProcessRollup2
FileName=/^(7z|7za|7zz|rar|winrar|tar)\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,CommandLine,SHA256HashData], limit=20000)