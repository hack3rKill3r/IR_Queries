// IR-464 - TeamViewer Execution
// MITRE ATT&CK: T1219
#event_simpleName=ProcessRollup2
FileName=/TeamViewer.*\.exe$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)