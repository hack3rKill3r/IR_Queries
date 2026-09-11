// IR-467 - RustDesk Execution
// MITRE ATT&CK: T1219
#event_simpleName=ProcessRollup2
FileName=/rustdesk(\.exe)?$/i
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)