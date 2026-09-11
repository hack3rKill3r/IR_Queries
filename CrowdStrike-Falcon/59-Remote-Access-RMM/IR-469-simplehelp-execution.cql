// IR-469 - SimpleHelp Execution
// MITRE ATT&CK: T1219
#event_simpleName=ProcessRollup2
(CommandLine=/SimpleHelp/i OR FileName=/SimpleHelp.*\.exe$/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)