// IR-465 - Splashtop Execution
// MITRE ATT&CK: T1219
#event_simpleName=ProcessRollup2
(FileName=/(SRManager|SRService|Splashtop.*)\.exe$/i OR CommandLine=/Splashtop/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)