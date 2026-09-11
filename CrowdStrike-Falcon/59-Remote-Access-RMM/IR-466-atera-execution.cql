// IR-466 - Atera Agent Execution
// MITRE ATT&CK: T1219
#event_simpleName=ProcessRollup2
(FileName=/(AteraAgent|AgentPackage)\.exe$/i OR CommandLine=/Atera/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)