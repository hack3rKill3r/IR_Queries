// IR-468 - MeshCentral Agent Execution
// MITRE ATT&CK: T1219
#event_simpleName=ProcessRollup2
(FileName=/meshagent(\.exe)?$/i OR CommandLine=/MeshCentral/i)
| table([@timestamp,ComputerName,UserName,ParentBaseFileName,FileName,FilePath,CommandLine,SHA256HashData],limit=20000)